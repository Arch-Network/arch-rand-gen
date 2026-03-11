use std::str::FromStr;
use std::sync::mpsc;

use arch_sdk::{
    arch_program::{
        account::AccountMeta, compute_budget::ComputeBudgetInstruction, hash::Hash,
        instruction::Instruction, pubkey::Pubkey, sanitized::ArchMessage,
    },
    blocking::ArchRpcClient as BlockingRpcClient,
    build_and_sign_transaction, with_secret_key_file, ArchRpcClient, Config, Event, EventTopic,
    Status, WebSocketClient,
};
use bitcoin::key::UntweakedKeypair;
use oracle_program::instruction::OracleInstruction;
use tracing::{error, info, warn};
use vrf_core::ecvrf_prove;

// ── Constants ─────────────────────────────────────────────────────────────

/// WebSocket endpoint of the Arch leader node.
const WS_URL: &str = "ws://127.0.0.1:10080";

/// Delay between WebSocket connection retries.
const WS_RETRY_BACKOFF_SECS: u64 = 5;

/// Key filenames under `~/.arch/`.
const ORACLE_KEY_FILE: &str = "oracle.key";
const ORACLE_PROGRAM_KEY_FILE: &str = "oracle_program.key";
const ORACLE_ED_KEY_FILE: &str = ".oracle_ed.key";
const TREASURY_KEY_FILE: &str = "treasury.key";

// ── Event type flowing through the pipe ───────────────────────────────────

/// A single RequestRandomness instruction, fully decoded and ready to prove.
struct PendingRequest {
    request_pda: [u8; 32],
    seed: [u8; 32],
    callback_pid: [u8; 32],
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Creates a new 32-byte Ed25519 secret key (for VRF), writes it to `path`, and returns the bytes.
pub fn create_ed_secret_key_and_save(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).unwrap();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, &bytes)?;
    Ok(bytes)
}

// ── Threads ───────────────────────────────────────────────────────────────

/// Listener: subscribes to the Arch WebSocket, fetches each matching
/// transaction, and extracts one PendingRequest per RequestRandomness
/// instruction into the channel.
async fn run_listener(outer_tx: mpsc::Sender<PendingRequest>, oracle_program: Pubkey) {
    let rpc = ArchRpcClient::new(&Config::localnet());
    let mut ws = WebSocketClient::new(WS_URL);

    loop {
        match ws.connect().await {
            Ok(()) => break,
            Err(e) => {
                warn!("🔌 WebSocket connection failed: {e} — retrying in {WS_RETRY_BACKOFF_SECS}s");
                tokio::time::sleep(tokio::time::Duration::from_secs(WS_RETRY_BACKOFF_SECS)).await;
            }
        }
    }

    info!("🟢 Connected to Arch WebSocket at {WS_URL}");
    let (hash_tx, mut hash_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    // Subscribe to all processed transactions and filter in the loop below.
    ws.on_event(EventTopic::Transaction, None, move |event| {
        if let Event::Transaction(tx_event) = event {
            if tx_event.status == Status::Processed {
                let _ = hash_tx.send(tx_event.hash);
            }
        }
    })
    .await
    .expect("failed to register transaction event callback");

    while let Some(tx_hash) = hash_rx.recv().await {
        info!("📡 Transaction event: {tx_hash}");

        let hash = match Hash::from_str(&tx_hash) {
            Ok(h) => h,
            Err(e) => {
                warn!("⚠️  Malformed tx hash {tx_hash}: {e}");
                continue;
            }
        };

        let processed_tx = match rpc.get_processed_transaction(&hash).await {
            Ok(Some(tx)) => tx,
            Ok(None) => {
                warn!("⚠️  Tx {tx_hash} not found on RPC");
                continue;
            }
            Err(e) => {
                error!("❌ RPC error fetching {tx_hash}: {e}");
                continue;
            }
        };

        let message = &processed_tx.runtime_transaction.message;
        let account_keys = &message.account_keys;

        // Scan both top-level and inner instructions so that RequestRandomness
        // fired via CPI is also picked up.
        let top_level = message.instructions.iter();
        let inner = processed_tx
            .inner_instructions_list
            .iter()
            .flat_map(|ixs| ixs.iter().map(|i| &i.instruction));

        for ix in top_level.chain(inner) {
            let program_pk = match account_keys.get(ix.program_id_index as usize) {
                Some(pk) => pk,
                None => continue,
            };
            if program_pk.serialize() != oracle_program.serialize() {
                continue;
            }

            let oracle_ix: OracleInstruction = match borsh::from_slice(&ix.data) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let (seed, callback_pid) = match oracle_ix {
                OracleInstruction::RequestRandomness {
                    seed,
                    callback_pid,
                    ..
                } => (seed, callback_pid),
                OracleInstruction::FulfillRequest { .. } => continue,
            };

            // accounts[1] is request_pda.
            let pda_key_idx = match ix.accounts.get(1) {
                Some(&i) => i as usize,
                None => continue,
            };
            let request_pda = match account_keys.get(pda_key_idx) {
                Some(pk) => pk.serialize(),
                None => continue,
            };

            let pda_hex = hex_encode(&request_pda);
            let _ = outer_tx.send(PendingRequest { request_pda, seed, callback_pid });
            info!("🎲 Queued randomness request — pda={pda_hex}");
        }
    }
}

/// Processor: proves VRF, builds a FulfillRequest tx signed by the oracle
/// (treasury pays), submits it, and waits for confirmation.
fn run_processor(
    rx: mpsc::Receiver<PendingRequest>,
    oracle_keypair: UntweakedKeypair,
    oracle_vrf_sk: [u8; 32],
    oracle_pubkey: Pubkey,
    oracle_program: Pubkey,
    treasury_keypair: UntweakedKeypair,
    treasury_pubkey: Pubkey,
) {
    let rpc = BlockingRpcClient::new(&Config::localnet());

    for req in rx {
        let pda_hex = hex_encode(&req.request_pda);

        // ── 1. Generate VRF proof ─────────────────────────────────────────
        let pi = match ecvrf_prove(&oracle_vrf_sk, &req.seed) {
            Ok(p) => p,
            Err(e) => {
                error!("❌ VRF prove failed — pda={pda_hex}: {e:?}");
                continue;
            }
        };
        info!(
            "🔐 VRF proof generated — pda={pda_hex} pi={}",
            hex_encode(&pi)
        );

        // ── 2. Build and send FulfillRequest ─────────────────────────────
        let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);

        let mut fulfill_accounts = vec![
            AccountMeta::new_readonly(oracle_pubkey, true),
            AccountMeta::new(Pubkey::from(req.request_pda), false),
            AccountMeta::new_readonly(Pubkey::from(req.callback_pid), false),
        ];
        // If a callback program is set, ensure the system program is available
        // for any downstream account creation the callback might need.
        if req.callback_pid != [0u8; 32] {
            fulfill_accounts.push(AccountMeta::new_readonly(
                arch_sdk::arch_program::system_program::SYSTEM_PROGRAM_ID,
                false,
            ));
        }

        let fulfill_ix = Instruction {
            program_id: oracle_program,
            accounts: fulfill_accounts,
            data: borsh::to_vec(&OracleInstruction::FulfillRequest { pi })
                .expect("failed to serialize FulfillRequest"),
        };

        let blockhash = match rpc.get_best_finalized_block_hash() {
            Ok(h) => h,
            Err(e) => {
                error!("❌ Failed to fetch blockhash — pda={pda_hex}: {e}");
                continue;
            }
        };

        let tx = match build_and_sign_transaction(
            ArchMessage::new(&[cu_ix, fulfill_ix], Some(treasury_pubkey), blockhash),
            vec![treasury_keypair.clone(), oracle_keypair.clone()],
            Config::localnet().network,
        ) {
            Ok(t) => t,
            Err(e) => {
                error!("❌ Failed to sign transaction — pda={pda_hex}: {e}");
                continue;
            }
        };

        let txid = match rpc.send_transaction(tx) {
            Ok(id) => id,
            Err(e) => {
                error!("❌ Failed to send FulfillRequest — pda={pda_hex}: {e}");
                continue;
            }
        };
        info!("📤 FulfillRequest submitted — pda={pda_hex} txid={txid}");

        match rpc.wait_for_processed_transaction(&txid) {
            Ok(processed) => info!(
                "✅ Fulfilled — pda={pda_hex} txid={txid} status={:?}",
                processed.status
            ),
            Err(e) => error!("❌ Wait failed — txid={txid}: {e}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let arch_dir = format!("{}/.arch", std::env::var("HOME").expect("HOME not set"));
    std::fs::create_dir_all(&arch_dir).expect("failed to create ~/.arch");

    let key = |name: &str| format!("{}/{}", arch_dir, name);

    let (oracle_keypair, oracle_pubkey) =
        with_secret_key_file(&key(ORACLE_KEY_FILE)).expect("failed to load oracle.key");
    let (_, oracle_program_pubkey) = with_secret_key_file(&key(ORACLE_PROGRAM_KEY_FILE))
        .expect("failed to load oracle_program.key");
    let (treasury_keypair, treasury_pubkey) =
        with_secret_key_file(&key(TREASURY_KEY_FILE)).expect("failed to load treasury.key");

    let oracle_vrf_sk: [u8; 32] = std::fs::read(key(ORACLE_ED_KEY_FILE))
        .expect("failed to read .oracle_ed.key — run the generate_oracle_ed_key test first")
        .try_into()
        .expect(".oracle_ed.key must be exactly 32 bytes");

    info!("🏛️  Oracle server starting");
    info!("🔑 Oracle pubkey:         {oracle_pubkey}");
    info!("📜 Oracle program pubkey: {oracle_program_pubkey}");
    info!("🏦 Treasury pubkey:       {treasury_pubkey}");

    let (tx, rx) = mpsc::channel::<PendingRequest>();

    let processor = tokio::task::spawn_blocking(move || {
        run_processor(
            rx,
            oracle_keypair,
            oracle_vrf_sk,
            oracle_pubkey,
            oracle_program_pubkey,
            treasury_keypair,
            treasury_pubkey,
        )
    });

    run_listener(tx, oracle_program_pubkey).await;

    processor.await.expect("processor thread panicked");
}

// Run with: cargo test -p server -- generate_oracle_ed_key --ignored --nocapture
// Creates $HOME/.arch/.oracle_ed.key and prints the Ed pubkey to hardcode in shared/src/keys.rs.

#[test]
#[ignore = "run manually to (re)generate ~/.arch/.oracle_ed.key and print Ed pubkey"]
fn generate_oracle_ed_key() {
    use std::path::Path;
    use vrf_core::ecvrf_public_key;
    let home = std::env::var("HOME").expect("HOME not set");
    let path = Path::new(&home).join(".arch").join(".oracle_ed.key");
    let sk = create_ed_secret_key_and_save(&path).expect("create and save Ed secret key");
    let pk = ecvrf_public_key(&sk);
    println!("Saved Ed secret key to: {}", path.display());
    println!("ORACLE_ED_PUBKEY (paste into shared/src/keys.rs):");
    println!("pub const ORACLE_ED_PUBKEY: [u8; 32] = {:?};", pk);
}
