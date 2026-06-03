/// End-to-end test for the arch-rand-gen oracle program.
///
/// Prerequisites:
///   1. A running Arch localnet (`arch-node` + Bitcoin regtest)
///   2. The oracle program compiled to SBF:
///        cd oracle-program && cargo build-sbf
///      Output lands at:
///        ../target/sbpf-solana-solana/release/oracle_program.so
///   3. The oracle server running:
///        cargo run -p server
///
/// Run with:
///   cargo test -p e2e-tests -- --include-ignored --nocapture
#[cfg(test)]
pub mod tests {
    use arch_sdk::arch_program::{
        account::AccountMeta, compute_budget::ComputeBudgetInstruction, instruction::Instruction,
        pubkey::Pubkey, sanitized::ArchMessage, system_program::SYSTEM_PROGRAM_ID,
    };
    use arch_sdk::{
        build_and_sign_transaction, generate_new_keypair, with_secret_key_file, ArchRpcClient,
        Config, ProgramDeployer, Status,
    };
    use oracle_program::{
        instruction::OracleInstruction,
        state::{RequestStatus, VrfRequest, REQUEST_DISCRIMINATOR},
    };
    use shared::keys::{ORACLE_FEE, ORACLE_TREASURY_PUBKEY};
    use shared::seeds::VRF_REQ_SEED;

    /// Path to the compiled oracle program SBF binary.
    /// Build with: `cd oracle-program && cargo build-sbf`
    const ELF_PATH: &str = "../target/sbpf-solana-solana/release/oracle_program.so";

    /// How long to sleep between polls when waiting for FulfillRequest.
    const POLL_INTERVAL_MS: u64 = 1_000;
    /// Maximum time to wait for the oracle server to fulfill the request.
    const POLL_TIMEOUT_SECS: u64 = 60;

    // ── helpers ───────────────────────────────────────────────────────────

    fn assert_processed(status: &Status) {
        if let Status::Failed(msg) = status {
            panic!("transaction failed: {}", msg);
        }
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn print_logs(label: &str, logs: &[String]) {
        println!("──── logs: {} ────", label);
        for log in logs {
            println!("  {}", log);
        }
    }

    // ── tests ─────────────────────────────────────────────────────────────

    /// Deploys the oracle program, submits one `RequestRandomness`, then
    /// waits for the oracle server to fulfill the request and verifies the
    /// resulting `VrfRequest` account reaches `Finalized`.
    #[tokio::test]
    #[ignore = "requires running Arch localnet + oracle server"]
    async fn test_deploy_and_request_randomness() {
        let config = Config::localnet();
        let client = ArchRpcClient::new(&config);

        // Keys under ~/.arch/ (same as server): oracle_program.key, treasury.key;
        // server also uses oracle.key and .oracle_ed.key.
        let arch_dir = format!("{}/.arch", std::env::var("HOME").expect("HOME not set"));
        std::fs::create_dir_all(&arch_dir).expect("failed to create ~/.arch");

        // ── 1. Load (or generate) a stable program keypair ───────────────
        let program_key_path = format!("{}/oracle_program.key", arch_dir);
        println!("=== Step 1: load program keypair from {}", program_key_path);
        let program_keypair = with_secret_key_file(&program_key_path)
            .expect("failed to load/generate program keypair")
            .0;

        // ── 2. Authority: pays for program account creation ───────────────
        println!("=== Step 2: create and fund authority");
        let (authority_keypair, authority_pubkey, _) = generate_new_keypair(config.network);
        client
            .create_and_fund_account_with_faucet(&authority_keypair)
            .await
            .expect("faucet should fund authority");
        println!("authority: {}", authority_pubkey);

        // ── 3. Deploy oracle program ──────────────────────────────────────
        println!("=== Step 3: deploy oracle program from {}", ELF_PATH);
        let program_pubkey = ProgramDeployer::new(&config)
            .try_deploy_program(
                "Oracle Program".to_string(),
                program_keypair,
                authority_keypair,
                &ELF_PATH.to_string(),
            )
            .await
            .expect("program deployment failed");
        println!("program account: {}", program_pubkey);

        // ── 4. Fee payer: covers PDA rent + oracle service fee ────────────
        println!("=== Step 4: create and fund fee payer");
        let (fee_payer_keypair, fee_payer_pubkey, _) = generate_new_keypair(config.network);
        client
            .create_and_fund_account_with_faucet(&fee_payer_keypair)
            .await
            .expect("faucet should fund fee payer");
        println!("fee_payer: {}", fee_payer_pubkey);

        // ── 5. Treasury: shared keypair with the oracle server ────────────
        let treasury_key_path = format!("{}/treasury.key", arch_dir);
        let (_, oracle_treasury_pubkey) = with_secret_key_file(&treasury_key_path)
            .expect("failed to load/generate treasury keypair");
        assert_eq!(
            oracle_treasury_pubkey.serialize(),
            ORACLE_TREASURY_PUBKEY,
            "treasury.key must match ORACLE_TREASURY_PUBKEY in shared/src/keys.rs"
        );
        println!("oracle_treasury: {}", oracle_treasury_pubkey);
        println!("oracle_fee:      {} lamports", ORACLE_FEE);

        // ── 6. Derive request PDA ─────────────────────────────────────────
        println!("=== Step 5: derive VrfRequest PDA");
        let nonce: u64 = 0;
        let (request_pda_pubkey, bump) = Pubkey::find_program_address(
            &[
                VRF_REQ_SEED,
                fee_payer_pubkey.as_ref(),
                &nonce.to_le_bytes(),
            ],
            &program_pubkey,
        );
        println!("request_pda: {} (bump={})", request_pda_pubkey, bump);

        // ── 7. Build and send RequestRandomness ───────────────────────────
        println!("=== Step 6: build and send RequestRandomness");
        let seed = [0xdeu8; 32];

        let ix_data = borsh::to_vec(&OracleInstruction::RequestRandomness {
            nonce,
            seed,
            callback_pid: [0u8; 32],
            callback_disc: [0u8; 8],
            bump,
        })
        .expect("failed to serialize instruction");

        let request_ix = Instruction {
            program_id: program_pubkey,
            accounts: vec![
                AccountMeta::new(fee_payer_pubkey, true),
                AccountMeta::new(request_pda_pubkey, false),
                AccountMeta::new(oracle_treasury_pubkey, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data: ix_data,
        };

        let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(400_000);
        let blockhash = client
            .get_best_finalized_block_hash()
            .await
            .expect("failed to get block hash");

        let tx = build_and_sign_transaction(
            ArchMessage::new(&[cu_ix, request_ix], Some(fee_payer_pubkey), blockhash),
            vec![fee_payer_keypair],
            config.network,
        )
        .expect("failed to build transaction");

        let txid = client
            .send_transaction(tx)
            .await
            .expect("failed to send transaction");
        println!("RequestRandomness txid: {}", txid);

        let processed = client
            .wait_for_processed_transaction(&txid)
            .await
            .expect("failed to wait for transaction");
        print_logs("RequestRandomness", &processed.logs);
        assert_processed(&processed.status);

        // ── 8. Verify initial account state (Pending) ────────────────────
        println!("=== Step 7: verify VrfRequest is Pending");
        let account_info = client
            .read_account_info(request_pda_pubkey)
            .await
            .expect("request PDA should exist after RequestRandomness");
        let req: VrfRequest =
            borsh::from_slice(&account_info.data).expect("failed to deserialize VrfRequest");
        assert_eq!(
            req.discriminator, REQUEST_DISCRIMINATOR,
            "wrong discriminator"
        );
        assert_eq!(req.seed, seed, "seed mismatch");
        assert_eq!(req.nonce, nonce, "nonce mismatch");
        assert_eq!(
            req.requester,
            fee_payer_pubkey.serialize(),
            "requester mismatch"
        );

        // Early-exit if the oracle already fulfilled before we polled.
        if req.status == RequestStatus::Finalized {
            println!("  VrfRequest is Finalized ✓ pi: {}", hex_encode(&req.pi));
            return;
        }

        // ── 9. Poll until the server fulfills the request ─────────────────
        println!(
            "=== Step 8: waiting for oracle server to fulfill (timeout={}s)",
            POLL_TIMEOUT_SECS
        );
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(POLL_TIMEOUT_SECS);

        let final_req = loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(POLL_INTERVAL_MS)).await;

            let info = client
                .read_account_info(request_pda_pubkey)
                .await
                .expect("request PDA should still exist");
            let req: VrfRequest =
                borsh::from_slice(&info.data).expect("failed to deserialize VrfRequest");

            println!("  status: {:?}", req.status);
            match req.status {
                RequestStatus::Finalized => break req,
                RequestStatus::Failed => panic!("VrfRequest marked Failed by oracle"),
                RequestStatus::Pending => {
                    if std::time::Instant::now() >= deadline {
                        panic!(
                            "timed out after {}s waiting for FulfillRequest",
                            POLL_TIMEOUT_SECS
                        );
                    }
                }
            }
        };

        // ── 10. Verify final state ────────────────────────────────────────
        println!("=== Step 9: verify Finalized state");
        assert_eq!(final_req.status, RequestStatus::Finalized);
        assert_ne!(
            final_req.result, [0u8; 64],
            "result should be non-zero after fulfillment"
        );
        assert_ne!(final_req.pi, [0u8; 80], "proof should be stored on-chain");
        println!("  result: {}", hex_encode(&final_req.result));
        println!("  pi:     {}", hex_encode(&final_req.pi));
        println!("=== All assertions passed ✓");
    }
}
