pub mod error;
pub mod instruction;
pub mod state;

use arch_program::{
    account::{AccountInfo, AccountMeta},
    hashing_functions::sha256,
    instruction::Instruction,
    msg,
    program::{get_bitcoin_block_height, get_clock, invoke, invoke_signed, next_account_info},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::minimum_rent,
    system_instruction::{create_account, transfer},
};

use error::OracleError;
use instruction::OracleInstruction;
use state::{RequestStatus, VrfRequest, REQUEST_DISCRIMINATOR};

pub use shared::keys::{ORACLE_ARCH_PUBKEY, ORACLE_ED_PUBKEY, ORACLE_FEE, ORACLE_TREASURY_PUBKEY};
use shared::seeds::VRF_REQ_SEED;

#[cfg(not(any(test, feature = "no-entrypoint")))]
use arch_program::entrypoint;
#[cfg(not(any(test, feature = "no-entrypoint")))]
entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> Result<(), ProgramError> {
    let ix: OracleInstruction =
        borsh::from_slice(instruction_data).map_err(|_| OracleError::InvalidInstructionData)?;

    match ix {
        OracleInstruction::RequestRandomness {
            nonce,
            seed,
            callback_pid,
            callback_disc,
            bump,
        } => process_request_randomness(
            program_id,
            accounts,
            nonce,
            seed,
            callback_pid,
            callback_disc,
            bump,
        ),

        OracleInstruction::FulfillRequest { pi } => process_fulfill_request(accounts, pi),
    }
}

// ── RequestRandomness ─────────────────────────────────────────────────────

fn process_request_randomness(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    nonce: u64,
    seed: [u8; 32],
    callback_pid: [u8; 32],
    callback_disc: [u8; 8],
    bump: u8,
) -> Result<(), ProgramError> {
    msg!("RequestRandomness: start nonce={}", nonce);

    let iter = &mut accounts.iter();
    let fee_payer = next_account_info(iter)?;
    let request_pda = next_account_info(iter)?;
    let oracle_treasury = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    msg!(
        "RequestRandomness: fee_payer={} pda={} treasury={}",
        fee_payer.key,
        request_pda.key,
        oracle_treasury.key,
    );

    if oracle_treasury.key.serialize() != ORACLE_TREASURY_PUBKEY {
        msg!("RequestRandomness: invalid oracle treasury");
        return Err(OracleError::InvalidOracleTreasury.into());
    }

    let nonce_bytes = nonce.to_le_bytes();
    let seeds: &[&[u8]] = &[VRF_REQ_SEED, fee_payer.key.as_ref(), &nonce_bytes, &[bump]];

    // Mix the caller-supplied seed with on-chain entropy so that even a
    // repeated or predictable seed produces a unique VRF alpha each time.
    //   sha256(seed || block_height || slot || unix_timestamp || treasury_lamports)
    let block_height = get_bitcoin_block_height();
    let clock = get_clock();
    let treasury_lamports = **oracle_treasury.lamports.borrow();
    let mut mix = Vec::with_capacity(32 + 8 + 8 + 8 + 8);
    mix.extend_from_slice(&seed);
    mix.extend_from_slice(&block_height.to_le_bytes());
    mix.extend_from_slice(&clock.slot.to_le_bytes());
    mix.extend_from_slice(&clock.unix_timestamp.to_le_bytes());
    mix.extend_from_slice(&treasury_lamports.to_le_bytes());
    let mixed_seed = sha256(&mix).to_bytes();

    msg!(
        "RequestRandomness: block_height={} slot={} ts={} treasury={}",
        block_height,
        clock.slot,
        clock.unix_timestamp,
        treasury_lamports,
    );

    // Serialize the initial state first so we know the exact byte length.
    let req = VrfRequest {
        discriminator: REQUEST_DISCRIMINATOR,
        requester: fee_payer.key.serialize(),
        nonce,
        seed: mixed_seed,
        status: RequestStatus::Pending,
        result: [0u8; 64],
        callback_pid,
        callback_disc,
        bump,
        pi: [0u8; 80],
    };
    let serialized = borsh::to_vec(&req).map_err(|_| OracleError::AccountSerializeFailed)?;
    let space = serialized.len();

    msg!(
        "RequestRandomness: serialized {} bytes, creating PDA",
        space
    );

    // Create the PDA account (no Bitcoin anchor required).
    invoke_signed(
        &create_account(
            fee_payer.key,
            request_pda.key,
            minimum_rent(space),
            space as u64,
            program_id,
        ),
        &[
            fee_payer.clone(),
            request_pda.clone(),
            system_program.clone(),
        ],
        &[seeds],
    )
    .map_err(|_| OracleError::PdaCreationFailed)?;

    msg!("RequestRandomness: PDA created, writing state");

    // Write state into the freshly allocated account.
    request_pda.data.borrow_mut().copy_from_slice(&serialized);

    msg!(
        "RequestRandomness: state written, transferring oracle fee {}",
        ORACLE_FEE
    );

    // Transfer the oracle service fee to the treasury.
    invoke(
        &transfer(fee_payer.key, oracle_treasury.key, ORACLE_FEE),
        &[
            fee_payer.clone(),
            oracle_treasury.clone(),
            system_program.clone(),
        ],
    )
    .map_err(|_| OracleError::PdaCreationFailed)?;

    msg!("RequestRandomness: done");

    Ok(())
}

// ── FulfillRequest ────────────────────────────────────────────────────────

fn process_fulfill_request(accounts: &[AccountInfo], pi: [u8; 80]) -> Result<(), ProgramError> {
    msg!("FulfillRequest: start");

    let iter = &mut accounts.iter();
    let oracle = next_account_info(iter)?;
    let request_pda = next_account_info(iter)?;
    let callback_program = next_account_info(iter)?;

    msg!(
        "FulfillRequest: oracle={} pda={}",
        oracle.key,
        request_pda.key
    );

    if oracle.key.serialize() != ORACLE_ARCH_PUBKEY {
        msg!("FulfillRequest: invalid oracle signer");
        return Err(OracleError::InvalidOracleSigner.into());
    }

    let mut req: VrfRequest = borsh::from_slice(&request_pda.data.borrow())
        .map_err(|_| OracleError::AccountDeserializeFailed)?;

    if req.discriminator != REQUEST_DISCRIMINATOR {
        return Err(OracleError::WrongDiscriminator.into());
    }
    if req.status != RequestStatus::Pending {
        msg!("FulfillRequest: not pending, status={:?}", req.status);
        return Err(OracleError::RequestNotPending.into());
    }

    msg!("FulfillRequest: verifying VRF proof");

    let beta = vrf_core::ecvrf_verify(&ORACLE_ED_PUBKEY, &req.seed, &pi)
        .map_err(OracleError::CryptoError)?;

    req.result = beta;
    req.pi = pi;

    // Attempt the callback CPI if one was registered.
    // We intentionally do NOT use `?` so that a callback failure doesn't
    // revert the proof/result we just wrote.  The CPI's own account mutations
    // are rolled back on error, but our account changes survive as long as
    // this instruction returns Ok(()).
    let has_callback = req.callback_pid != [0u8; 32];
    if has_callback {
        msg!("FulfillRequest: invoking callback");
        let mut callback_data = req.callback_disc.to_vec();
        callback_data.extend_from_slice(&beta);

        // Build callback account list: request_pda first, then any extra
        // accounts forwarded from accounts[3..] (e.g. bet_pda, player, house).
        let mut cb_accounts_meta = vec![AccountMeta::new_readonly(*request_pda.key, false)];
        for acc in accounts[3..].iter() {
            cb_accounts_meta.push(if acc.is_writable {
                AccountMeta::new(*acc.key, false)
            } else {
                AccountMeta::new_readonly(*acc.key, false)
            });
        }

        let callback_ix = Instruction {
            program_id: Pubkey::from(req.callback_pid),
            accounts: cb_accounts_meta,
            data: callback_data,
        };

        // callback_program must be in the infos so the runtime can load it.
        let mut cb_infos: Vec<AccountInfo> = vec![request_pda.clone(), callback_program.clone()];
        cb_infos.extend_from_slice(&accounts[3..]);

        let callback_result = invoke(&callback_ix, &cb_infos);
        if callback_result.is_err() {
            msg!("FulfillRequest: callback failed, marking Failed");
            req.status = RequestStatus::Failed;
        } else {
            req.status = RequestStatus::Finalized;
        }
    } else {
        req.status = RequestStatus::Finalized;
    }

    msg!(
        "FulfillRequest: writing result, proof, status={:?}",
        req.status
    );
    let serialized = borsh::to_vec(&req).map_err(|_| OracleError::AccountReserializeFailed)?;
    request_pda.data.borrow_mut().copy_from_slice(&serialized);

    Ok(())
}
