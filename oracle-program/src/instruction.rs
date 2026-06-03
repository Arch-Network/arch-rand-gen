use borsh::{BorshDeserialize, BorshSerialize};

#[derive(BorshSerialize, BorshDeserialize)]
pub enum OracleInstruction {
    /// Create a new randomness request.
    ///
    /// Accounts:
    ///   0. `[signer, writable]` fee_payer     — pays PDA rent + oracle fee
    ///   1. `[writable]`         request_pda   — created by this instruction
    ///   2. `[writable]`         oracle_treasury — must match ORACLE_TREASURY_PUBKEY
    ///   3. `[]`                 system_program
    RequestRandomness {
        nonce: u64,
        seed: [u8; 32],
        callback_pid: [u8; 32],
        callback_disc: [u8; 8],
        bump: u8,
    },

    /// Fulfill a pending randomness request.
    /// Verifies pi against ORACLE_ED_PUBKEY and the request seed, stores pi and result,
    /// then CPIs into the callback program with accounts[3..] forwarded as extras.
    ///
    /// Accounts:
    ///   0. `[signer]`   oracle           — must match ORACLE_ARCH_PUBKEY
    ///   1. `[writable]` request_pda      — must be Pending; set to Finalized/Failed
    ///   2. `[]`         callback_program — consumer program for CPI
    ///   3+. (forwarded) extra accounts   — passed through to the callback as-is
    FulfillRequest { pi: [u8; 80] },
}
