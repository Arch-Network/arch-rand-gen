use arch_program::program_error::ProgramError;
use vrf_core::VrfError;

#[derive(Debug)]
pub enum OracleError {
    // ── Instruction parsing ──────────────────────────────────────────────
    InvalidInstructionData,

    // ── RequestRandomness ────────────────────────────────────────────────
    PdaCreationFailed,
    AccountSerializeFailed,
    InvalidOracleTreasury,

    // ── FulfillRequest — oracle authority ───────────────────────────────
    InvalidOracleSigner,

    // ── FulfillRequest — account state ──────────────────────────────────
    AccountDeserializeFailed,
    WrongDiscriminator,
    RequestNotPending,

    // ── FulfillRequest — VRF verification ───────────────────────────────
    /// Wraps the underlying VrfError for full debuggability.
    /// Error codes 7–12 map to VrfError variants in order.
    CryptoError(VrfError),

    // ── FulfillRequest — post-verify ────────────────────────────────────
    AccountReserializeFailed,
    CallbackFailed,
}

impl From<OracleError> for ProgramError {
    fn from(e: OracleError) -> Self {
        let code: u32 = match e {
            OracleError::InvalidInstructionData => 0,
            OracleError::PdaCreationFailed => 1,
            OracleError::AccountSerializeFailed => 2,
            OracleError::InvalidOracleTreasury => 15,
            OracleError::InvalidOracleSigner => 3,
            OracleError::AccountDeserializeFailed => 4,
            OracleError::WrongDiscriminator => 5,
            OracleError::RequestNotPending => 6,
            OracleError::CryptoError(ref vrf_err) => match vrf_err {
                VrfError::BadPublicKey => 7,
                VrfError::SmallOrderKey => 8,
                VrfError::BadGammaPoint => 9,
                VrfError::NonCanonicalScalar => 10,
                VrfError::HashToCurveFailed => 11,
                VrfError::ChallengeMismatch => 12,
            },
            OracleError::AccountReserializeFailed => 13,
            OracleError::CallbackFailed => 14,
        };
        ProgramError::Custom(code)
    }
}
