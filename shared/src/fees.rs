/// Oracle fee calculation for RequestRandomness.
///
/// The user pays ORACLE_FEE lamports into the treasury when calling
/// RequestRandomness. The treasury uses these funds to pay for the
/// FulfillRequest transaction that the oracle server submits on-chain.
///
/// Total fee = flat_service_fee
///           + (fulfill_compute_units × lamports_per_cu)
///           + (base_fee_per_signer  × fulfill_tx_signers)

/// Flat service fee component, in lamports.
/// Covers oracle infrastructure, key management, and operational costs.
pub const FLAT_SERVICE_FEE: u64 = 50_000;

/// Estimated compute units consumed by one FulfillRequest transaction.
/// The oracle server sets set_compute_unit_limit(1_400_000) = MAX_COMPUTE_UNIT_LIMIT.
pub const FULFILL_REQUEST_COMPUTE_UNITS: u64 = 1_400_000;

/// Lamport cost per compute unit.
/// Arch Network does not currently expose a per-CU price mechanism, so this is 0.
/// Update when Arch introduces priority fees.
pub const LAMPORTS_PER_COMPUTE_UNIT: u64 = 0;

/// Base transaction fee per signer, in lamports.
/// FulfillRequest is co-signed by the oracle account and the treasury (2 signatures).
pub const BASE_FEE_PER_SIGNER: u64 = 5_000;

/// Number of signers on the FulfillRequest transaction.
pub const FULFILL_TX_SIGNERS: u64 = 2;

/// Calculate the oracle fee for a given compute-unit price.
///
/// This is a `const fn` so it can be used to initialise other constants.
/// Pass `LAMPORTS_PER_COMPUTE_UNIT` for the canonical fee, or a custom
/// value when the network introduces dynamic pricing.
pub const fn calculate_oracle_fee(lamports_per_cu: u64) -> u64 {
    FLAT_SERVICE_FEE
        + FULFILL_REQUEST_COMPUTE_UNITS * lamports_per_cu
        + BASE_FEE_PER_SIGNER * FULFILL_TX_SIGNERS
}

/// Total oracle fee charged on RequestRandomness, in lamports.
/// = 50_000 (service) + 0 (compute) + 10_000 (2 × sig fee) = 60_000 lamports
pub const ORACLE_FEE: u64 = calculate_oracle_fee(LAMPORTS_PER_COMPUTE_UNIT);
