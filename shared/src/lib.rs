pub mod fees;
pub mod keys;
pub mod seeds;

// network constants are only useful to off-chain crates (server, e2e-tests, frontend).
// On-chain programs import shared with features = ["on-chain"] to skip this module.
#[cfg(not(feature = "on-chain"))]
pub mod network;
