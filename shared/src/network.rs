// Network constants are not needed by on-chain programs (which have no network
// access). On-chain programs use the "no-std" feature; off-chain crates do not.

pub const ARCH_RPC_TESTNET: &str = "https://rpc.testnet.arch.network";
pub const ARCH_RPC_MAINNET: &str = "https://rpc.arch.network";

pub const ARCH_EXPLORER_TESTNET: &str = "https://explorer.arch.network";
pub const ARCH_EXPLORER_MAINNET: &str = "https://explorer.arch.network";
