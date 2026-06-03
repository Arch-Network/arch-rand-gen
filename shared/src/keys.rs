/// Ed25519 (Ed curve) public key of the oracle — used for VRF proof verification only.
/// Generate with: cargo test -p vrf-core --test generate_oracle_ed_key generate_oracle_ed_key -- --ignored --nocapture
/// then paste the printed constant here.
pub const ORACLE_ED_PUBKEY: [u8; 32] = [
    123, 229, 31, 213, 164, 107, 93, 148, 15, 169, 164, 114, 98, 140, 199, 192, 116, 122, 41, 94,
    222, 146, 166, 229, 9, 126, 50, 151, 88, 114, 15, 179,
];

/// Arch (secp256k1) pubkey of the oracle signer account — must match the signer on FulfillRequest.
/// Set to the pubkey from $HOME/.arch/oracle.key.
pub const ORACLE_ARCH_PUBKEY: [u8; 32] = [
    43, 38, 115, 65, 178, 79, 221, 43, 146, 247, 10, 159, 138, 25, 38, 166, 119, 83, 58, 180, 110,
    44, 107, 68, 100, 155, 151, 239, 121, 170, 148, 53,
];

/// Arch (secp256k1) pubkey of the treasury account — receives RequestRandomness fees.
/// Set to the pubkey from $HOME/.arch/treasury.key.
pub const ORACLE_TREASURY_PUBKEY: [u8; 32] = [
    43, 38, 115, 65, 178, 79, 221, 43, 146, 247, 10, 159, 138, 25, 38, 166, 119, 83, 58, 180, 110,
    44, 107, 68, 100, 155, 151, 239, 121, 170, 148, 53,
];

/// Lamports charged per randomness request.
/// Computed by `shared::fees::calculate_oracle_fee` — see fees.rs for the breakdown.
pub use crate::fees::ORACLE_FEE;
