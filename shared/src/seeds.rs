/// PDA seed for the oracle VRF request account.
/// Full seeds: [VRF_REQ_SEED, fee_payer_pubkey, nonce.to_le_bytes(), bump]
pub const VRF_REQ_SEED: &[u8] = b"vrf_req";
