use borsh::{BorshDeserialize, BorshSerialize};

pub const REQUEST_DISCRIMINATOR: [u8; 8] = *b"vrfreq\0\0";

/// Fixed serialized size of a VrfRequest account (bytes).
/// 8 + 32 + 8 + 32 + 1 + 64 + 32 + 8 + 1 + 80 = 266
pub const VRF_REQUEST_SIZE: usize = 266;

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct VrfRequest {
    /// Identifies this account type; must equal REQUEST_DISCRIMINATOR.
    pub discriminator: [u8; 8],
    /// Wallet that called RequestRandomness (pays rent).
    pub requester: [u8; 32],
    /// Nonce chosen by the requester; part of PDA seeds.
    pub nonce: u64,
    /// VRF input alpha committed at request time.
    pub seed: [u8; 32],
    pub status: RequestStatus,
    /// 64-byte VRF output (beta); zero-filled until status == Finalized.
    pub result: [u8; 64],
    /// Consumer program that receives the CPI callback on fulfillment.
    pub callback_pid: [u8; 32],
    /// Instruction discriminator forwarded to the consumer callback.
    pub callback_disc: [u8; 8],
    /// PDA bump seed stored for convenience.
    pub bump: u8,
    /// 80-byte VRF proof (pi); stored for off-chain auditability.
    pub pi: [u8; 80],
}

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Clone, Copy, Debug)]
#[borsh(use_discriminant = true)]
pub enum RequestStatus {
    Pending = 0,
    Finalized = 1,
    Failed = 2,
}
