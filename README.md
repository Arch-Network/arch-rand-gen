# arch-rand-gen

Verifiable Random Function (VRF) oracle for the [Arch Network](https://arch.network). Any on-chain program can request unpredictable, provably-fair randomness by calling `RequestRandomness`; the oracle server responds with a cryptographic proof that lets anyone verify the random output off-chain or on-chain.

Cryptography is based on **[RFC 9381 — Verifiable Random Functions (VRFs)](https://datatracker.ietf.org/doc/html/rfc9381)**, specifically the `ECVRF-EDWARDS25519-SHA512-TAI` suite defined in Section 5.5.

---

## Repository layout

```
arch-rand-gen/
├── oracle-program/   On-chain Arch program (RBPF / SBF)
├── vrf-core/         Pure-Rust RFC 9381 VRF library
├── shared/           Constants shared between on-chain and off-chain code
├── server/           Off-chain oracle daemon
├── e2e-tests/        End-to-end integration test
├── Makefile          Build + run shortcuts
└── dev.sh            One-command tmux dev environment
```

---

## Components

### `oracle-program` — on-chain program

An Arch RBPF program that manages randomness request accounts and verifies VRF proofs on-chain.

**Instructions**

| Instruction | Accounts | Description |
|---|---|---|
| `RequestRandomness` | fee_payer (signer, writable), request_pda (writable, new), oracle_treasury (writable), system_program | Creates a `VrfRequest` PDA, transfers the oracle fee to the treasury, and stores the caller-supplied seed. Optionally accepts a `callback_pid` + `callback_disc` so the oracle can CPI back into the caller's program when the request is fulfilled. |
| `FulfillRequest` | oracle (signer), request_pda (writable), callback_program | Called exclusively by the oracle server. Verifies the VRF proof against `ORACLE_ED_PUBKEY`, writes `beta` (the 64-byte random output) into the `VrfRequest` account, marks it `Finalized`, and optionally CPIs into the callback program. |

**`VrfRequest` account layout** (Borsh, ~186 bytes)

| Field | Type | Description |
|---|---|---|
| `discriminator` | `[u8; 8]` | Unique account type tag |
| `requester` | `[u8; 32]` | Fee payer pubkey |
| `nonce` | `u64` | Caller-supplied nonce; used in PDA derivation |
| `seed` | `[u8; 32]` | Alpha string passed to the VRF |
| `status` | `RequestStatus` | `Pending` → `Finalized` or `Failed` |
| `result` | `[u8; 64]` | Beta — the verified random output |
| `pi` | `[u8; 80]` | VRF proof stored for provably-fair auditability |
| `callback_pid` | `[u8; 32]` | Optional callback program ID (`[0u8;32]` = none) |
| `callback_disc` | `[u8; 8]` | First 8 bytes prepended to the CPI data payload |
| `bump` | `u8` | PDA canonical bump |

**PDA seeds:** `[b"vrf_req", fee_payer_pubkey, nonce.to_le_bytes(), bump]`

---

### `vrf-core` — VRF cryptography

A `no_std`-compatible Rust library implementing the full RFC 9381 `ECVRF-EDWARDS25519-SHA512-TAI` suite. It is used both by the on-chain program (proof verification) and the oracle server (proof generation).

```rust
// Generate a proof (oracle server)
let pi: [u8; 80] = ecvrf_prove(&secret_key_32, alpha)?;

// Derive the random output from the proof (off-chain)
let beta: [u8; 64] = ecvrf_proof_to_hash(&pi)?;

// Verify a proof (on-chain program)
let beta: [u8; 64] = ecvrf_verify(&public_key_32, alpha, &pi)?;
```

All three steps follow the algorithms in [RFC 9381 Section 5](https://datatracker.ietf.org/doc/html/rfc9381#section-5). The test vectors in `vrf-core/tests/vrf_vectors.rs` are taken directly from [Appendix B.1](https://datatracker.ietf.org/doc/html/rfc9381#appendix-B.1).

---

### `shared` — constants

Crate used by both on-chain and off-chain code. Gated behind `features = ["on-chain"]` for programs that run without std.

| Module | Contents |
|---|---|
| `keys` | `ORACLE_ED_PUBKEY` (Ed25519, for VRF), `ORACLE_ARCH_PUBKEY` (secp256k1, for tx signing), `ORACLE_TREASURY_PUBKEY` (secp256k1, fee recipient) |
| `fees` | `ORACLE_FEE` — lamports charged per request |
| `seeds` | `VRF_REQ_SEED` — PDA seed prefix |
| `network` | Testnet / mainnet RPC + explorer URLs |

---

### `server` — oracle daemon

An async Rust service (Tokio) that listens for `RequestRandomness` instructions on-chain and automatically fulfills them.

**Architecture**

```
WebSocket listener ──(mpsc channel)──> Processor thread
     │                                       │
     │  subscribes to all processed txs      │  ecvrf_prove(oracle_ed_sk, seed) → pi
     │  filters for oracle program ixs       │  build + sign FulfillRequest tx
     │  extracts seed + request_pda          │  submit via blocking RPC
     └───────────────────────────────────────┘
```

- The **listener** maintains a persistent WebSocket connection to the Arch leader node, re-connecting automatically on disconnect.
- The **processor** runs in a `spawn_blocking` thread to avoid blocking the async runtime during the (CPU-bound) VRF proof computation.
- Key files read from `~/.arch/`: `oracle.key` (Arch signer), `oracle_program.key` (deployed program pubkey), `treasury.key` (fee recipient), `.oracle_ed.key` (Ed25519 VRF secret key).

---

### `e2e-tests` — integration test

`test_deploy_and_request_randomness` — deploys the oracle program to a running Arch localnet, submits a `RequestRandomness` instruction, and polls the `VrfRequest` PDA until the server fulfills it, then asserts the proof and random output are non-zero and the status is `Finalized`.

---

## Setup

### Prerequisites

| Tool | Purpose |
|---|---|
| Rust stable | Compile off-chain crates |
| [Solana toolchain](https://docs.solanalabs.com/cli/install) (`cargo-build-sbf`) | Compile the on-chain RBPF program |
| Arch localnet | Running Arch node + Bitcoin regtest (`arch-node`) |
| tmux | Dev environment window management |

### 1. Generate oracle keys

The oracle needs two keypairs: an Arch secp256k1 keypair (for signing transactions) and an Ed25519 keypair (for the VRF). Keys are stored under `~/.arch/`.

```bash
# Arch keypairs — generated automatically on first server run if absent.
# The files are: ~/.arch/oracle.key  ~/.arch/oracle_program.key  ~/.arch/treasury.key

# Ed25519 VRF keypair — run once, then paste the printed constant into shared/src/keys.rs.
make keygen
```

The `keygen` target runs an ignored test that writes `~/.arch/.oracle_ed.key` and prints the matching `ORACLE_ED_PUBKEY` constant. Paste that constant into `shared/src/keys.rs` before building the on-chain program. The Arch oracle signer and treasury pubkeys are also pinned in `shared/src/keys.rs`; make sure `ORACLE_ARCH_PUBKEY` matches `~/.arch/oracle.key` and `ORACLE_TREASURY_PUBKEY` matches `~/.arch/treasury.key`.

### 2. Build

```bash
make build
# or individually:
cargo build -p server
cd oracle-program && cargo build-sbf
```

### 3. Start the oracle server

```bash
make server
# or:
cargo run -p server
```

The server connects to `ws://127.0.0.1:10080` and begins listening for requests.

### 4. Run the end-to-end test

With Arch localnet running and the server started:

```bash
make e2e
```

This deploys the oracle program to localnet, sends a `RequestRandomness`, and waits for the server to fulfill it.

---

## Quick start (all-in-one)

```bash
./dev.sh
```

Builds everything, then opens a tmux session with two windows:

| Window | Command |
|---|---|
| `oracle` | `cargo run -p server` |
| `e2e` | Waits for localnet, then runs `test_deploy_and_request_randomness` |

Options:

```
--skip-build   Skip build steps (use existing binaries)
--skip-e2e     Open the e2e window as a plain shell (server only)
```

Switch windows with `Ctrl+B N` / `Ctrl+B P`. Detach with `Ctrl+B D`.

---

## How it works (end-to-end flow)

```
Caller tx
  RequestRandomness { seed, callback_pid, callback_disc, bump }
    → oracle-program: create VrfRequest PDA (Pending), transfer fee

Oracle server (listener)
    → detects RequestRandomness instruction on-chain

Oracle server (processor)
    → pi = ecvrf_prove(oracle_ed_sk, seed)          [RFC 9381 §5.1]
    → submit FulfillRequest { pi }

oracle-program (on-chain)
    → beta = ecvrf_verify(ORACLE_ED_PUBKEY, seed, pi) [RFC 9381 §5.3]
    → write beta + pi into VrfRequest PDA, mark Finalized
    → if callback_pid != [0;32]: CPI(callback_pid, callback_disc ++ beta)

Caller (callback or poll)
    → read VrfRequest.result  →  64 bytes of verifiable randomness
```

The random output (`beta`) is fully deterministic given the oracle's secret key and the caller-supplied seed, yet unpredictable to the caller before the oracle publishes `pi`. Anyone can re-verify the output independently using `ecvrf_verify`.

---

## On-chain vs off-chain verification

The `FulfillRequest` instruction runs `ecvrf_verify` inside the RBPF VM to confirm the proof before writing `beta` to the `VrfRequest` account. This means the verification already happens on-chain as part of the oracle's fulfillment transaction — callers receive a result they can trust without doing any additional cryptographic work themselves.

It is technically possible for a caller program to re-verify the proof on-chain by importing `vrf-core` and calling `ecvrf_verify` directly. However, the full RFC 9381 ECVRF verification involves several Edwards25519 point decompressions, scalar multiplications, and a hash-to-curve operation, which together consume well over 1.4 million compute units — exceeding the current per-transaction CU budget. **On-chain re-verification by consumer programs is therefore not practical at this time.** Off-chain verification (see below) is the recommended approach for provably-fair auditing.

For the remaining production-readiness work, including decentralization,
request expiry/refunds, durable server processing, account cleanup, dynamic
fees, key rotation, monitoring, and audit requirements, see
[`docs/production-hardening.md`](docs/production-hardening.md).

---

## Provably fair verification

```bash
# Given: pi (hex), seed (hex), oracle_ed_pubkey (hex from shared/src/keys.rs)
# Derive beta off-chain:
python3 - <<'EOF'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
# ... or use any RFC 9381-compatible library
EOF
```

Because the proof `pi` is stored in the `VrfRequest` account, anyone can independently verify that `beta` was computed correctly from the published oracle public key and the original seed — no trust in the oracle operator required.

---

## Integrating from another program

Add a `RequestRandomness` CPI to your program:

```rust
let ix = Instruction {
    program_id: oracle_program_id,
    accounts: vec![
        AccountMeta::new(fee_payer,       true),   // signer, writable
        AccountMeta::new(request_pda,     false),  // writable, new
        AccountMeta::new(oracle_treasury, false),  // writable; must match ORACLE_TREASURY_PUBKEY
        AccountMeta::new_readonly(system_program::ID, false),
    ],
    data: borsh::to_vec(&OracleInstruction::RequestRandomness {
        nonce,
        seed,
        callback_pid: *your_program_id.as_ref(),  // oracle will CPI back here
        callback_disc: YOUR_CALLBACK_DISCRIMINATOR,
        bump,
    })?,
};
invoke(&ix, &[fee_payer_info, request_pda_info, treasury_info, system_info])?;
```

Your program's callback entry point receives `callback_disc ++ beta` as instruction data, where `beta` is the 64-byte verified random output.

---

## References

- [RFC 9381 — Verifiable Random Functions (VRFs)](https://datatracker.ietf.org/doc/html/rfc9381)
- [Arch Network documentation](https://docs.arch.network)
- [Arch Network Explorer (testnet)](https://explorer.test.arch.network)
