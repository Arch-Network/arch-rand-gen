# Production hardening plan

This document tracks the remaining work required to move this oracle from a
single-operator demo toward production-ready verifiable randomness.

The current patch addresses the first two critical issues:

- `FulfillRequest` verifies the VRF proof on-chain with `ecvrf_verify`.
- `RequestRandomness` constrains fees to `ORACLE_TREASURY_PUBKEY`.

Everything below is still required before mainnet use.

## Priorities

1. Remove single-operator trust and single points of failure.
2. Add request lifecycle controls so users can recover from oracle failure.
3. Make the off-chain server durable, observable, and retry-safe.
4. Make fees and account cleanup sustainable.
5. Lock down the crypto API surface and complete assurance work.
6. Replace ad hoc key handling with production operations.

## 1. Decentralize randomness production

### Problem

One Ed25519 VRF key and one Arch signer currently control all fulfillment. A
key compromise can bias outputs, and downtime or censorship halts fulfillment.

### Code plan

- Introduce an `OracleCommittee` config account owned by the oracle program:
  - committee authority
  - active oracle members
  - per-member VRF public keys
  - per-member Arch signer pubkeys
  - quorum threshold
  - version/epoch
- Replace `ORACLE_ED_PUBKEY` and `ORACLE_ARCH_PUBKEY` as hardcoded global trust
  roots with committee state loaded by the program.
- Change `VrfRequest` to track partial fulfillments:
  - request alpha
  - committee epoch
  - bitmap or vector of fulfilled members
  - per-member proof/output commitments or stored proofs
  - final combined result
- Add `SubmitPartialFulfillment` for each oracle member.
- Add `FinalizeRequest` once quorum is reached.
- Combine independent outputs with domain-separated hashing, for example:
  - `final_beta = sha512("arch-vrf-v1" || request_pda || epoch || beta_1 || ... || beta_n)`
  - require a stable ordering by committee member index.

### Alternatives to decide before implementation

- N-of-M independent VRFs with output combination. This is simpler to ship and
  audit incrementally.
- FROST beacon. This gives a stronger threshold-signing model but requires a
  larger protocol and key-generation ceremony.

### Acceptance checks

- A single oracle member cannot finalize a request when threshold > 1.
- Reordered partial fulfillments produce the same final output.
- Invalid member signatures/proofs are rejected.
- Committee rotation cannot alter already-created requests because each request
  stores its committee epoch.

### Work outside this repo

- Define the oracle operator set and governance process.
- Decide whether the production target is independent VRFs or FROST.
- Run key ceremony and operator onboarding.

## 2. Simplify and domain-separate the VRF alpha

### Problem

The current alpha mixes caller seed, block height, slot, timestamp, and treasury
balance. Public chain values do not fix oracle bias and treasury balance couples
randomness to fee-account state.

### Code plan

- Replace the current seed mix with an explicit request commitment:
  - `alpha = sha256("arch-rand-gen:v1" || requester || nonce || user_seed || callback_pid || callback_disc)`
- Store both `user_seed` and computed `alpha`, or rename the existing stored
  field to make clear that it is the VRF alpha.
- Update the server listener to prove over the stored alpha, not the raw
  instruction seed, or ensure both sides derive alpha identically.
- Add tests proving:
  - same requester/nonce/user_seed gives the same PDA and alpha
  - changing callback or nonce changes alpha
  - treasury lamports do not affect alpha

### Acceptance checks

- On-chain and server derivation match exactly.
- Existing docs call the field `alpha` when it is not the raw user seed.
- No account balance is part of randomness derivation.

### Compatibility note

Changing alpha derivation is a breaking behavior change for in-flight pending
requests. Apply it with a program version bump or reject old pending requests
before migration.

## 3. Add timeout, cancel, refund, and close flows

### Problem

Pending requests can remain stuck forever. Finalized/failed accounts are never
closed, so rent and state accumulate indefinitely.

### Code plan

- Extend `VrfRequest` with lifecycle fields:
  - `created_slot`
  - `expires_slot`
  - `fee_paid`
  - `rent_payer`
- Add `CancelRequest`:
  - requester-only
  - allowed only while `Pending`
  - allowed only after `expires_slot`
  - marks request `Cancelled` or closes immediately
  - refunds any refundable lamports according to the fee policy
- Add `CloseRequest`:
  - requester-only, or requester plus optional cleanup authority
  - allowed after `Finalized`, `Failed`, or `Cancelled`
  - transfers remaining lamports to requester
  - zeroes or reallocates account as appropriate for Arch program semantics
- Define callback failure behavior:
  - keep current `Failed` status but allow close
  - do not retry callback indefinitely unless request state explicitly supports it

### Acceptance checks

- Pending before expiry cannot be cancelled.
- Pending after expiry can be cancelled by requester.
- Non-requesters cannot cancel or close unless explicitly authorized.
- Finalized, failed, and cancelled requests can be closed.
- Account lamports are reclaimed to the expected destination.

### Work outside this repo

- Decide the refund split between service fee and transaction/rent costs.
- Publish requester-facing guidance on expiry and close behavior.

## 4. Make the oracle server durable

### Problem

The server relies on live WebSocket events and logs-and-continues on many RPC
errors. Downtime can permanently miss requests.

### Code plan

- Add persistent request storage:
  - SQLite, Postgres, or another durable queue
  - unique key by request PDA
  - states: discovered, proving, submitted, confirmed, failed, abandoned
  - retry count and next retry time
- Add a periodic reconciliation loop:
  - scan `get_program_accounts` for pending requests
  - enqueue any pending request missing from local storage
  - compare stored status with on-chain status
- Add retry with exponential backoff for:
  - RPC fetch failures
  - blockhash fetch failures
  - transaction send failures
  - confirmation timeouts
- Make fulfillment idempotent:
  - before proving/submitting, read request state and skip non-pending requests
  - tolerate duplicate queue entries
- Add graceful shutdown:
  - stop intake
  - finish or checkpoint in-flight jobs

### Acceptance checks

- If the server is down during a request, reconciliation later finds and fulfills it.
- Duplicate WebSocket events do not submit conflicting finalizations.
- RPC errors are retried with bounded backoff.
- Restarting the server preserves pending work.

### Work outside this repo

- Pick the production database and backup/retention policy.
- Provision managed storage and credentials.
- Add deployment health checks.

## 5. Make fees sustainable and governable

### Problem

`ORACLE_FEE` is compile-time static and assumes zero compute-unit price. The
treasury can go underwater when fee markets change.

### Code plan

- Introduce a `FeeConfig` account:
  - flat service fee
  - base signer fee
  - compute unit estimate
  - lamports per compute unit
  - minimum treasury balance
  - config authority
- Read `FeeConfig` in `RequestRandomness` and charge the computed fee.
- Store `fee_paid` in `VrfRequest`.
- Add `UpdateFeeConfig` gated by governance/admin authority.
- Add server-side treasury monitoring:
  - warn below threshold
  - stop accepting work or raise alerts if treasury cannot pay fulfillment

### Acceptance checks

- Requests fail if the fee payer cannot pay the current configured fee.
- Fee changes affect new requests only.
- Existing requests retain their paid fee for accounting/refund logic.
- Treasury-balance alerts fire below the configured threshold.

### Work outside this repo

- Decide governance authority for fee changes.
- Define production alert thresholds.
- Monitor actual compute-unit usage and update estimates.

## 6. Choose the long-term on-chain verification strategy

### Problem

Full Ed25519 ECVRF verification is expensive under RBPF limits. The current
single-shot verify may be acceptable only if it fits current compute budgets.

### Code plan, option A: two-transaction Ed25519 verification

- Add a `BeginVerify` instruction that calls `ecvrf_begin_verify`.
- Store `h_compressed` and `u_compressed` in request state or a verification PDA.
- Add `FinishVerify` that calls `ecvrf_finish_verify` and writes the result.
- Make the server submit both transactions and resume safely if one succeeds.

### Code plan, option B: migrate to secp256k1 VRF

- Implement or adopt an ECVRF-secp256k1 suite.
- Use Arch/native secp256k1 recovery or verification syscalls where possible.
- Replace Ed25519 VRF keys with secp256k1 VRF keys.
- Add RFC-compatible or suite-specific test vectors.

### Acceptance checks

- Verification fits within network compute limits with margin.
- Invalid proofs fail before result write.
- Server can recover after partial two-transaction progress.

### Work outside this repo

- Benchmark on the target Arch runtime.
- Choose Ed25519 split verification versus secp256k1 migration.
- Have the selected crypto design reviewed before mainnet.

## 7. Lock down crypto API footguns

### Problem

`ecvrf_proof_to_hash` is exposed next to `ecvrf_verify`, which made it easy to
ship unverified fulfillment.

### Code plan

- Remove `ecvrf_proof_to_hash` from the public API if no safe production use
  remains.
- If it must remain for tests or tooling:
  - gate it behind a feature such as `unchecked-proof-to-hash`
  - mark it `#[doc(hidden)]`
  - rename it to `unchecked_proof_to_hash`
  - add docs that it must never be used for accepting oracle output
- Add a code search or lint check in CI that rejects on-chain use of unchecked
  helpers.

### Acceptance checks

- `oracle-program` cannot compile if it tries to call the unchecked helper
  without explicitly enabling the unsafe feature.
- Public docs show `ecvrf_verify` as the normal verification path.

## 8. Expand crypto and program assurance

### Problem

The core has RFC vectors, but production use needs negative-path tests, fuzzing,
and external review.

### Code plan

- Add property/fuzz tests for proof decoding:
  - non-canonical scalars
  - malformed compressed points
  - small-order public keys
  - challenge mismatch
  - truncated/length-invalid inputs at API boundaries
- Add program-level tests for:
  - invalid treasury
  - invalid oracle signer
  - invalid VRF proof
  - wrong request status
  - callback failure status
  - cancel/close flows after those are implemented
- Add deterministic fixtures for request alpha derivation.
- Add CI jobs for `cargo test`, formatting, and SBF build once the Arch SDK path
  is available in CI.

### Acceptance checks

- Fuzz corpus runs without panics.
- Each `OracleError` variant has a test path.
- CI builds the on-chain program and server in a clean environment.

### Work outside this repo

- Schedule a third-party cryptography and smart-contract audit.
- Track audit findings to closure before mainnet.

## 9. Production key management and operations

### Problem

Keys are local files under `~/.arch`, key rotation requires redeploy for
hardcoded pubkeys, and there are no metrics or alerts.

### Code plan

- Move from hardcoded keys to on-chain config accounts:
  - signer keys
  - VRF public keys
  - treasury pubkey
  - fee config
  - committee epoch
- Add key rotation instructions:
  - propose new keys
  - activate after delay or governance approval
  - keep old committee epochs for in-flight requests
- Add metrics to the server:
  - requests discovered
  - fulfillments submitted/confirmed/failed
  - queue depth
  - retry count
  - RPC latency/error rate
  - treasury balance
- Add structured logs with request PDA, nonce, status, and transaction id.
- Add rate limiting or admission control:
  - per-requester caps
  - global queue cap
  - reject or price requests when treasury/queue pressure is high

### Acceptance checks

- Keys can rotate without redeploying the program.
- In-flight requests remain tied to their original committee/config epoch.
- Alerts fire for stuck pending requests, low treasury balance, and server
  liveness failure.

### Work outside this repo

- Choose HSM/KMS provider and signing flow.
- Provision metrics/alerting stack.
- Define incident response and key-compromise runbooks.

## Suggested implementation sequence

1. Add lifecycle fields, expiry, cancel, and close. This is self-contained and
   immediately improves user safety.
2. Replace alpha mixing with domain-separated alpha derivation, then align
   server and docs.
3. Add durable queue, retry/backoff, and reconciliation scan to the server.
4. Move fee and treasury configuration into on-chain config accounts.
5. Lock down `ecvrf_proof_to_hash` and add missing negative tests.
6. Benchmark verification and choose either two-transaction Ed25519 verification
   or secp256k1 VRF.
7. Implement committee/quorum or FROST design.
8. Add key rotation, metrics, alerting, rate limiting, and audit remediation.

## Definition of production-ready

The oracle should not be considered production-ready until:

- No single operator can unilaterally bias finalized randomness.
- Users can cancel expired pending requests and reclaim eligible lamports.
- Finalized/failed/cancelled request accounts can be closed.
- Server downtime does not permanently lose requests.
- Fees can be updated without redeploying the program.
- Keys can rotate without redeploying the program.
- All proof acceptance paths verify cryptographically on-chain.
- CI covers crypto vectors, negative tests, program tests, server tests, and SBF
  builds.
- Independent audit findings are resolved or explicitly accepted.
