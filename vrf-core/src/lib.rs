use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{IsIdentity, VartimeMultiscalarMul},
};
use sha2::{Digest, Sha512};

/// ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 suite 0x03)
const SUITE: u8 = 0x03;
const C_LEN: usize = 16; // challenge bytes (cLen)
const PT_LEN: usize = 32; // compressed point bytes
const Q_LEN: usize = 32; // scalar bytes (qLen)

pub const PROOF_LEN: usize = PT_LEN + C_LEN + Q_LEN; // 80 bytes
pub const BETA_LEN: usize = 64;

#[derive(Debug, PartialEq)]
pub enum VrfError {
    /// PK bytes do not decode to a valid curve point
    BadPublicKey,
    /// PK is a small-order point (insecure / RFC 9381 §5.6.1)
    SmallOrderKey,
    /// Gamma bytes in the proof do not decode to a valid curve point
    BadGammaPoint,
    /// s scalar in the proof is >= field order q (non-canonical)
    NonCanonicalScalar,
    /// encode_to_curve exhausted all 256 attempts without finding a valid point
    HashToCurveFailed,
    /// Recomputed challenge c' does not match the proof's c
    ChallengeMismatch,
}

/// VRF_prove(SK, alpha) — RFC 9381 §5.1
///
/// - `sk`    : 32-byte ed25519 secret key
/// - `alpha` : the seed/message to sign
///
/// Derives the 32-byte compressed Ed25519 public key from a 32-byte secret (same as used for VRF).
pub fn ecvrf_public_key(sk: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(sk);
    let hashed_sk = hasher.finalize();
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&hashed_sk[..32]);
    x_bytes[0] &= 248;
    x_bytes[31] &= 127;
    x_bytes[31] |= 64;
    let x = Scalar::from_bytes_mod_order(x_bytes);
    let pk_point = &x * ED25519_BASEPOINT_POINT;
    pk_point.compress().to_bytes()
}

/// Returns the 80-byte VRF proof (pi) on success.
pub fn ecvrf_prove(sk: &[u8; 32], alpha: &[u8]) -> Result<[u8; PROOF_LEN], VrfError> {
    // Step 1: expand SK via SHA-512, then apply EdDSA scalar clamping (RFC 8032 §5.1.5)
    let mut hasher = Sha512::new();
    hasher.update(sk);
    let hashed_sk = hasher.finalize();

    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&hashed_sk[..32]);
    x_bytes[0] &= 248;
    x_bytes[31] &= 127;
    x_bytes[31] |= 64;
    let x = Scalar::from_bytes_mod_order(x_bytes);

    // Step 2: derive public key point
    let pk_point = &x * ED25519_BASEPOINT_POINT;
    let pk_bytes = pk_point.compress().to_bytes();

    // Step 3: H = encode_to_curve(pk_bytes, alpha)
    let h = encode_to_curve(&pk_bytes, alpha)?;

    // Step 4: Gamma = x * H
    let gamma = &x * &h;

    // Step 5: k = nonce_generation(hashed_sk[32..64], H)
    let mut trunc = [0u8; 32];
    trunc.copy_from_slice(&hashed_sk[32..64]);
    let k = nonce_generation(&trunc, &h);

    // Step 6: U = k*B, V = k*H
    let u = &k * ED25519_BASEPOINT_POINT;
    let v = &k * &h;

    // Step 7: c = challenge_generation(pk_point, H, Gamma, U, V)
    let c_raw = challenge_generation(&pk_point, &h, &gamma, &u, &v);

    // Step 8: s = k + c * x
    let mut c_scalar_bytes = [0u8; 32];
    c_scalar_bytes[..C_LEN].copy_from_slice(&c_raw);
    let c_scalar = Scalar::from_bytes_mod_order(c_scalar_bytes);
    let s = k + c_scalar * x;

    // Step 9: serialize proof: Gamma(32) || c(16) || s(32)
    let mut pi = [0u8; PROOF_LEN];
    pi[..PT_LEN].copy_from_slice(gamma.compress().as_bytes());
    pi[PT_LEN..PT_LEN + C_LEN].copy_from_slice(&c_raw);
    pi[PT_LEN + C_LEN..].copy_from_slice(s.as_bytes());

    Ok(pi)
}

/// RFC 9381 §5.4.2.1 — ECVRF_nonce_generation_RFC8032
///
/// `truncated_hashed_sk` = second half of SHA-512(SK) (bytes 32..64)
fn nonce_generation(truncated_hashed_sk: &[u8; 32], h: &EdwardsPoint) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(truncated_hashed_sk);
    hasher.update(h.compress().as_bytes());
    let k_string = hasher.finalize();

    let mut k_bytes = [0u8; 64];
    k_bytes.copy_from_slice(&k_string);
    Scalar::from_bytes_mod_order_wide(&k_bytes)
}

/// VRF_verify(PK, alpha, pi) — RFC 9381 §5.3
///
/// - `pk`    : 32-byte compressed ed25519 public key (oracle's)
/// - `alpha` : the seed/message that was signed
/// - `pi`    : 80-byte proof from the oracle
///
/// Returns the 64-byte VRF output (beta) on success.
pub fn ecvrf_verify(
    pk: &[u8; PT_LEN],
    alpha: &[u8],
    pi: &[u8; PROOF_LEN],
) -> Result<[u8; BETA_LEN], VrfError> {
    // Steps 1-2: decode public key Y
    let y = CompressedEdwardsY(*pk)
        .decompress()
        .ok_or(VrfError::BadPublicKey)?;

    // Step 3: key validation — reject small-order points (8*Y == identity)
    if y.is_small_order() {
        return Err(VrfError::SmallOrderKey);
    }

    // Steps 4-6: decode proof -> (Gamma, c_raw, c_scalar, s)
    let (gamma, c_raw, c_scalar, s) = decode_proof(pi)?;

    // Step 7: H = encode_to_curve(PK, alpha)
    let h = encode_to_curve(pk, alpha)?;

    // Step 8: U = s*B - c*Y  (vartime joint: one interleaved NAF loop, precomputed basepoint)
    // Step 9: V = s*H - c*Gamma  (Straus: joint NAF loop over two variable points)
    // Wrappers are #[inline(never)] so NafLookupTable5 stack frames don't inflate ecvrf_verify.
    let neg_c = -c_scalar;
    let u = vartime_double_base(&neg_c, &y, &s);
    let v = vartime_var(&s, &h) + vartime_var(&neg_c, &gamma);

    // Step 10: c' = challenge_generation(Y, H, Gamma, U, V)
    let c_prime = challenge_generation(&y, &h, &gamma, &u, &v);

    // Step 11: verify c == c'
    if c_raw != c_prime {
        return Err(VrfError::ChallengeMismatch);
    }

    Ok(proof_to_hash(&gamma))
}

/// `neg_c * A + s * B` — isolated so NafLookupTable5 lives in its own frame.
#[inline(never)]
fn vartime_double_base(neg_c: &Scalar, a: &EdwardsPoint, s: &Scalar) -> EdwardsPoint {
    EdwardsPoint::vartime_double_scalar_mul_basepoint(neg_c, a, s)
}

/// Single vartime scalar mult — isolated so its NafLookupTable5 lives in its own frame.
#[inline(never)]
fn vartime_var(a: &Scalar, p: &EdwardsPoint) -> EdwardsPoint {
    EdwardsPoint::vartime_multiscalar_mul([a], [p])
}

/// RFC 9381 §5.4.4
/// pi layout: Gamma(32) || c(16) || s(32) = 80 bytes
fn decode_proof(
    pi: &[u8; PROOF_LEN],
) -> Result<(EdwardsPoint, [u8; C_LEN], Scalar, Scalar), VrfError> {
    // pi is &[u8; PROOF_LEN] (80 bytes by type), so all slice ranges are in-bounds:
    //   0..PT_LEN        = 0..32   (within 80)
    //   PT_LEN..48       = 32..48  (within 80)
    //   PT_LEN+C_LEN..   = 48..80  (within 80)

    let mut gamma_bytes = [0u8; PT_LEN];
    gamma_bytes.copy_from_slice(&pi[..PT_LEN]);
    let gamma = CompressedEdwardsY(gamma_bytes)
        .decompress()
        .ok_or(VrfError::BadGammaPoint)?;

    // c: 16 little-endian bytes, padded to 32 bytes for Scalar (c < 2^128 < q, no reduction)
    let mut c_raw = [0u8; C_LEN];
    c_raw.copy_from_slice(&pi[PT_LEN..PT_LEN + C_LEN]);
    let mut c_scalar_bytes = [0u8; Q_LEN];
    c_scalar_bytes[..C_LEN].copy_from_slice(&c_raw);
    let c_scalar = Scalar::from_bytes_mod_order(c_scalar_bytes);

    // s: 32 bytes, must be canonical (< q)
    let mut s_bytes = [0u8; Q_LEN];
    s_bytes.copy_from_slice(&pi[PT_LEN + C_LEN..]);
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))
        .ok_or(VrfError::NonCanonicalScalar)?;

    Ok((gamma, c_raw, c_scalar, s))
}

/// RFC 9381 §5.4.1.1 — ECVRF_encode_to_curve_try_and_increment
///
/// Hashes `alpha` to a curve point in the prime-order subgroup.
/// `pk` is used as the domain-separation salt.
#[inline(never)]
fn encode_to_curve(pk: &[u8; PT_LEN], alpha: &[u8]) -> Result<EdwardsPoint, VrfError> {
    for ctr in 0u8..=255 {
        let mut h = Sha512::new();
        h.update([SUITE, 0x01]); // suite_string || domain_sep_front
        h.update(pk); // encode_to_curve_salt
        h.update(alpha);
        h.update([ctr, 0x00]); // counter || domain_sep_back
        let hash = h.finalize();

        // SHA-512 output is always 64 bytes; PT_LEN = 32 <= 64, so this slice is in-bounds
        let mut point_bytes = [0u8; PT_LEN];
        point_bytes.copy_from_slice(&hash[..PT_LEN]);

        if let Some(point) = CompressedEdwardsY(point_bytes).decompress() {
            // Multiply by cofactor (8) to place the point in the prime-order subgroup
            let h_point = point.mul_by_cofactor();
            if !h_point.is_identity() {
                return Ok(h_point);
            }
        }
    }
    Err(VrfError::HashToCurveFailed)
}

/// Same as `challenge_generation` but accepts pre-compressed point bytes.
/// Avoids 4 field inversions (compress) when Y, H, Gamma, U are already stored compressed.
#[inline(never)]
fn challenge_generation_bytes(
    y_bytes: &[u8; PT_LEN],
    h_bytes: &[u8; PT_LEN],
    gamma_bytes: &[u8; PT_LEN],
    u_bytes: &[u8; PT_LEN],
    v_bytes: &[u8; PT_LEN],
) -> [u8; C_LEN] {
    let mut hasher = Sha512::new();
    hasher.update([SUITE, 0x02]);
    hasher.update(y_bytes);
    hasher.update(h_bytes);
    hasher.update(gamma_bytes);
    hasher.update(u_bytes);
    hasher.update(v_bytes);
    hasher.update([0x00]);
    let hash = hasher.finalize();
    let mut result = [0u8; C_LEN];
    result.copy_from_slice(&hash[..C_LEN]);
    result
}

/// RFC 9381 §5.4.3
///
/// Returns the first cLen (16) bytes of SHA-512 over the five input points.
#[inline(never)]
fn challenge_generation(
    y: &EdwardsPoint,
    h: &EdwardsPoint,
    gamma: &EdwardsPoint,
    u: &EdwardsPoint,
    v: &EdwardsPoint,
) -> [u8; C_LEN] {
    let mut hasher = Sha512::new();
    hasher.update([SUITE, 0x02]); // suite_string || domain_sep_front
    for p in [y, h, gamma, u, v] {
        hasher.update(p.compress().as_bytes());
    }
    hasher.update([0x00]); // domain_sep_back
    let hash = hasher.finalize();

    // SHA-512 output is always 64 bytes; C_LEN = 16 <= 64, so this slice is in-bounds
    let mut result = [0u8; C_LEN];
    result.copy_from_slice(&hash[..C_LEN]);
    result
}

/// Step 1 of two-transaction VRF verification.
///
/// Computes `H = encode_to_curve(pk, alpha)` and `U = s·B − c·Y`.
/// Store the returned `(H_compressed, U_compressed)` in the request account;
/// pass them to `ecvrf_finish_verify` in a second transaction.
pub fn ecvrf_begin_verify(
    pk: &[u8; PT_LEN],
    alpha: &[u8],
    pi: &[u8; PROOF_LEN],
) -> Result<([u8; PT_LEN], [u8; PT_LEN]), VrfError> {
    let y = CompressedEdwardsY(*pk)
        .decompress()
        .ok_or(VrfError::BadPublicKey)?;
    if y.is_small_order() {
        return Err(VrfError::SmallOrderKey);
    }

    let (_, _, c_scalar, s) = decode_proof(pi)?;
    let h = encode_to_curve(pk, alpha)?;

    let neg_c = -c_scalar;
    let u = vartime_double_base(&neg_c, &y, &s);

    Ok((h.compress().to_bytes(), u.compress().to_bytes()))
}

/// Step 2 of two-transaction VRF verification.
///
/// Takes the `h_compressed` and `u_compressed` stored by `ecvrf_begin_verify`,
/// completes the challenge check, and returns beta on success.
///
/// Uses compressed-byte inputs for challenge hashing (avoids 4 field inversions).
pub fn ecvrf_finish_verify(
    pk: &[u8; PT_LEN],
    pi: &[u8; PROOF_LEN],
    h_compressed: &[u8; PT_LEN],
    u_compressed: &[u8; PT_LEN],
) -> Result<[u8; BETA_LEN], VrfError> {
    let (gamma, c_raw, c_scalar, s) = decode_proof(pi)?;

    let h = CompressedEdwardsY(*h_compressed)
        .decompress()
        .ok_or(VrfError::BadGammaPoint)?;

    let neg_c = -c_scalar;
    let v = vartime_var(&s, &h) + vartime_var(&neg_c, &gamma);

    // Extract the compressed gamma bytes directly from pi (no re-compression needed).
    let mut gamma_bytes = [0u8; PT_LEN];
    gamma_bytes.copy_from_slice(&pi[..PT_LEN]);

    let v_compressed = v.compress();
    let c_prime = challenge_generation_bytes(
        pk,
        h_compressed,
        &gamma_bytes,
        u_compressed,
        v_compressed.as_bytes(),
    );

    if c_raw != c_prime {
        return Err(VrfError::ChallengeMismatch);
    }

    Ok(proof_to_hash(&gamma))
}

/// Extracts beta from a proof without performing full verification.
///
/// Decodes Gamma from the first 32 bytes of `pi` and returns `proof_to_hash(Gamma)`.
/// Cheap alternative to `ecvrf_verify` for on-chain use where the oracle's signing
/// key already authenticates the fulfillment.
pub fn ecvrf_proof_to_hash(pi: &[u8; PROOF_LEN]) -> Result<[u8; BETA_LEN], VrfError> {
    let mut gamma_bytes = [0u8; PT_LEN];
    gamma_bytes.copy_from_slice(&pi[..PT_LEN]);
    let gamma = CompressedEdwardsY(gamma_bytes)
        .decompress()
        .ok_or(VrfError::BadGammaPoint)?;
    Ok(proof_to_hash(&gamma))
}

/// RFC 9381 §5.2
fn proof_to_hash(gamma: &EdwardsPoint) -> [u8; BETA_LEN] {
    let mut hasher = Sha512::new();
    hasher.update([SUITE, 0x03]); // suite_string || domain_sep_front
                                  // cofactor * Gamma clears the torsion component before hashing
    hasher.update(gamma.mul_by_cofactor().compress().as_bytes());
    hasher.update([0x00]); // domain_sep_back
    let hash = hasher.finalize();

    // SHA-512 output is always exactly BETA_LEN (64) bytes
    let mut result = [0u8; BETA_LEN];
    result.copy_from_slice(&hash[..]);
    result
}
