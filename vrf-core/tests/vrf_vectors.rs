/// RFC 9381 Appendix B.3 — ECVRF-EDWARDS25519-SHA512-TAI (suite 0x03)
///
/// Three official test vectors (examples 16, 17, 18) plus negative cases
/// covering each distinct error path in ecvrf_verify.
use curve25519_dalek::edwards::CompressedEdwardsY;
use vrf_core::{ecvrf_prove, ecvrf_verify, VrfError, PROOF_LEN};

// Scans y-coordinates until it finds one where decompression fails
// (x² is a quadratic non-residue mod p). ~50% of y values have this
// property, so we expect to succeed within a handful of iterations.
fn invalid_point_bytes() -> [u8; 32] {
    for b in 0u8..=255 {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        if CompressedEdwardsY(bytes).decompress().is_none() {
            return bytes;
        }
    }
    // Vary a mid-range byte to get larger y values and retry
    for b in 0u8..=255 {
        let mut bytes = [0u8; 32];
        bytes[16] = b;
        if CompressedEdwardsY(bytes).decompress().is_none() {
            return bytes;
        }
    }
    panic!("failed to find an invalid compressed point in 512 attempts");
}

// ── helpers ────────────────────────────────────────────────────────────────

fn from_hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex digit"))
        .collect()
}

fn pk(hex: &str) -> [u8; 32] {
    from_hex(hex).try_into().expect("PK must be 32 bytes")
}

fn pi(hex: &str) -> [u8; PROOF_LEN] {
    from_hex(hex).try_into().expect("pi must be 80 bytes")
}

fn beta(hex: &str) -> [u8; 64] {
    from_hex(hex).try_into().expect("beta must be 64 bytes")
}

// ── RFC 9381 §B.3 positive test vectors ───────────────────────────────────

/// Example 16: empty alpha
#[test]
fn rfc9381_example_16() {
    let result = ecvrf_verify(
        &pk("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
        b"",
        &pi(
            "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f\
             26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab12\
             68a1b0db10836d9826a528ca76567805",
        ),
    );

    assert_eq!(
        result.unwrap(),
        beta(
            "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff\
             66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae"
        )
    );
}

/// Example 17: alpha = 0x72 (1 byte)
#[test]
fn rfc9381_example_17() {
    let result = ecvrf_verify(
        &pk("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
        &from_hex("72"),
        &pi(
            "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed593\
             3bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926d\
             a3ef39226bbc355bdc9850112c8f4b02",
        ),
    );

    assert_eq!(
        result.unwrap(),
        beta(
            "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb\
             5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031"
        )
    );
}

/// Example 18: alpha = 0xaf82 (2 bytes)
#[test]
fn rfc9381_example_18() {
    let result = ecvrf_verify(
        &pk("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
        &from_hex("af82"),
        &pi(
            "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf80\
             96bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a\
             2d41b00b05081ed0f58ee5e31b3a970e",
        ),
    );

    assert_eq!(
        result.unwrap(),
        beta(
            "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c45\
             2118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f"
        )
    );
}

// ── Negative tests — one per error variant ────────────────────────────────

/// BadPublicKey: PK bytes do not decompress to a valid curve point.
/// (the y-coordinate has no corresponding x on the curve — x² is a QNR mod p)
#[test]
fn rejects_bad_public_key() {
    let bad_pk = invalid_point_bytes();
    let result = ecvrf_verify(&bad_pk, b"anything", &[0u8; PROOF_LEN]);
    assert_eq!(result, Err(VrfError::BadPublicKey));
}

/// SmallOrderKey: the low-order point of order 4 encodes to a known byte sequence.
/// 8 * (small-order point) == identity, so it must be rejected.
#[test]
fn rejects_small_order_key() {
    // Compressed encoding of the order-4 torsion point (0, -1) on Edwards25519.
    // This is a valid compressed point that decompresses successfully but is small-order.
    let low_order_pk = pk("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    let result = ecvrf_verify(&low_order_pk, b"anything", &[0u8; PROOF_LEN]);
    assert_eq!(result, Err(VrfError::SmallOrderKey));
}

/// BadGammaPoint: Gamma bytes in pi (0..32) don't decompress to a valid curve point.
#[test]
fn rejects_bad_gamma_point() {
    let valid_pk = pk("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let mut bad_pi = [0u8; PROOF_LEN];
    // Put an invalid point encoding in the Gamma slot (bytes 0..32)
    bad_pi[..32].copy_from_slice(&invalid_point_bytes());
    let result = ecvrf_verify(&valid_pk, b"", &bad_pi);
    assert_eq!(result, Err(VrfError::BadGammaPoint));
}

/// NonCanonicalScalar: s bytes (48..80) set to 0xff which is > field order q
#[test]
fn rejects_non_canonical_scalar() {
    let valid_pk = pk("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let mut bad_pi = pi(
        "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f\
         26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab12\
         68a1b0db10836d9826a528ca76567805",
    );
    // s occupies bytes 48..80; 0xfff...f > q, so Scalar::from_canonical_bytes returns None
    bad_pi[48..].fill(0xff);
    let result = ecvrf_verify(&valid_pk, b"", &bad_pi);
    assert_eq!(result, Err(VrfError::NonCanonicalScalar));
}

/// ChallengeMismatch: valid proof from example 16 but wrong alpha supplied
#[test]
fn rejects_wrong_alpha() {
    let result = ecvrf_verify(
        &pk("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
        b"not the original alpha",
        &pi(
            "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f\
             26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab12\
             68a1b0db10836d9826a528ca76567805",
        ),
    );
    assert_eq!(result, Err(VrfError::ChallengeMismatch));
}

// ── RFC 9381 §B.3 prove vectors (prove → compare pi, then verify → compare beta) ──

fn sk(hex: &str) -> [u8; 32] {
    from_hex(hex).try_into().expect("SK must be 32 bytes")
}

/// Example 16: empty alpha — prove produces the RFC pi, verify produces the RFC beta
#[test]
fn prove_example_16() {
    let sk_bytes = sk("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let expected_pi = pi(
        "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f\
         26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab12\
         68a1b0db10836d9826a528ca76567805",
    );
    let computed_pi = ecvrf_prove(&sk_bytes, b"").unwrap();
    assert_eq!(computed_pi, expected_pi);

    let result = ecvrf_verify(
        &pk("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
        b"",
        &computed_pi,
    );
    assert_eq!(
        result.unwrap(),
        beta(
            "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff\
             66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae"
        )
    );
}

/// Example 17: alpha = 0x72 (1 byte)
#[test]
fn prove_example_17() {
    let sk_bytes = sk("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let alpha = from_hex("72");
    let expected_pi = pi(
        "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed593\
         3bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926d\
         a3ef39226bbc355bdc9850112c8f4b02",
    );
    let computed_pi = ecvrf_prove(&sk_bytes, &alpha).unwrap();
    assert_eq!(computed_pi, expected_pi);

    let result = ecvrf_verify(
        &pk("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
        &alpha,
        &computed_pi,
    );
    assert_eq!(
        result.unwrap(),
        beta(
            "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb\
             5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031"
        )
    );
}

/// Example 18: alpha = 0xaf82 (2 bytes)
#[test]
fn prove_example_18() {
    let sk_bytes = sk("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
    let alpha = from_hex("af82");
    let expected_pi = pi(
        "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf80\
         96bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a\
         2d41b00b05081ed0f58ee5e31b3a970e",
    );
    let computed_pi = ecvrf_prove(&sk_bytes, &alpha).unwrap();
    assert_eq!(computed_pi, expected_pi);

    let result = ecvrf_verify(
        &pk("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
        &alpha,
        &computed_pi,
    );
    assert_eq!(
        result.unwrap(),
        beta(
            "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c45\
             2118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f"
        )
    );
}

// HashToCurveFailed is astronomically unlikely to trigger with real inputs.
// It would require crafting an alpha where all 256 counter values produce
// invalid points — computationally infeasible, so no test case is provided.
