//! Standalone proof fixture for the removed sect283k1/ECDH-B283 surface.
//!
//! This deliberately models the relevant control flow from tagged v2 source
//! commit `70da3cd` without restoring that code to any published crate. The
//! two-element subgroup arithmetic is exact: T = (0, 1), T + T = O.

const ENCODED_POINT_LEN: usize = 37;
const FIELD_LEN: usize = 36;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LegacyPoint {
    Identity,
    OrderTwo { x: u8, y: u8 },
}

#[derive(Debug, Eq, PartialEq)]
enum LegacyError {
    Encoding,
    SharedIdentity,
}

fn legacy_deserialize_compressed(bytes: &[u8]) -> Result<LegacyPoint, LegacyError> {
    if bytes.len() != ENCODED_POINT_LEN {
        return Err(LegacyError::Encoding);
    }
    if bytes.iter().all(|&byte| byte == 0) {
        return Ok(LegacyPoint::Identity);
    }
    if bytes[0] != 0x02 && bytes[0] != 0x03 {
        return Err(LegacyError::Encoding);
    }
    if bytes[1..].iter().all(|&byte| byte == 0) {
        // The removed parser returned (0, sqrt(1)) without subgroup checking
        // and ignored the prefix parity in this special case.
        return Ok(LegacyPoint::OrderTwo { x: 0, y: 1 });
    }
    Err(LegacyError::Encoding)
}

fn order_two_scalar_mul(scalar: &[u8], point: LegacyPoint) -> LegacyPoint {
    match point {
        LegacyPoint::Identity => LegacyPoint::Identity,
        point if scalar.last().copied().unwrap_or(0) & 1 == 1 => point,
        _ => LegacyPoint::Identity,
    }
}

fn legacy_decapsulate_x(
    scalar: &[u8],
    ciphertext: &[u8],
) -> Result<[u8; FIELD_LEN], LegacyError> {
    let point = legacy_deserialize_compressed(ciphertext)?;
    if point == LegacyPoint::Identity {
        return Err(LegacyError::SharedIdentity);
    }
    let shared = order_two_scalar_mul(scalar, point);
    if shared == LegacyPoint::Identity {
        return Err(LegacyError::SharedIdentity);
    }
    Ok([0; FIELD_LEN])
}

fn gf2_invert(value: u8) -> Option<u8> {
    (value != 0).then_some(1)
}

fn legacy_serialize_compressed(point: LegacyPoint) -> [u8; ENCODED_POINT_LEN] {
    let mut output = [0u8; ENCODED_POINT_LEN];
    if point == LegacyPoint::Identity {
        return output;
    }
    let LegacyPoint::OrderTwo { x, y } = point else {
        unreachable!()
    };
    // This is the removed serializer's `self.x.invert().unwrap()` path.
    let y_tilde = gf2_invert(x).unwrap() * y;
    output[0] = if y_tilde == 1 { 0x03 } else { 0x02 };
    output
}

#[test]
fn order_two_ciphertext_exposes_parity_and_known_shared_x() {
    let point = LegacyPoint::OrderTwo { x: 0, y: 1 };

    // In GF(2), y^2 + xy = x^3 + 1 for (0, 1).
    let LegacyPoint::OrderTwo { x, y } = point else {
        unreachable!()
    };
    assert_eq!((y * y) ^ (x * y), (x * x * x) ^ 1);

    // -(x, y) = (x, x + y), so T = -T and T has order two.
    assert_eq!(LegacyPoint::OrderTwo { x, y: x ^ y }, point);
    assert_eq!(order_two_scalar_mul(&[2], point), LegacyPoint::Identity);
    assert_eq!(order_two_scalar_mul(&[1], point), point);

    for prefix in [0x02, 0x03] {
        let mut ciphertext = [0u8; ENCODED_POINT_LEN];
        ciphertext[0] = prefix;
        assert_eq!(legacy_deserialize_compressed(&ciphertext), Ok(point));
        assert_eq!(legacy_decapsulate_x(&[1], &ciphertext), Ok([0; FIELD_LEN]));
        assert_eq!(
            legacy_decapsulate_x(&[2], &ciphertext),
            Err(LegacyError::SharedIdentity)
        );
    }
}

#[test]
fn x_zero_point_serializer_panics_in_removed_control_flow() {
    let point = LegacyPoint::OrderTwo { x: 0, y: 1 };
    assert!(std::panic::catch_unwind(|| legacy_serialize_compressed(point)).is_err());
}

#[test]
fn removed_scalar_order_did_not_match_sec2() {
    const SEC2_ORDER: &str =
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61";
    const REMOVED_ORDER: &str =
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE96E404282DD3232283E5";
    assert_eq!(SEC2_ORDER.len(), 72);
    assert_eq!(REMOVED_ORDER.len(), 72);
    assert_ne!(SEC2_ORDER, REMOVED_ORDER);
}
