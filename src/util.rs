use hex::{self, FromHex};
use k256::{
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
    elliptic_curve::{PrimeField, sec1::FromEncodedPoint},
};

pub fn pp_to_hex(point: &ProjectivePoint) -> String {
    let affine = point.to_affine();
    let encoded: EncodedPoint = EncodedPoint::from(affine);
    let pt_bytes = encoded.as_bytes();
    let pt_hex = hex::encode(pt_bytes);

    pt_hex
}

pub fn hex_to_pp(hex: &str) -> Result<ProjectivePoint, String> {
    let raw = Vec::from_hex(hex).map_err(|e| format!("Invalid hex string: {}", e))?;
    let encoded =
        EncodedPoint::from_bytes(&raw).map_err(|e| format!("Invalid encoded point: {}", e))?;
    let affine = AffinePoint::from_encoded_point(&encoded)
        .into_option()
        .ok_or("Invalid affine point".to_string())?;

    Ok(ProjectivePoint::from(affine))
}

pub fn scalar_to_hex(scalar: &Scalar) -> String {
    let bytes = scalar.to_bytes();
    let hex_str = hex::encode(bytes);

    hex_str
}

pub fn hex_to_scalar(hex: &str) -> Result<Scalar, String> {
    let raw = Vec::from_hex(hex).map_err(|e| format!("Invalid hex string: {}", e))?;
    if raw.len() != 32 {
        return Err("Invalid scalar length".to_string());
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&raw);

    Scalar::from_repr(buf.into())
        .into_option()
        .ok_or("Invalid scalar".to_string())
}

#[cfg(test)]
mod tests {
    use crate::schnorr::{compute_nonce_point, generate_nonce};

    use super::*;

    #[test]
    fn test_pp_valid_roundtrip() {
        let nonce = generate_nonce();
        let nonce_point = compute_nonce_point(&nonce);
        let hex = pp_to_hex(&nonce_point);
        let decoded = hex_to_pp(&hex).unwrap();
        assert_eq!(nonce_point, decoded);
    }

    #[test]
    fn test_hex_to_pp_invalid() {
        let hex = "invalid";
        let decoded = hex_to_pp(hex);
        assert!(decoded.is_err());
    }

    #[test]
    fn test_scalar_valid_roundtrip() {
        let nonce = generate_nonce();
        let hex = scalar_to_hex(&nonce);
        let decoded = hex_to_scalar(&hex).unwrap();
        assert_eq!(nonce, decoded);
    }

    #[test]
    fn test_scalar_invalid_roundtrip() {
        let hex = "invalid";
        let decoded = hex_to_scalar(hex);
        assert!(decoded.is_err());
    }

    #[test]
    fn test_scalar_invalid_length() {
        let hex = "042069";
        let decoded = hex_to_scalar(hex);
        assert!(decoded.is_err());
    }
}
