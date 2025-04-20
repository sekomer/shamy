#![allow(non_snake_case)]

use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{Field, PrimeField, sec1::ToEncodedPoint},
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
pub struct SchnorrSignature {
    pub R: ProjectivePoint, // r*G
    pub s: Scalar,          // r + c*x
}

impl SchnorrSignature {
    /// verify the Schnorr signature against the public key X.
    pub fn verify(&self, msg: &[u8], X: &ProjectivePoint) -> bool {
        let c = compute_challenge(&self.R, X, msg);
        let lhs = ProjectivePoint::GENERATOR * self.s;
        let rhs = self.R + (X * &c);

        lhs == rhs
    }
}

/// generate a random nonce for signing.
pub fn generate_nonce() -> Scalar {
    Scalar::random(&mut OsRng)
}

/// compute the nonce point R = r*G from a nonce scalar r.
pub fn compute_nonce_point(r: &Scalar) -> ProjectivePoint {
    ProjectivePoint::GENERATOR * r
}

/// compute the challenge c = H(R, X, m) where:
/// - R is the nonce point
/// - X is the public key
/// - m is the message
/// - H is SHA-256
pub fn compute_challenge(R: &ProjectivePoint, X: &ProjectivePoint, msg: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    let R_enc = R.to_encoded_point(false);
    let X_enc = X.to_encoded_point(false);
    hasher.update(R_enc.as_bytes());
    hasher.update(X_enc.as_bytes());
    hasher.update(msg);
    let hash_result = hasher.finalize();
    let field_bytes: <Scalar as PrimeField>::Repr = hash_result.into();

    Scalar::from_repr(field_bytes).unwrap()
}
