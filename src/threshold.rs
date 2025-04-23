#![allow(non_snake_case)]

use crate::schnorr::*;
use k256::{ProjectivePoint, Scalar};

/// Participant in the threshold Schnorr signature scheme.
/// Each participant has:
/// - A unique ID (used for Shamir's secret sharing)
/// - A long-term secret key (x_i)
/// - A public key share (X_i = x_i*G)
#[derive(Debug, Clone, Copy)]
pub struct Participant {
    pub id: u64,
    pub x_i: Scalar,
    pub X_i: ProjectivePoint,
}

impl Participant {
    pub fn from_secret(id: u64, x_i: Scalar) -> Self {
        let X_i = ProjectivePoint::GENERATOR * x_i;
        Self { id, x_i, X_i }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PartialSignature {
    pub id: u64,
    pub s_i: Scalar,
}

/// aggregate the public key from a set of participants.
/// X = Σ λᵢ·Xᵢ where λᵢ is the Lagrange coefficient
pub fn aggregate_public_key(public_keys: &[(u64, ProjectivePoint)]) -> ProjectivePoint {
    let ids: Vec<u64> = public_keys.iter().map(|(id, _)| *id).collect();
    public_keys
        .iter()
        .fold(ProjectivePoint::IDENTITY, |acc, (id, X_i)| {
            let lambda = lagrange_coefficient(*id, &ids);
            acc + (*X_i * lambda)
        })
}

pub fn aggregate_nonce(nonces: &[(u64, ProjectivePoint)], ids: &[u64]) -> ProjectivePoint {
    nonces
        .iter()
        .fold(ProjectivePoint::IDENTITY, |acc, (id, R_i)| {
            let lambda = lagrange_coefficient(*id, &ids);
            acc + (*R_i * lambda)
        })
}

/// compute the Lagrange coefficient λᵢ for participant i in the set of participants.
/// λᵢ = Π (j / (j - i)) for all j ≠ i
/// where j and i are participant IDs.
/// https://en.wikipedia.org/wiki/Polynomial_interpolation
pub fn lagrange_coefficient(id_i: u64, ids: &[u64]) -> Scalar {
    let id_i_scalar = Scalar::from(id_i);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;

    for &id_j in ids {
        if id_j == id_i {
            continue;
        }
        let id_j_scalar = Scalar::from(id_j);
        num *= id_j_scalar;
        den *= id_j_scalar - id_i_scalar;
    }

    num * den.invert().unwrap()
}

/// compute a partial signature s_i = r_i + c·x_i where:
/// - r_i is the participant's nonce
/// - c is the challenge
/// - x_i is the participant's secret key
pub fn partial_sign(participant: &Participant, r_i: &Scalar, c: &Scalar) -> PartialSignature {
    PartialSignature {
        id: participant.id,
        s_i: r_i + (participant.x_i * c),
    }
}

/// combine partial signatures using Lagrange interpolation to produce the final signature.
/// s = Σ λᵢ·sᵢ
/// where:
/// - λᵢ is the Lagrange coefficient for participant i
/// - sᵢ is the partial signature from participant i
pub fn finalize_signature_lagrange(
    partials: &[PartialSignature],
    R: ProjectivePoint,
) -> SchnorrSignature {
    let ids: Vec<u64> = partials.iter().map(|p| p.id).collect();
    let mut s = Scalar::ZERO;

    for p in partials {
        let lambda = lagrange_coefficient(p.id, &ids);
        s += lambda * p.s_i;
    }

    SchnorrSignature { R, s }
}
