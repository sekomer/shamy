#![allow(non_snake_case)]

use crate::threshold::*;
use crate::vss::calculate_commitment;
use k256::{ProjectivePoint, Scalar, elliptic_curve::Field};
use rand_core::OsRng;

pub struct KeygenOutput {
    pub participants: Vec<Participant>,
    pub public_key: ProjectivePoint,
    pub commitments: Vec<ProjectivePoint>,
}

/// generate a random polynomial of degree t-1.
/// a_0 = secret, a_1, ..., a_{t-1} = random scalars
pub fn random_polynomial(secret: Scalar, t: usize) -> Vec<Scalar> {
    let mut coeffs = vec![secret];
    for _ in 1..t {
        coeffs.push(Scalar::random(&mut OsRng));
    }

    coeffs
}

/// evaluate the polynomial at x = id.
pub fn eval_polynomial(coeffs: &[Scalar], id: u64) -> Scalar {
    let mut acc = Scalar::ZERO;
    let x = Scalar::from(id);
    for &c in coeffs.iter().rev() {
        // horners rule
        acc = acc * x + c;
    }

    acc
}

/// Create n Shamir shares for threshold t.
/// Returns (participants, public_key, commitments).
pub fn shamir_keygen(n: usize, t: usize) -> KeygenOutput {
    assert!(t >= 2 && t <= n);
    let secret = Scalar::random(&mut OsRng);
    let poly = random_polynomial(secret, t);

    let public_key = ProjectivePoint::GENERATOR * secret;

    let commitments = poly
        .iter()
        .map(|c| calculate_commitment(*c))
        .collect::<Vec<_>>();

    let participants: Vec<Participant> = (1..=n as u64)
        .map(|id| {
            let x_i = eval_polynomial(&poly, id);
            let X_i = ProjectivePoint::GENERATOR * x_i;
            Participant { id, x_i, X_i }
        })
        .collect();

    KeygenOutput {
        participants,
        public_key,
        commitments,
    }
}
