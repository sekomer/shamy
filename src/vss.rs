#![allow(non_snake_case)]

use k256::{ProjectivePoint, Scalar};

/// calculates the commitment for a given coefficient
pub fn calculate_commitment(c: Scalar) -> ProjectivePoint {
    ProjectivePoint::GENERATOR * c
}

/// verifies a participant's share against a set of commitments using Feldman's VSS scheme
pub fn verify_share(id: u64, x_i: Scalar, commitments: &[ProjectivePoint]) -> bool {
    /*
     * verification:
     *
     * polynomial f(i) is defined as:
     *         f(i) = a₀ + a₁i + ... + aₜiᵗ
     *     G * f(i) = C₀ + C₁i + ... + Cₜiᵗ
     *
     * where:
     *     xᵢ = f(i)      [share]
     *     Cⱼ = aⱼG       [commitment]
     *
     * multiplying both sides by generator G:
     *     xᵢG = f(i)G    [verification equation]
     */

    let lhs = ProjectivePoint::GENERATOR * x_i;

    let id_scalar = Scalar::from(id);
    let mut id_pow = Scalar::ONE;

    let mut rhs = ProjectivePoint::IDENTITY;
    for &C_j in commitments.iter() {
        rhs += C_j * id_pow;
        id_pow = id_pow * id_scalar;
    }

    lhs == rhs
}
