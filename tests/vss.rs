use k256::{
    Scalar,
    elliptic_curve::{Field, rand_core::OsRng},
};
use rand::{Rng, rng};
use shamy::vss::calculate_commitment;
use shamy::{shamir::*, vss::verify_commitment};

#[test]
fn test_verify_commitment_valid() {
    let n = 5;
    let t = 3;

    let secret = Scalar::random(&mut OsRng);
    let coefs = random_polynomial(secret, t);
    let commitments = coefs
        .iter()
        .map(|c| calculate_commitment(*c))
        .collect::<Vec<_>>();

    let mut rng = rng();

    let p_id = rng.random_range(1..=n);
    let x_i = eval_polynomial(&coefs, p_id);

    let is_valid = verify_commitment(p_id, x_i, &commitments);

    assert!(is_valid);
}

#[test]
fn test_verify_commitment_invalid_coefs() {
    let n = 5;
    let t = 3;

    let secret = Scalar::random(&mut OsRng);
    let original_coefs = random_polynomial(secret, t);

    let mut rng = rng();

    let p_id = rng.random_range(1..=n);
    let x_i = eval_polynomial(&original_coefs, p_id);

    let wrong_coefs = random_polynomial(secret, t);
    let wrong_commitments = wrong_coefs
        .iter()
        .map(|c| calculate_commitment(*c))
        .collect::<Vec<_>>();

    let is_valid = verify_commitment(p_id, x_i, &wrong_commitments);

    assert!(!is_valid);
}

#[test]
fn test_verify_commitment_invalid_id() {
    let n = 5;
    let t = 3;

    let secret = Scalar::random(&mut OsRng);
    let coefs = random_polynomial(secret, t);
    let commitments = coefs
        .iter()
        .map(|c| calculate_commitment(*c))
        .collect::<Vec<_>>();

    let mut rng = rng();

    let p_id = rng.random_range(1..=n);
    let x_i = eval_polynomial(&coefs, p_id);

    let wrong_id = p_id + 1;

    let is_valid = verify_commitment(wrong_id, x_i, &commitments);
    assert!(!is_valid);
}
