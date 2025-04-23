#![allow(non_snake_case)]

use k256::ProjectivePoint;
use shamy::schnorr::*;
use shamy::shamir::*;
use shamy::threshold::*;

#[test]
fn test_invalid_signature_wrong_message() {
    let n = 3;
    let t = 3;
    let keygen_output = shamir_keygen(n, t);

    let correct_msg = b"Correct message";
    let tampered_msg = b"Wrong message";
    let ids: Vec<u64> = keygen_output.participants.iter().map(|p| p.id).collect();

    let nonce_pairs = keygen_output
        .participants
        .iter()
        .map(|p| {
            let r_i = generate_nonce();
            let R_i = compute_nonce_point(&r_i);
            (p, r_i, R_i)
        })
        .collect::<Vec<_>>();

    let nonces = nonce_pairs
        .clone()
        .into_iter()
        .map(|(p, _, R_i)| (p.id, R_i))
        .collect::<Vec<_>>();
    let R = aggregate_nonce(&nonces.as_slice(), &ids);

    let c = compute_challenge(&R, &keygen_output.public_key, correct_msg);

    let partials = nonce_pairs
        .iter()
        .map(|(p, r_i, _)| partial_sign(p, r_i, &c))
        .collect::<Vec<_>>();

    let sig = finalize_signature_lagrange(&partials, R);
    assert!(!sig.verify(tampered_msg, &keygen_output.public_key));
}

#[test]
fn test_valid_signature_deterministic() {
    let n = 4;
    let t = 4;
    let keygen_output = shamir_keygen(n, t);

    let msg = b"Repeat verification";
    let ids: Vec<u64> = keygen_output.participants.iter().map(|p| p.id).collect();

    let nonce_pairs = keygen_output
        .participants
        .iter()
        .map(|p| {
            let r_i = generate_nonce();
            let R_i = compute_nonce_point(&r_i);
            (p, r_i, R_i)
        })
        .collect::<Vec<_>>();

    let R = nonce_pairs
        .iter()
        .fold(ProjectivePoint::IDENTITY, |acc, (p, _, R_i)| {
            let lambda = lagrange_coefficient(p.id, &ids);
            acc + (*R_i * lambda)
        });

    let c = compute_challenge(&R, &keygen_output.public_key, msg);

    let partials = nonce_pairs
        .iter()
        .map(|(p, r_i, _)| partial_sign(p, r_i, &c))
        .collect::<Vec<_>>();

    let sig = finalize_signature_lagrange(&partials, R);

    for _ in 0..50 {
        assert!(sig.verify(msg, &keygen_output.public_key));
    }
}
