#![allow(non_snake_case)]

use k256::{ProjectivePoint, Scalar};
use rand::{rng, seq::IteratorRandom};
use shamy::schnorr::*;
use shamy::shamir::*;
use shamy::threshold::*;

#[test]
fn test_threshold_schnorr_3_5() {
    let mut rng = rng();
    let n = 5;
    let t = 3;
    let keygen_output = shamir_keygen(n, t);

    let msg = b"Hello threshold schnorr!";

    let chosen_participants: Vec<Participant> = keygen_output
        .participants
        .iter()
        .choose_multiple(&mut rng, t)
        .into_iter()
        .map(|p| *p)
        .collect();

    let ids: Vec<u64> = chosen_participants.iter().map(|p| p.id).collect();

    let mut nonce_pairs = Vec::new(); // (Participant, r_i, R_i)
    for p in &chosen_participants {
        let r_i = generate_nonce();
        let R_i = compute_nonce_point(&r_i);
        nonce_pairs.push((p, r_i, R_i));
    }

    let nonces = nonce_pairs
        .clone()
        .into_iter()
        .map(|(p, _, R_i)| (p.id, R_i))
        .collect::<Vec<_>>();
    let R = aggregate_nonce(&nonces.as_slice(), &ids);

    let c = compute_challenge(&R, &keygen_output.public_key, msg);

    let partials = nonce_pairs
        .iter()
        .map(|(p, r_i, _)| partial_sign(p, *r_i, c))
        .collect::<Vec<_>>();

    let signature = finalize_signature_lagrange(&partials, R);
    assert!(signature.verify(msg, &keygen_output.public_key));
}

#[test]
fn test_threshold_schnorr_5_5_valid() {
    let n = 5;
    let t = 5;
    let keygen_output = shamir_keygen(n, t);

    let msg = b"Full participation test";
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

    let c = compute_challenge(&R, &keygen_output.public_key, msg);

    let partials = nonce_pairs
        .iter()
        .map(|(p, r_i, _)| partial_sign(p, *r_i, c))
        .collect::<Vec<_>>();

    let sig = finalize_signature_lagrange(&partials, R);
    assert!(sig.verify(msg, &keygen_output.public_key));
}

#[test]
fn test_invalid_signature_wrong_participants() {
    let n = 5;
    let t = 5;
    let keygen_output = shamir_keygen(n, t);

    let msg = b"Wrong participant set";

    // threshold is 5 but only 3 participants are signing
    let signers = &keygen_output.participants[0..3];

    let signer_ids: Vec<u64> = signers.iter().map(|p| p.id).collect();

    let nonce_pairs = signers
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
    let R = aggregate_nonce(&nonces.as_slice(), &signer_ids);

    let c = compute_challenge(&R, &keygen_output.public_key, msg);

    let partials = nonce_pairs
        .iter()
        .map(|(p, r_i, _)| partial_sign(p, *r_i, c))
        .collect::<Vec<_>>();

    let sig = finalize_signature_lagrange(&partials, R);
    assert!(!sig.verify(msg, &keygen_output.public_key));
}

#[test]
fn test_threshold_signature_equals_manual_combined_signature() {
    let n = 5;
    let t = 3;
    let keygen_output = shamir_keygen(n, t);

    let mut rng = rng();
    let chosen: Vec<Participant> = keygen_output
        .participants
        .iter()
        .choose_multiple(&mut rng, t)
        .into_iter()
        .copied()
        .collect();

    let ids: Vec<u64> = chosen.iter().map(|p| p.id).collect();
    let msg = b"same signature from reconstructed key";

    let nonce_pairs: Vec<(Participant, Scalar, ProjectivePoint)> = chosen
        .iter()
        .map(|p| {
            let r_i = generate_nonce();
            let R_i = compute_nonce_point(&r_i);
            (*p, r_i, R_i)
        })
        .collect();

    let R = nonce_pairs
        .iter()
        .fold(ProjectivePoint::IDENTITY, |acc, (p, _, R_i)| {
            let lambda = lagrange_coefficient(p.id, &ids);
            acc + (*R_i * lambda)
        });

    // aggregate the secret key from the chosen participants for manual verification
    let combined_x = chosen.iter().fold(Scalar::ZERO, |acc, p| {
        let lambda = lagrange_coefficient(p.id, &ids);
        acc + (lambda * p.x_i)
    });
    let X = ProjectivePoint::GENERATOR * combined_x;

    // reconstruct nonce: r = Σ λᵢ·rᵢ
    let combined_r = nonce_pairs.iter().fold(Scalar::ZERO, |acc, (p, r_i, _)| {
        let lambda = lagrange_coefficient(p.id, &ids);
        acc + (lambda * r_i)
    });
    let c = compute_challenge(&R, &X, msg);

    // manual signature
    let s_manual = combined_r + c * combined_x;
    let manual_signature = SchnorrSignature { R, s: s_manual };

    // threshold signature from partials
    let partials: Vec<PartialSignature> = nonce_pairs
        .iter()
        .map(|(p, r_i, _)| partial_sign(p, *r_i, c))
        .collect();

    let threshold_signature = finalize_signature_lagrange(&partials, R);

    assert_eq!(manual_signature.R, threshold_signature.R);
    assert_eq!(manual_signature.s, threshold_signature.s);
}

#[test]
fn test_compare_signatures_of_different_subsets() {
    let n = 5;
    let t = 3;
    let keygen_output = shamir_keygen(n, t);

    let msg = b"Hello threshold schnorr!";

    let chosen_participants: Vec<Participant> =
        keygen_output.participants.iter().take(t).copied().collect();

    let ids: Vec<u64> = chosen_participants.iter().map(|p| p.id).collect();

    let mut nonce_pairs = Vec::new();
    for p in &chosen_participants {
        let r_i = generate_nonce();
        let R_i = compute_nonce_point(&r_i);
        nonce_pairs.push((p, r_i, R_i));
    }

    let nonces = nonce_pairs
        .clone()
        .into_iter()
        .map(|(p, _, R_i)| (p.id, R_i))
        .collect::<Vec<_>>();
    let R = aggregate_nonce(&nonces.as_slice(), &ids);

    let c = compute_challenge(&R, &keygen_output.public_key, msg);

    let partials = nonce_pairs
        .iter()
        .map(|(p, r_i, _)| partial_sign(p, *r_i, c))
        .collect::<Vec<_>>();

    let signature = finalize_signature_lagrange(&partials, R);
    assert!(signature.verify(msg, &keygen_output.public_key));

    // ---------------------------

    let rev_chosen_participants: Vec<Participant> = keygen_output
        .participants
        .iter()
        .rev()
        .take(t)
        .copied()
        .collect();

    let ids: Vec<u64> = rev_chosen_participants.iter().map(|p| p.id).collect();

    let public_keys = rev_chosen_participants
        .iter()
        .map(|p| (p.id, p.X_i))
        .collect::<Vec<_>>();
    let rev_public_key = aggregate_public_key(&public_keys);

    assert_eq!(keygen_output.public_key, rev_public_key);

    let mut nonce_pairs = Vec::new();
    for p in &rev_chosen_participants {
        let r_i = generate_nonce();
        let R_i = compute_nonce_point(&r_i);
        nonce_pairs.push((p, r_i, R_i));
    }

    let nonces = nonce_pairs
        .clone()
        .into_iter()
        .map(|(p, _, R_i)| (p.id, R_i))
        .collect::<Vec<_>>();
    let R = aggregate_nonce(&nonces.as_slice(), &ids);

    let c = compute_challenge(&R, &rev_public_key, msg);

    let partials = nonce_pairs
        .iter()
        .map(|(p, r_i, _)| partial_sign(p, *r_i, c))
        .collect::<Vec<_>>();

    let rev_signature = finalize_signature_lagrange(&partials, R);

    println!("signature: {:?}", signature);
    println!("rev_signature: {:?}", rev_signature);
    assert_ne!(signature.R, rev_signature.R);
    assert_ne!(signature.s, rev_signature.s);
}
