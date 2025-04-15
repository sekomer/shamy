#![allow(non_snake_case)]

use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{Field, PrimeField, sec1::ToEncodedPoint},
};

use rand_core::OsRng;
use sha2::{Digest, Sha256};

/*
Schnorr Signature Scheme
────────────────────────

digital signature scheme based on the discrete log problem.

G = generator point

[KEYGEN]
- secret key: x (random scalar)
- public key: X = x*G

[SIGN]
1. generate random nonce r                =>
2. compute R = r*G                        => (nonce point)
3. compute challenge c = H(R || X || msg) => (hash of nonce point, public key and message)
4. compute s = r + c*x                    => signature: (R, s)

[VERIFY]
- check if: s*G = R + c*X

ASCII Flow:
┌──────────┐     ┌─────────┐     ┌──────────┐
│  Nonce   │     │ Message │     │  PubKey  │
│    r     │     │   msg   │     │    X     │
└────┬─────┘     └───┬─────┘     └────┬─────┘
     │               │                │
     │   R = r*G     │                │
     └─────┐         │                │
           ▼         │                │
      ┌────────┐     │                │
      │   R    │     │                │
      └───┬────┘     │                │
          │          │                │
          └──────────┼────────────────┘
                     │
                     ▼
             ┌──────────────┐
             │ c = H(R,X,m) │
             └──────┬───────┘
                    │
              s = r + c*x
                    │
                    ▼
             ┌──────────────┐
             │  Signature   │
             │    (R,s)     │
             └──────────────┘

────────────────────────
[MATH]
- thx to discrete log problem in elliptic curves,
- its hard to compute x given X = x*G
- verification works because:
   ┌───────────────────┐
   │ s*G = (r + c*x)*G │
   │     = r*G + c*x*G │
   │     = R + c*X     │
   └───────────────────┘
- which means we can calculate (R + c*X) and check if it equals s*G
- therefore verify the signature 🦀

In threshold setting:
- secret x is split among n parties
- each party has share x_i and corresponding public share X_i = x_i*G
- signature is created by combining partial signatures using Lagrange interpolation
- https://en.wikipedia.org/wiki/Lagrange_polynomial
*/

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

#[derive(Debug, Clone, Copy)]
pub struct PartialSignature {
    pub id: u64,
    pub s_i: Scalar,
}

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

// --------------------------------------------------------
//               THRESHOLD KEY GENERATION
// --------------------------------------------------------

/// generate a new participant with a random secret key.
pub fn generate_participant(id: u64) -> Participant {
    let x_i = Scalar::random(&mut OsRng);
    let X_i = ProjectivePoint::GENERATOR * x_i;

    Participant { id, x_i, X_i }
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

// --------------------------------------------------------
//           THRESHOLD SCHNORR SIGNING (t-of-n)
// --------------------------------------------------------

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
fn compute_challenge(R: &ProjectivePoint, X: &ProjectivePoint, msg: &[u8]) -> Scalar {
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
pub fn partial_sign(participant: &Participant, r_i: Scalar, c: Scalar) -> PartialSignature {
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

/// --------------------------------------------------------
///                    TESTS
/// --------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rng, seq::IteratorRandom};

    #[test]
    fn test_threshold_schnorr_3_5() {
        let mut rng = rng();
        let n = 5;
        let t = 3;
        let participants = (1..=n).map(generate_participant).collect::<Vec<_>>();

        let msg = b"Hello threshold schnorr!";

        let chosen_participants: Vec<Participant> = participants
            .iter()
            .choose_multiple(&mut rng, t)
            .into_iter()
            .map(|p| *p)
            .collect();

        let ids: Vec<u64> = chosen_participants.iter().map(|p| p.id).collect();

        // aggregate the public key from the chosen participants
        let public_keys = chosen_participants
            .iter()
            .map(|p| (p.id, p.X_i))
            .collect::<Vec<_>>();
        let public_key = aggregate_public_key(&public_keys);

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

        let c = compute_challenge(&R, &public_key, msg);

        let partials = nonce_pairs
            .iter()
            .map(|(p, r_i, _)| partial_sign(p, *r_i, c))
            .collect::<Vec<_>>();

        let signature = finalize_signature_lagrange(&partials, R);
        assert!(signature.verify(msg, &public_key));
    }

    #[test]
    fn test_threshold_schnorr_5_5_valid() {
        let participants = (1..=5).map(generate_participant).collect::<Vec<_>>();
        let msg = b"Full participation test";
        let ids: Vec<u64> = participants.iter().map(|p| p.id).collect();

        let public_keys = participants
            .iter()
            .map(|p| (p.id, p.X_i))
            .collect::<Vec<_>>();
        let public_key = aggregate_public_key(&public_keys);

        let nonce_pairs = participants
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

        let c = compute_challenge(&R, &public_key, msg);

        let partials = nonce_pairs
            .iter()
            .map(|(p, r_i, _)| partial_sign(p, *r_i, c))
            .collect::<Vec<_>>();

        let sig = finalize_signature_lagrange(&partials, R);
        assert!(sig.verify(msg, &public_key));
    }

    #[test]
    fn test_invalid_signature_wrong_participants() {
        let participants = (1..=5).map(generate_participant).collect::<Vec<_>>();
        let msg = b"Wrong participant set";

        let signers = &participants[0..3]; // signers
        let verifiers = &participants[2..5]; // different subset

        let signer_ids: Vec<u64> = signers.iter().map(|p| p.id).collect();
        let public_keys = verifiers.iter().map(|p| (p.id, p.X_i)).collect::<Vec<_>>();
        let public_key = aggregate_public_key(&public_keys);

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

        let c = compute_challenge(&R, &public_key, msg);

        let partials = nonce_pairs
            .iter()
            .map(|(p, r_i, _)| partial_sign(p, *r_i, c))
            .collect::<Vec<_>>();

        let sig = finalize_signature_lagrange(&partials, R);
        assert!(!sig.verify(msg, &public_key));
    }

    #[test]
    fn test_invalid_signature_wrong_message() {
        let participants = (1..=3).map(generate_participant).collect::<Vec<_>>();
        let correct_msg = b"Correct message";
        let tampered_msg = b"Wrong message";
        let ids: Vec<u64> = participants.iter().map(|p| p.id).collect();

        let public_keys = participants
            .iter()
            .map(|p| (p.id, p.X_i))
            .collect::<Vec<_>>();
        let public_key = aggregate_public_key(&public_keys);

        let nonce_pairs = participants
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

        let c = compute_challenge(&R, &public_key, correct_msg);

        let partials = nonce_pairs
            .iter()
            .map(|(p, r_i, _)| partial_sign(p, *r_i, c))
            .collect::<Vec<_>>();

        let sig = finalize_signature_lagrange(&partials, R);
        assert!(!sig.verify(tampered_msg, &public_key));
    }

    #[test]
    fn test_valid_signature_deterministic() {
        let participants = (1..=4).map(generate_participant).collect::<Vec<_>>();
        let msg = b"Repeat verification";
        let ids: Vec<u64> = participants.iter().map(|p| p.id).collect();

        let public_keys = participants
            .iter()
            .map(|p| (p.id, p.X_i))
            .collect::<Vec<_>>();
        let public_key = aggregate_public_key(&public_keys);

        let nonce_pairs = participants
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

        let c = compute_challenge(&R, &public_key, msg);

        let partials = nonce_pairs
            .iter()
            .map(|(p, r_i, _)| partial_sign(p, *r_i, c))
            .collect::<Vec<_>>();

        let sig = finalize_signature_lagrange(&partials, R);

        for _ in 0..50 {
            assert!(sig.verify(msg, &public_key));
        }
    }

    #[test]
    fn test_threshold_signature_equals_manual_combined_signature() {
        let mut rng = rng();
        let n = 5;
        let t = 3;

        let participants = (1..=n).map(generate_participant).collect::<Vec<_>>();
        let chosen: Vec<Participant> = participants
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
        let participants = (1..=n).map(generate_participant).collect::<Vec<_>>();

        let msg = b"Hello threshold schnorr!";

        let chosen_participants: Vec<Participant> = participants.iter().take(t).copied().collect();

        let ids: Vec<u64> = chosen_participants.iter().map(|p| p.id).collect();

        let public_keys = chosen_participants
            .iter()
            .map(|p| (p.id, p.X_i))
            .collect::<Vec<_>>();
        let public_key = aggregate_public_key(&public_keys);

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

        let c = compute_challenge(&R, &public_key, msg);

        let partials = nonce_pairs
            .iter()
            .map(|(p, r_i, _)| partial_sign(p, *r_i, c))
            .collect::<Vec<_>>();

        let signature = finalize_signature_lagrange(&partials, R);
        assert!(signature.verify(msg, &public_key));

        // ---------------------------

        let rev_chosen_participants: Vec<Participant> =
            participants.iter().rev().take(t).copied().collect();

        let ids: Vec<u64> = rev_chosen_participants.iter().map(|p| p.id).collect();

        let public_keys = rev_chosen_participants
            .iter()
            .map(|p| (p.id, p.X_i))
            .collect::<Vec<_>>();
        let public_key = aggregate_public_key(&public_keys);

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

        let c = compute_challenge(&R, &public_key, msg);

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
}
