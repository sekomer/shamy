pub mod frost;
pub mod schnorr;
pub mod shamir;
pub mod threshold;
pub mod util;
pub mod vss;

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
