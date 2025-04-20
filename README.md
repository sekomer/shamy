# Shamy

![ci](https://github.com/sekomer/shamy/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/sekomer/shamy/branch/main/graph/badge.svg)](https://codecov.io/gh/sekomer/shamy)

A simple Rust library exploring Shamir's Secret Sharing and threshold Schnorr signatures.

## Features

- [x] **Lagrange Interpolation**
- [x] **Threshold Schnorr Signatures**
- [x] **Verifiable Secret Sharing (VSS)**
- [ ] **Two‑Nonce Commit‑and‑Reveal (FROST)**

## Building

To build the project:

```bash
cargo build
```

## Testing

```bash
cargo test
```

## Examples

```bash
cargo run --example 2of3
```

## Schnorr Signature

```
[FLOW]
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

[MATH]
   ┌───────────────────┐
   │ s*G = (r + c*x)*G │
   │     = r*G + c*x*G │
   │     = R + c*X     │
   └───────────────────┘
```

## Verifiable Secret Sharing

```
[FLOW]
┌──────────┐     ┌────────────┐     ┌─────────────────┐
│  Secret  │     │ Polynomial │     │   Commitments   │
│    s     │────►│    f(x)    │────►│ C[j] = G * a_j  │
└──────────┘     └────────────┘     └─────────────────┘
                       │                  │
                       │                  │
                       ▼                  │
                 ┌────────────┐           │
                 │   Shares   │◄──────────┘
                 │    s[i]    │
                 └────────────┘
                       │
                       │
                       ▼
                ┌──────────────┐
                │Reconstruction│
                │    t-of-n    │
                └──────────────┘

[MATH]
   ┌─────────────────────────────┐
   │ f(x) = s + a₁x + a₂x² + ... │
   │ C[i] = f(i)*G               │
   │ Verify: s[i]*G = C[i]       │
   └─────────────────────────────┘
```
