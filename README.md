# Shamy

A simple Rust library exploring Shamir's Secret Sharing and threshold Schnorr signatures.

> **Note**: At the moment, the code implements a _multi-signature aggregator_ approach, true **single-secret threshold** scheme will be added soon.

## Features

- [x] **Multi-party Schnorr Signatures**
- [x] **Lagrange Interpolation**
- [ ] **Threshold Schnorr Signatures**
- [ ] **Verifiable Secret Sharing (VSS)**

## Building

To build the project:

```bash
cargo build
```

## Testing

```bash
cargo test
```

## Flow and Math

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
