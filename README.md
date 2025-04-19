# Shamy

A simple Rust library exploring Shamir's Secret Sharing and threshold Schnorr signatures.

## Features

- [x] **Lagrange Interpolation**
- [x] **Threshold Schnorr Signatures**
- [ ] **Verifiable Secret Sharing (VSS)**
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
