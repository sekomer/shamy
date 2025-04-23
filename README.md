# Shamy

![ci](https://github.com/sekomer/shamy/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/sekomer/shamy/branch/main/graph/badge.svg)](https://codecov.io/gh/sekomer/shamy)

A simple Rust library exploring Shamir's Secret Sharing and threshold Schnorr signatures.

## Features

- [x] **Lagrange Interpolation**
- [x] **Threshold Schnorr Signatures**
- [x] **Verifiable Secret Sharing (VSS)**
- [x] **Command Line Interface**
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

## CLI

Installation:

```bash
$ cargo install --path .  # --force to overwrite existing installation
$ shamy help
```

Without installation:

```bash
$ cargo run --bin cli -- help
```

### Usage

`shamy` cli provides functionality for generating threshold keys, signing and verifying signatures, and managing nonces. Here's a breakdown of the commands:

### Key Generation

Generate a set of secret shares for a threshold signature scheme:

```bash
$ shamy help
Usage: shamy [OPTIONS] [COMMAND]

Commands:
  keygen
  schnorr
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose
  -h, --help     Print help
  -V, --version  Print version
```

**Keygen subcommand:**

```bash
$ shamy keygen help
Usage: shamy keygen [OPTIONS] --threshold <THRESHOLD> --num-shares <NUM_SHARES>

Options:
  -t, --threshold <THRESHOLD>
  -n, --num-shares <NUM_SHARES>
  -o, --output <OUTPUT>
  -h, --help                     Print help
```

**Schnorr subcommand:**

```bash
$ shamy schnorr help
Usage: shamy schnorr <COMMAND>

Commands:
  sign
  verify
  combine
  nonce
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

**Keygen example:**

```bash
$ shamy keygen -t 2 -n 3 -o keygen.secret
[Participant ID:0]
x_i = ee3c358e001602812a38c70d46cf17247bcb0b090432fc97405f8f1ed31c12ce
X_i = 02704e4d43daa4caea3d7255d53f718db8f10454f79ad2013b75f9199b12d54759

[Participant ID:1]
x_i = eece776f152ad14c742e413ff080d0f77f434aea539621743f8eaa7182c67225
X_i = 03ac5baf9ff6b3f0fd687518563b75a71b39ba07544037d5cdb603596ef4f26987

[Participant ID:2]
x_i = ef60b9502a3fa017be23bb729a328aca82bb8acba2f946513ebdc5c43270d17c
X_i = 0298866baa57cfef146777e52a0945f0769b003d1167cb6945108f8b3773034cfb

Public key X = 03b95def8e4ad6ac4f2f85d6b26e2c60614eb820c5d0439be17467163082349bdd
Commitment 0 = 03b95def8e4ad6ac4f2f85d6b26e2c60614eb820c5d0439be17467163082349bdd
Commitment 1 = 03019eb058e2dcaa496e16824fc9ed8d454f18bcac2e55024a43c775ff2051a39b
```

**Combine Signatures Example:**

```bash
$ shamy schnorr combine --nonce 031cb8610733456b7f163fb088a127118ddfe10689af097eb7646c96c025b8e5ae --ids 1 2 --signatures 4ea64f5d0b0a68762d143eb45b6e00366923dc76d4fbc9830176b42223677016 983f3626eb6cb6dddf7c9eada612b64ba7558c35db80cee908469d50b2b9441f
Interpolated signature: 050d68932aa81a0e7aabdebb10c94a212af22cb7ce76c41cfaa6caf394159c0d
```

**Signature Verification Example:**

```bash
$ shamy schnorr verify --message "rust is best" --nonce 032ab98218bf256c1e9a3d7a85f451f0879867fbc0923540c4cd2928d1f4b03303 --signature 2290a650e2d62d3f3155c52284d7db29cb0674ee5539be9340f816aca92c7262 --public-key 03dba6989ee4de1e4a4710fcd6fd7fc85970f30bb0efaa9dbd5c42f43476f95907
🔒✅ Signature is valid
```

**Nonce Generation Example:**

```bash
$ shamy schnorr nonce generate
nonce (r): b30e56960a2b942e355df83f09d1f3a12725b5289a7aef8282cb45911023b05e
R = (r*G): 02203d146b391430f9db199ddec803e045200ad1301bb4582dda76ef88b980beef
```

check help for more features

---

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
