#![allow(non_snake_case)]

mod cli_tests;
mod parser;

use parser::*;
use shamy::{
    schnorr::{SchnorrSignature, compute_challenge, compute_nonce_point, generate_nonce},
    shamir::shamir_keygen,
    threshold::{
        PartialSignature, Participant, aggregate_nonce, finalize_signature_lagrange, partial_sign,
    },
    util::{hex_to_pp, hex_to_scalar, pp_to_hex, scalar_to_hex},
};
use std::{
    fs::File,
    io::{BufWriter, Write},
};

fn main() {
    let cli = parser::Cli::parse();

    match cli.command {
        Some(parser::Commands::Keygen {
            threshold,
            num_shares,
            output,
        }) => {
            let keygen_output = shamir_keygen(num_shares as usize, threshold as usize);

            let mut writers: Vec<Box<dyn Write>> = vec![Box::new(std::io::stdout())];
            if let Some(output) = output {
                let file = File::create(output).unwrap();
                writers.push(Box::new(BufWriter::new(file)));
            }

            for (i, participant) in keygen_output.participants.iter().enumerate() {
                for writer in &mut writers {
                    writeln!(writer, "[Participant ID:{}]", i).unwrap();

                    let hex_str = scalar_to_hex(&participant.x_i);
                    writeln!(writer, "x_i = {}", hex_str).unwrap();

                    let pt_hex = pp_to_hex(&participant.X_i);
                    writeln!(writer, "X_i = {}\n", pt_hex).unwrap();
                }
            }

            let pt_hex = pp_to_hex(&keygen_output.public_key);
            for writer in &mut writers {
                writeln!(writer, "Public key X = {}", pt_hex).unwrap();
            }

            for (i, commitment) in keygen_output.commitments.iter().enumerate() {
                let pt_hex = pp_to_hex(&commitment);
                for writer in &mut writers {
                    writeln!(writer, "Commitment {} = {}", i, pt_hex).unwrap();
                }
            }
        }
        Some(parser::Commands::Schnorr { command }) => match command {
            SchnorrCommands::Sign {
                challange,
                share,
                id,
                nonce,
            } => {
                let share = hex_to_scalar(&share).unwrap();
                let nonce = hex_to_scalar(&nonce).unwrap();
                let challange = hex_to_scalar(&challange).unwrap();

                let participant = Participant::from_secret(id, share);
                let signature = partial_sign(&participant, &nonce, &challange);

                println!("Signature: {} ", scalar_to_hex(&signature.s_i));
            }
            SchnorrCommands::Nonce { command } => match command {
                NonceCommands::Generate => {
                    let r = generate_nonce();
                    let R = compute_nonce_point(&r);
                    println!("r(nonce): {}", scalar_to_hex(&r));
                    println!("R(G * r): {}", pp_to_hex(&R));
                }
                NonceCommands::Verify { nonce } => match hex_to_scalar(&nonce) {
                    Ok(_) => println!("Nonce is valid"),
                    Err(e) => println!("Error: {}", e),
                },
            },
            SchnorrCommands::Verify {
                message,
                signature,
                public_key,
                nonce,
            } => {
                let signature = hex_to_scalar(&signature).unwrap();
                let public_key = hex_to_pp(&public_key).unwrap();

                let signature = SchnorrSignature {
                    R: hex_to_pp(&nonce).unwrap(),
                    s: signature,
                };
                match signature.verify(&message.as_bytes(), &public_key) {
                    true => println!("🔒✅ Signature is valid"),
                    false => println!("🔒❌ Signature is invalid"),
                }
            }
            SchnorrCommands::Challenge {
                message,
                ids,
                nonces,
                public_key,
            } => {
                let nonce_pairs = ids
                    .clone()
                    .into_iter()
                    .zip(nonces)
                    .map(|(id, nonce)| (id, hex_to_pp(&nonce).unwrap()))
                    .collect::<Vec<_>>();
                let R = aggregate_nonce(&nonce_pairs, &ids);
                let c = compute_challenge(&R, &hex_to_pp(&public_key).unwrap(), message.as_bytes());

                println!("Challenge: {}", scalar_to_hex(&c));
            }
            SchnorrCommands::Combine {
                ids,
                signatures,
                nonce,
            } => {
                let nonce = hex_to_pp(&nonce).unwrap();
                let partial_signatures = signatures
                    .iter()
                    .zip(ids)
                    .map(|(s, id)| PartialSignature {
                        id,
                        s_i: hex_to_scalar(s).unwrap(),
                    })
                    .collect::<Vec<_>>();
                let signature = finalize_signature_lagrange(&partial_signatures, nonce);
                println!("Interpolated signature: {}", scalar_to_hex(&signature.s));
            }
        },
        _ => unreachable!(),
    }
}
