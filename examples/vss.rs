#![allow(non_snake_case)]

use rand::seq::IndexedRandom;
use shamy::shamir;
use shamy::vss::verify_commitment;

fn main() {
    let n = 3;
    let t = 2;
    let keygen_output = shamir::shamir_keygen(n, t);

    let mut rng = rand::rng();
    let random_participant = keygen_output.participants.choose(&mut rng).unwrap();

    match verify_commitment(
        random_participant.id,
        random_participant.x_i,
        &keygen_output.commitments,
    ) {
        true => println!("Share verification successful ✅"),
        false => println!("Share verification failed ❌"),
    }
}
