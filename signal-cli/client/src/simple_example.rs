pub mod parse;

use anyhow::Result;
use ark_bn254::{Bn254 as E, Fr as F};
use ark_ff::ToConstraintField;
use ark_groth16::Groth16;
use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::result::Result::Ok;
use client::bul::BulNet;
use common::zk::{exec_scanint, exec_standint, some_pred, MsgUser};
use rand::rngs::OsRng;
use url::Url;
use zk_callbacks::{
    generic::{
        bulletin::PublicUserBul,
        object::{Com, Time},
        user::User,
    },
    impls::{centralized::ds::sigstore::GRSchnorrObjStore, hash::Poseidon},
};

fn main() -> Result<()> {
    let bul = BulNet::new(Url::parse("http://127.0.0.1:3000").unwrap());

    let mut rng = OsRng;

    // Create a new user
    let mut user = User::create(
        MsgUser {
            reputation: F::from(0),
            num_interactions_since_last_scan: F::from(0),
        },
        &mut rng,
    );

    let commit: Com<F> = user.commit::<Poseidon<2>>();

    match bul.join_bul(commit) {
        Ok(()) => println!("Successfully joined!\n"),
        Err(e) => println!("Failed to join: {}", e),
    }

    let (pubkey, witness) =
        <BulNet as PublicUserBul<F, MsgUser>>::get_membership_data(&bul, commit).unwrap();
    let pk_arb_pred = bul.get_arbitrary_pred_pk();
    let pk_standard = bul.get_standard_proving_key();

    println!("[USER] Generating proof... ");

    let proof = user
        .prove_statement_and_in::<Poseidon<2>, (), (), (), (), Groth16<E>, GRSchnorrObjStore>(
            &mut rng,
            some_pred, // Specifically, this statement here (see some_pred above)
            &pk_arb_pred,
            (
                witness, pubkey, // public membership data (the sig pubkey)
            ),
            true,
            (),
            (),
        )
        .unwrap();

    let mut payload3 = vec![];
    proof
        .serialize_with_mode(&mut payload3, Compress::No)
        .unwrap();

    let mut pub_inputs = vec![];
    pub_inputs.extend::<Vec<F>>(().to_field_elements().unwrap());
    pub_inputs
        .serialize_with_mode(&mut payload3, Compress::No)
        .unwrap();

    // Send
    let res = bul.post("api/interact/arbitrary_pred", payload3).unwrap();
    println!(
        "[SERVER] Checking proof and storing interaction... Output: {:?} \n",
        res
    );

    println!("[USER] Interacting (proving)...");

    let mut pub_inputs = vec![];
    pub_inputs.extend::<Vec<F>>(().to_field_elements().unwrap());

    let exec = exec_standint(
        &mut user,
        &mut rng,
        &bul,
        &pk_standard,
        Time::from(0),
        F::from(0),
        (),
    )
    .unwrap();

    println!("[USER] Executed interaction! New user: {:o} \n", user);

    println!("[BULLETIN / SERVER] Verifying and storing...");

    let mut payload = vec![];
    exec.serialize_with_mode(&mut payload, Compress::No)
        .unwrap();
    let res = bul.post("api/interact/standard", payload);

    println!(
        "[SERVER] Checking proof and storing interaction... Output: {:?} \n",
        res
    );

    println!("[USER] Scanning a ticket... ");

    let pk_scan = bul.get_scanning_proving_key();
    let scan_one =
        exec_scanint(&mut user, &mut rng, &bul, &pk_scan, &bul, Time::from(100)).unwrap();

    println!("[USER] Scanned single ticket... {:o} \n", user);

    println!("[BULLETIN / SERVER] Verifying and storing scan...");

    let mut payload2 = vec![];
    scan_one
        .serialize_with_mode(&mut payload2, Compress::No)
        .unwrap();
    let res = bul.post("api/interact/scan", payload2);

    println!(
        "[SERVER] Checking proof and storing interaction... Output: {:?} \n",
        res
    );

    println!("[BULLETIN / SERVER] Verifying and storing scan...");

    println!("{:?}", user);

    Ok(())
}
