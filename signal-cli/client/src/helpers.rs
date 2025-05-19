use crate::bul::BulNet;

use anyhow::Result;
use ark_bn254::Fr;
use ark_ff::{BigInteger, BigInteger256, PrimeField, ToConstraintField};
use ark_groth16::Groth16;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::{fs, result::Result::Ok, UniformRand};
use common::{
    zk::{exec_scanint, exec_standint, pseudonym_pred, MsgUser, PseudonymArgs, PseudonymArgsVar},
    E, F,
};
use petname::{Generator, Petnames};
use rand::{
    rngs::{OsRng, StdRng},
    SeedableRng,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
    str::FromStr,
};
use url::Url;
use zk_callbacks::{
    crypto::hash::HasherZK,
    generic::{
        bulletin::PublicUserBul,
        callbacks::CallbackCom,
        object::{Com, Time},
        user::User,
    },
    impls::{
        centralized::{crypto::PlainTikCrypto, ds::sigstore::GRSchnorrObjStore},
        hash::Poseidon,
    },
};

#[derive(Serialize, Deserialize)]
pub struct PseudonymProofEntry {
    pub context: String,
    pub claimed: String,
}

#[derive(Serialize, Deserialize)]
pub struct PollPseudonymProofEntry {
    pub context: String,
    pub claimed: String,
    pub timestamp: u64,
}

fn save_struct(user: &User<F, MsgUser>) -> std::io::Result<()> {
    let file = File::create("client/user.bin")?;
    let mut writer = BufWriter::new(file);
    // user.serialize_with_mode(&mut writer, Compress::No).unwrap();
    user.data
        .serialize_with_mode(&mut writer, Compress::No)
        .unwrap();
    user.zk_fields
        .serialize_with_mode(&mut writer, Compress::No)
        .unwrap();
    user.callbacks
        .serialize_with_mode(&mut writer, Compress::No)
        .unwrap();
    user.scan_index
        .serialize_with_mode(&mut writer, Compress::No)
        .unwrap();
    user.in_progress_cbs
        .serialize_with_mode(&mut writer, Compress::No)
        .unwrap();
    writer.flush()?;
    Ok(())
}

// thread 'tokio-runtime-worker' panicked at client/src/helpers.rs:319:30:
// called `Result::unwrap()` on an `Err` value: Custom { kind: InvalidData, error: "IoError(Error { kind: UnexpectedEof, message: \"failed to fill whole buffer\" })" }
// note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
// [gen_cb_for_msg] Panic inside task: JoinError::Panic(Id(15), "called `Result::unwrap()` on an `Err` value: Custom { kind: InvalidData, error: \"IoError(Error { kind: UnexpectedEof, message: \\\"failed to fill whole buffer\\\" })\" }", ...)

fn load_struct() -> std::io::Result<User<F, MsgUser>> {
    let file = File::open("client/user.bin")?;
    let mut reader = BufReader::new(file);
    let obj = User::<F, MsgUser>::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes)
        .map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e))
    })?;
    Ok(obj)
}

pub fn join2() -> Result<()> {
    let bul = BulNet::new(Url::parse("http://127.0.0.1:3000").unwrap());

    let mut rng = OsRng;

    // Create a new user
    let user = User::create(
        MsgUser {
            sk: F::from(0),
            reputation: F::from(0),
            num_interactions_since_last_scan: F::from(0),
            banned: F::from(0),
            badge1: F::from(0),
            badge2: F::from(0),
            badge3: F::from(0),
        },
        &mut rng,
    );

    let commit: Com<F> = user.commit::<Poseidon<2>>();
    println!("{:?}", commit.clone());

    let _ = bul.join_bul(commit);

    println!("{:?}", user);
    let _ = save_struct(&user);

    // Delete pseudo_log.jsonl if it exists
    let _ = fs::remove_file("client/pseudo_log.jsonl");

    // Generate new pseudo proof
    gen_pseudo();

    Ok(())
}

pub fn gen_cb_for_msg() -> Result<Vec<u8>, SynthesisError> {
    println!("[USER] Interacting (proving)...");

    let bul = BulNet::new(Url::parse("http://127.0.0.1:3000").unwrap());
    let mut rng = OsRng;

    let mut user: User<F, MsgUser> = load_struct().unwrap();

    let pk_standard = get_standard_proving_key();

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

    println!("[USER] Executed interaction! New user: {:?} \n", user);

    println!("[BULLETIN / SERVER] Verifying and storing...");

    let mut payload = vec![];
    exec.serialize_with_mode(&mut payload, Compress::No)
        .unwrap();

    let _ = save_struct(&user);
    println!("{:?}", user);

    Ok(payload)
}

pub fn scan() -> Result<Vec<u8>, SynthesisError> {
    println!("[USER] Scanning a ticket... ");

    let bul = BulNet::new(Url::parse("http://127.0.0.1:3000").unwrap());
    let mut rng = OsRng;

    let mut user: User<F, MsgUser> = load_struct().unwrap();

    let pk_scan = get_scanning_proving_key();
    let scan_one = exec_scanint(&mut user, &mut rng, &bul, &pk_scan, &bul, Time::from(0)).unwrap();

    println!("[USER] Scanned single ticket... {:?} \n", user);

    println!("[BULLETIN / SERVER] Verifying and storing scan...");

    let mut payload2 = vec![];
    scan_one
        .serialize_with_mode(&mut payload2, Compress::No)
        .unwrap();

    println!("[BULLETIN / SERVER] Verifying and storing scan...");

    let _ = save_struct(&user);
    println!("{:?}", user);

    Ok(payload2)
}

// pub fn ban(timestamp: u64) -> Result<()> {
//     // Open file and parse all JSON lines
//     let file = File::open("server/zkpair_log.jsonl").context("Failed to open JSONL file")?;
//     let reader = BufReader::new(file);

//     for line in reader.lines() {
//         let line = line?;
//         let json: Value = serde_json::from_str(&line)?;

//         if json.get("timestamp").and_then(|t| t.as_u64()) == Some(timestamp) {
//             // Extract the callback commitment
//             let cb_str = json
//                 .get("cb")
//                 .and_then(|v| v.as_str())
//                 .context("Missing or invalid `cb` field")?;

//             let cb_bytes = Vec::from_hex(cb_str)?;
//             let cb: CallbackCom<Fr, Fr, PlainTikCrypto<Fr>> =
//                 CanonicalDeserialize::deserialize_compressed(&cb_bytes[..])?;

//             // Send ban
//             let bul = BulNet::new(Url::parse("http://127.0.0.1:3000").unwrap());
//             let url = bul.api.join("api/ban").expect("Invalid endpoint");

//             let mut buf = Vec::new();
//             cb.serialize_with_mode(&mut buf, Compress::No)
//                 .expect("Serialization failed");

//             bul.client.post(url).body(buf).send()?;

//             return Ok(());
//         }
//     }

//     Err(anyhow::anyhow!(
//         "No matching entry found for timestamp {}",
//         timestamp
//     ))
// }

// pub fn rep(timestamp: u64) -> Result<()> {
//     // Open file and parse all JSON lines
//     let file = File::open("server/zkpair_log.jsonl").context("Failed to open JSONL file")?;
//     let reader = BufReader::new(file);

//     for line in reader.lines() {
//         let line = line?;
//         let json: Value = serde_json::from_str(&line)?;

//         if json.get("timestamp").and_then(|t| t.as_u64()) == Some(timestamp) {
//             // Extract the callback commitment
//             let cb_str = json
//                 .get("cb")
//                 .and_then(|v| v.as_str())
//                 .context("Missing or invalid `cb` field")?;

//             let cb_bytes = Vec::from_hex(cb_str)?;
//             let cb: CallbackCom<Fr, Fr, PlainTikCrypto<Fr>> =
//                 CanonicalDeserialize::deserialize_compressed(&cb_bytes[..])?;

//             // Send rep
//             let bul = BulNet::new(Url::parse("http://127.0.0.1:3000").unwrap());
//             let url = bul.api.join("api/reputation").expect("Invalid endpoint");

//             let mut buf = Vec::new();
//             cb.serialize_with_mode(&mut buf, Compress::No)
//                 .expect("Serialization failed");

//             bul.client.post(url).body(buf).send()?;
//             return Ok(());
//         }
//     }

//     Err(anyhow::anyhow!(
//         "No matching entry found for timestamp {}",
//         timestamp
//     ))
// }

pub fn send_callback_to_endpoint(timestamp: u64, endpoint: &str) -> Result<()> {
    let bul = BulNet::new(Url::parse("http://127.0.0.1:3000").unwrap());

    // Create JSON body
    let body = serde_json::to_vec(&serde_json::json!({ "timestamp": timestamp }))?;

    // POST to /api/cb with JSON body
    let cb_url = bul.api.join("api/cb")?;
    let resp = bul
        .client
        .post(cb_url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()?;

    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("Failed to fetch callback from server"));
    }

    let cb_bytes = resp.bytes()?.to_vec();
    let cb: CallbackCom<Fr, Fr, PlainTikCrypto<Fr>> =
        CanonicalDeserialize::deserialize_compressed(&cb_bytes[..])?;

    let mut buf = Vec::new();
    cb.serialize_with_mode(&mut buf, Compress::No)?;

    let target_url = bul.api.join(endpoint)?;
    bul.client.post(target_url).body(buf).send()?;

    Ok(())
}

pub fn ban(timestamp: u64) -> Result<()> {
    send_callback_to_endpoint(timestamp, "api/ban")
}

pub fn rep(timestamp: u64) -> Result<()> {
    send_callback_to_endpoint(timestamp, "api/reputation")
}

pub fn prf(sk: &F, ctx: &F) -> F {
    Poseidon::<2>::hash(&[*sk, *ctx])
}

pub fn compute_pseudo_for_poll(context: &F) -> F {
    let user = load_struct().unwrap();
    prf(&user.data.sk, context)
}

pub fn gen_pseudo() {
    let mut rng = OsRng;
    let user = load_struct().unwrap();
    let context: F = F::rand(&mut rng);
    let claimed = Poseidon::<2>::hash(&[user.data.sk, context]);

    let entry = PseudonymProofEntry {
        context: context.into_bigint().to_string(),
        claimed: claimed.into_bigint().to_string(),
    };

    // Append to file as JSONL
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("client/pseudo_log.jsonl")
        .unwrap();

    writeln!(file, "{}", serde_json::to_string(&entry).unwrap()).unwrap();
    let _ = save_struct(&user);
}

pub fn pseudo_proof_with_msg(claimed: F, context: F) -> Result<Vec<u8>, SynthesisError> {
    println!("[USER] Interacting (proving)...");

    let mut user: User<F, MsgUser> = load_struct().unwrap();
    let bul = BulNet::new(Url::parse("http://127.0.0.1:3000").unwrap());
    let mut rng = OsRng;

    let pk_standard = get_standard_proving_key();

    // Get signature and key for arbitrary predicate proof
    let commit = user.commit::<Poseidon<2>>();
    let (pubkey, sig) = bul.get_membership_data(commit).unwrap();
    let pk_arb_pred = get_arbitrary_pred_pk();

    let pseudo = PseudonymArgs { context, claimed };
    println!("[USER] Generating pseudonym proof with {:?}", pseudo);

    let proof = user.prove_statement_and_in::<
        Poseidon<2>,
        PseudonymArgs<F>,
        PseudonymArgsVar<F>,
        (),
        (),
        Groth16<E>,
        GRSchnorrObjStore,
    >(
        &mut rng,
        pseudonym_pred,
        &pk_arb_pred,
        (sig, pubkey),
        true,
        pseudo.clone(),
        (),
    )?;

    // Execute standard interaction
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

    println!("[USER] Executed interaction");

    // Serialize all three components: exec, proof, pub_inputs
    let mut payload = vec![];
    exec.serialize_with_mode(&mut payload, Compress::No)
        .unwrap();
    proof
        .serialize_with_mode(&mut payload, Compress::No)
        .unwrap();
    vec![context, claimed]
        .serialize_with_mode(&mut payload, Compress::No)
        .unwrap();

    let _ = save_struct(&user);
    println!("{:?}", user);
    Ok(payload)
}

pub fn pseudo_proof_vote(claimed: F, context: F) -> Result<Vec<u8>, SynthesisError> {
    println!("[USER] Interacting (proving)...");

    let user: User<F, MsgUser> = load_struct().unwrap();
    let bul = BulNet::new(Url::parse("http://127.0.0.1:3000").unwrap());
    let mut rng = OsRng;

    // Get signature and key for arbitrary predicate proof
    let commit = user.commit::<Poseidon<2>>();
    let (pubkey, sig) = bul.get_membership_data(commit).unwrap();
    let pk_arb_pred = get_arbitrary_pred_pk();

    let pseudo = PseudonymArgs { context, claimed };
    println!("[USER] Generating pseudonym proof with {:?}", pseudo);

    let proof = user.prove_statement_and_in::<
        Poseidon<2>,
        PseudonymArgs<F>,
        PseudonymArgsVar<F>,
        (),
        (),
        Groth16<E>,
        GRSchnorrObjStore,
    >(
        &mut rng,
        pseudonym_pred,
        &pk_arb_pred,
        (sig, pubkey),
        true,
        pseudo.clone(),
        (),
    )?;

    // Serialize all three components: exec, proof, pub_inputs
    let mut payload = vec![];
    proof
        .serialize_with_mode(&mut payload, Compress::No)
        .unwrap();
    vec![context, claimed]
        .serialize_with_mode(&mut payload, Compress::No)
        .unwrap();

    let _ = save_struct(&user);
    Ok(payload)
}

pub fn get_pseudo_from_claimed(claimed_str: String) -> String {
    // Convert claimed_str back to field element
    let claimed = F::from_bigint(BigInteger256::from_str(&claimed_str).unwrap()).unwrap();

    // Convert to bytes
    let claimed_bytes = claimed.into_bigint().to_bytes_le();

    // Pad or truncate to 32 bytes
    let mut seed = [0u8; 32];
    let len = claimed_bytes.len().min(32);
    seed[..len].copy_from_slice(&claimed_bytes[..len]);

    // Seed RNG and generate name
    let mut rng = StdRng::from_seed(seed);
    let g = Petnames::default();
    g.generate(&mut rng, 2, " ")
        .unwrap_or_else(|| "anonymous user".to_string())
}

pub fn list_all_pseudos_from_log() {
    let file = File::open("client/pseudo_log.jsonl").expect("Failed to open pseudo_log.jsonl");
    let reader = BufReader::new(file);

    for (i, line_result) in reader.lines().enumerate() {
        let line = line_result.expect("Failed to read line");
        let json: Value = serde_json::from_str(&line).expect("Invalid JSON");

        if let Some(claimed_str) = json["claimed"].as_str() {
            let pseudo = get_pseudo_from_claimed(claimed_str.to_string());
            println!("\"{}\"; index = {}", pseudo, i + 1);
        } else {
            eprintln!("Line {} missing 'claimed' field", i + 1);
        }
    }
}

/// Retrieves the `claimed` and `context` strings at the given 1-based line index
pub fn get_claimed_context_by_index(index: usize) -> Option<(String, String)> {
    let file = File::open("client/pseudo_log.jsonl").expect("Failed to open pseudo_log.jsonl");
    let reader = BufReader::new(file);

    for (i, line_result) in reader.lines().enumerate() {
        if i + 1 == index {
            let line = line_result.ok()?;
            let json: Value = serde_json::from_str(&line).ok()?;
            let claimed = json["claimed"].as_str()?.to_string();
            let context = json["context"].as_str()?.to_string();
            return Some((claimed, context));
        }
    }

    None // Return None if index is out of bounds or data is malformed
}

pub fn make_authorship_proof(i1: usize, i2: usize) -> Result<Vec<u8>, SynthesisError> {
    let user = load_struct().unwrap();
    let mut rng = OsRng;
    let bul = BulNet::new(Url::parse("http://127.0.0.1:3000").unwrap());

    // Get signature and key for arbitrary predicate proof
    let commit = user.commit::<Poseidon<2>>();
    let (pubkey, sig) = bul.get_membership_data(commit).unwrap();
    let pk_arb_pred = get_arbitrary_pred_pk2();

    use common::zk::authorship_pred;
    use common::zk::PseudonymArgsPair;
    use common::zk::PseudonymArgsPairVar;

    let (claimed_str1, context_str1) =
        get_claimed_context_by_index(i1).expect("Invalid index or malformed line");
    let (claimed_str2, context_str2) =
        get_claimed_context_by_index(i2).expect("Invalid index or malformed line");

    let context1 = string_to_f(&context_str1);
    let claimed1 = string_to_f(&claimed_str1);
    let context2 = string_to_f(&context_str2);
    let claimed2 = string_to_f(&claimed_str2);

    let pseudo = PseudonymArgs {
        context: context1,
        claimed: claimed1,
    };
    println!("[USER] Generating pseudonym proof with {:?}", pseudo);
    let pseudo2 = PseudonymArgs {
        context: context2,
        claimed: claimed2,
    };
    println!("[USER] Generating pseudonym proof with {:?}", pseudo2);

    let pair = PseudonymArgsPair {
        a: pseudo.clone(),
        b: pseudo2.clone(),
    };

    let proof = user
    .prove_statement_and_in::<
        Poseidon<2>,
        PseudonymArgsPair<F>,         // pub args type
        PseudonymArgsPairVar<F>,      // pub args var type
        (),
        (),
        Groth16<E>,
        GRSchnorrObjStore,
    >(
        &mut rng,
        authorship_pred,                // your statement predicate
        &pk_arb_pred,             // proving key
        (sig.clone(), pubkey),    // membership proof
        true,                     // whether to include object commitment
        pair.clone(),                  // your user object
        (),                 // public inputs go here
    )
    .unwrap();

    let mut payload = vec![];
    proof
        .serialize_with_mode(&mut payload, Compress::No)
        .unwrap();
    vec![context1, claimed1, context2, claimed2]
        .serialize_with_mode(&mut payload, Compress::No)
        .unwrap();

    let _ = save_struct(&user);

    Ok(payload)
}

pub fn string_to_f(s: &str) -> F {
    F::from_bigint(BigInteger256::from_str(s).unwrap()).unwrap()
}

pub fn make_badge_proof(i: usize, badge: F) -> Result<Vec<u8>, SynthesisError> {
    let user = load_struct().unwrap();
    let mut rng = OsRng;
    let bul = BulNet::new(Url::parse("http://127.0.0.1:3000").unwrap());

    // Get signature and key for arbitrary predicate proof
    let commit = user.commit::<Poseidon<2>>();
    let (pubkey, sig) = bul.get_membership_data(commit).unwrap();
    let pk_arb_pred = get_arbitrary_pred_pk3();

    use common::zk::badge_pred;
    use common::zk::BadgesArgs;
    use common::zk::BadgesArgsVar;

    let i_f = F::from(i as u32);
    // let badge = F::from(1);

    let badge_var = BadgesArgs {
        i: i_f,
        claimed: badge.clone(),
    };

    let proof = user
    .prove_statement_and_in::<
        Poseidon<2>,
        BadgesArgs<F>,         // pub args type
        BadgesArgsVar<F>,      // pub args var type
        (),
        (),
        Groth16<E>,
        GRSchnorrObjStore,
    >(
        &mut rng,
        badge_pred,                // your statement predicate
        &pk_arb_pred,             // proving key
        (sig.clone(), pubkey),    // membership proof
        true,                     // whether to include object commitment
        badge_var,                  // your user object
        (),                 // public inputs go here
    )
    .unwrap();

    let mut payload = vec![];
    proof
        .serialize_with_mode(&mut payload, Compress::No)
        .unwrap();
    vec![i_f, badge]
        .serialize_with_mode(&mut payload, Compress::No)
        .unwrap();

    let _ = save_struct(&user);

    Ok(payload)
}

use ark_groth16::ProvingKey;

pub fn get_standard_proving_key() -> ProvingKey<E> {
    let bul = BulNet::new(Url::parse("http://127.0.0.1:3000").unwrap());
    let url = bul
        .api
        .join("api/interaction/standard/proving_key")
        .unwrap();

    let bytes = bul
        .client
        .get(url)
        .send()
        .expect("failed to send request")
        .bytes()
        .expect("failed to get response bytes");

    ProvingKey::<E>::deserialize_with_mode(&*bytes, Compress::No, Validate::No)
        .expect("failed to deserialize proving key")
}

pub fn get_scanning_proving_key() -> ProvingKey<E> {
    let bul = BulNet::new(Url::parse("http://127.0.0.1:3000").unwrap());
    let url = bul.api.join("api/interaction/scan/proving_key").unwrap();

    let bytes = bul
        .client
        .get(url)
        .send()
        .expect("failed to send request")
        .bytes()
        .expect("failed to get response bytes");

    ProvingKey::<E>::deserialize_with_mode(&*bytes, Compress::No, Validate::No)
        .expect("failed to deserialize proving key")
}

pub fn get_arbitrary_pred_pk() -> ProvingKey<E> {
    let bul = BulNet::new(Url::parse("http://127.0.0.1:3000").unwrap());
    let url = bul.api.join("api/user/arbitrary_pred_proving_key").unwrap();

    let bytes = bul
        .client
        .get(url)
        .send()
        .expect("failed to send request")
        .bytes()
        .expect("failed to get response bytes");

    ProvingKey::<E>::deserialize_with_mode(&*bytes, Compress::No, Validate::No)
        .expect("failed to deserialize proving key")
}

pub fn get_arbitrary_pred_pk2() -> ProvingKey<E> {
    let bul = BulNet::new(Url::parse("http://127.0.0.1:3000").unwrap());
    let url = bul
        .api
        .join("api/user/arbitrary_pred_proving_key2")
        .unwrap();

    let bytes = bul
        .client
        .get(url)
        .send()
        .expect("failed to send request")
        .bytes()
        .expect("failed to get response bytes");

    ProvingKey::<E>::deserialize_with_mode(&*bytes, Compress::No, Validate::No)
        .expect("failed to deserialize proving key")
}

pub fn get_arbitrary_pred_pk3() -> ProvingKey<E> {
    let bul = BulNet::new(Url::parse("http://127.0.0.1:3000").unwrap());
    let url = bul
        .api
        .join("api/user/arbitrary_pred_proving_key3")
        .unwrap();

    let bytes = bul
        .client
        .get(url)
        .send()
        .expect("failed to send request")
        .bytes()
        .expect("failed to get response bytes");

    ProvingKey::<E>::deserialize_with_mode(&*bytes, Compress::No, Validate::No)
        .expect("failed to deserialize proving key")
}
