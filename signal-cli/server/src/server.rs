use crate::helpers::{
    append_vote, count_votes_by_timestamp, delete_poll_entry_by_timestamp,
    delete_poll_pseudo_entry_by_timestamp, find_callback_by_timestamp, get_ban_from_timestamp,
    get_context_from_timestamp, get_reputation_by_cb, is_ban_poll_by_timestamp,
    update_reaction_log,
};
use crate::ServerState;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, VerifyingKey};
use ark_r1cs_std::fields::fp::FpVar;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_snark::SNARK;
use ark_std::UniformRand;
use axum::{
    body::Bytes,
    extract::{Json, State},
    http::StatusCode,
    response::{ErrorResponse, IntoResponse, Response},
};
use client::helpers::{append_timing_line, append_timing_line_call_cb, append_timing_line_epoch, append_timing_line_features, append_timing_line_verify, load_start_time};
use common::{
    zk::{arg_ban, arg_rep, get_callbacks, get_extra_pubdata_for_scan2, MsgUser},
    Args, Cr, Snark, E, F,
};
use identicon_rs::Identicon;
use petname::{Generator, Petnames};
use rand::{
    rngs::{OsRng, StdRng},
    SeedableRng,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::SystemTime;
use std::{
    fs::{File, OpenOptions, read_to_string},
    io::{BufRead, BufReader, Write}, 
    process::Stdio, 
    str::FromStr, 
    string::ToString, 
    sync::Arc
};
use tokio::{process::Command, sync::RwLock};
use tracing::info;
use zk_callbacks::{
    generic::{
        bulletin::{CallbackBul, JoinableBulletin, UserBul},
        callbacks::CallbackCom,
        object::{Com, Time},
        scan::PubScanArgs,
        service::ServiceProvider,
        user::ExecutedMethod,
    },
    impls::{
        centralized::{
            crypto::{FakeSigPrivkey, PlainTikCrypto},
            ds::{
                sig::gr_schnorr::GrumpkinSchnorr,
                sigstore::{GRSchnorrCallbackStore, GRSchnorrObjStore, SigObjStore},
            },
        },
        hash::Poseidon,
    },
};

use crate::PseudonymArgs;
use crate::PseudonymArgsRate;

type PubScan = PubScanArgs<F, MsgUser, F, FpVar<F>, Cr, GRSchnorrCallbackStore<F>, 1>;
type ServerLock = Arc<RwLock<ServerState>>;

#[derive(Deserialize)]
pub struct JsonRpcInput {
    message: String,
    group_id: String,
    proof: Vec<u8>,
}

#[derive(Deserialize)]
pub struct JsonRpcInputPseudo {
    message: String,
    group_id: String,
    proof: Vec<u8>,
}

#[derive(Deserialize)]
pub struct JsonRpcBanPoll {
    message: Option<String>,
    group_id: String,
    timestamp: u64,
}

#[derive(Deserialize)]
pub struct JsonRpcReact {
    group_id: String,
    emoji: String,
    timestamp: u64,
}

#[derive(Deserialize)]
pub struct JsonRpcReply {
    group_id: String,
    message: String,
    timestamp: u64,
    proof: Vec<u8>,
}

#[derive(Deserialize)]
pub struct JsonRpcReplyPseudo {
    group_id: String,
    message: String,
    timestamp: u64,
    proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcVote {
    group_id: String,
    emoji: String,
    timestamp: u64,
    claimed: String,
    proof: Vec<u8>,
}

#[derive(Deserialize)]
pub struct JsonRpcPoll {
    message: String,
    group_id: String,
}

#[derive(Deserialize)]
pub struct JsonRpcCountVotes {
    group_id: String,
    timestamp: u64,
}

#[derive(Serialize)]
struct ContextResponse {
    context: String,
}

#[derive(Deserialize)]
pub struct TimestampRequest {
    timestamp: i64,
}

#[derive(Deserialize)]
pub struct JsonAuthorship {
    proof: Vec<u8>,
    group_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct TimingEntry {
    label: String,
    start_time: String,
    end_time: String,
    duration_seconds: f64,
}

#[derive(Deserialize)]
pub struct JsonBadge {
    proof: Vec<u8>,
    group_id: String,
}

#[derive(Deserialize)]
pub struct ContextRequest {
    thread: String,
}

#[derive(Serialize, Deserialize)]
pub struct ContextJson {
    thread: String,
    context: String,
}

#[derive(Deserialize)]
pub struct TimestampInput {
    timestamp: u64,
}

fn error_to_response(error: impl ToString) -> ErrorResponse {
    ErrorResponse::from((StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))
}

pub async fn forward_jsonrpc(
    State(state): State<ServerLock>,
    Json(input): Json<JsonRpcInput>,
) -> impl IntoResponse {
    info!("[SERVER] Verifying and appending interaction...");

    let mut state2 = state.write().await;
    let vk = state2.keys.standard_verifying_key.clone();
    let db = &mut state2.db;

    let mut reader = &input.proof[..];
    let exec: ExecutedMethod<F, Snark, Args, Cr, 1> =
        ExecutedMethod::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes).unwrap();

    // Start (2)
    let start_time_2 = SystemTime::now();

    let verified =
        <GRSchnorrObjStore as UserBul<F, MsgUser>>::verify_interact_and_append::<F, Groth16<E>, 1>(
            &mut db.obj_bul,
            exec.new_object.clone(),
            exec.old_nullifier.clone(),
            F::from(0),
            exec.cb_com_list.clone(), // cb_coms.clone(),
            exec.proof.clone(),
            None,
            &vk,
        );


    info!("[SERVER] Verification result: {:?}", verified);
    info!("[SERVER] Checking proof and storing interaction...");
    let cb_tickets = &exec.cb_tik_list.clone(); // get callback tickets

    let cb_methods = get_callbacks();
    let res = db
        .approve_interaction_and_store::<MsgUser, Groth16<E>, F, GRSchnorrObjStore, Poseidon<2>, 1>(
            exec,                 // output of interaction
            FakeSigPrivkey::sk(), // for authenticity: verify rerandomization of key produces
            // proper tickets (here it doesn't matter)
            F::from(0),
            &db.obj_bul.clone(),
            cb_methods.clone(),
            Time::from(0),
            db.obj_bul.get_pubkey(),
            true,
            &vk,
            332, // interaction number
        );

    // End (2)
    let end_time_2 = SystemTime::now();

    
    info!("[SERVER] Verification result: {:?}", res);
    if verified.is_ok() && res.is_ok() {
        info!("[SERVER] Verified and added to bulletin!");
    } else {
        info!("[SERVER] Verification failed. Not added to bulletin.");
    }

    for (cb_com, _) in cb_tickets.iter() {

        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open("server/zkpair_log.jsonl")
            .unwrap();

        let mut bytes = vec![];
        cb_com
            .serialize_with_mode(&mut bytes, Compress::No)
            .unwrap();

        writeln!(
            file,
            "{{\"callback_com\": \"{}\", \"type\": \"cb\"}}",
            hex::encode(bytes)
        )
        .unwrap();
    }

    let message_to_send = input.message;

    let output = Command::new("signal-cli-client")
        .arg("-a")
        .arg("+15712811486") // fixed anon bot number +15712811486 or +491724953171
        .arg("--json-rpc-tcp")
        .arg("127.0.0.1:7583")
        .arg("send")
        .arg("-g")
        .arg(&input.group_id)
        .arg("-m")
        .arg(&message_to_send)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    // End (3)
    let end_time = SystemTime::now();

    let start_time = match load_start_time("3") {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to load latency start time: {}", e);
            return;
        }
    };

    if let Err(e) = append_timing_line("3", start_time, end_time) {
        eprintln!("❌ Failed to write timing file for proof gen: {}", e);
    }

    if let Err(e) = append_timing_line("2", start_time_2, end_time_2) {
        eprintln!("❌ Failed to write timing file for proof gen: {}", e);
    }

    match output {
        Ok(output) => {

            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("Raw stdout from signal-cli-client: {}", stdout);

            let parsed: Value = serde_json::from_str(&stdout).unwrap();
            let ts = parsed["timestamp"].as_i64().unwrap();
            println!("Timestamp: {}", ts);

            let path = "server/zkpair_log.jsonl";
            let original_lines = read_to_string(path)
                .unwrap_or_default()
                .lines()
                .map(|s| s.to_string())
                .collect::<Vec<_>>();

            // Remove last line and parse callback
            assert!(original_lines.len() >= 1, "Expected at least one cb line before msg");

            let cb_line = &original_lines[original_lines.len() - 1];
            let cb_val: Value = serde_json::from_str(cb_line).unwrap();
            let cb = cb_val["callback_com"].as_str().unwrap();

            // Construct new line
            let new_entry = serde_json::json!({
                "timestamp": ts,
                "reputation": 0,
                "cb": cb,
            });

            // Combine previous lines (minus last) with new entry
            let mut all_entries = original_lines[..original_lines.len() - 1]
                .iter()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .collect::<Vec<_>>();

            all_entries.push(new_entry);

            // Optional: Sort by timestamp if you want strict time order
            all_entries.sort_by_key(|v| v["timestamp"].as_i64().unwrap_or(0));

            // Rewrite the file
            let mut file = File::create(path).unwrap();
            for entry in all_entries {
                writeln!(file, "{}", entry.to_string()).unwrap();
            }

            let stderr = String::from_utf8_lossy(&output.stderr);

            if output.status.success() {
                println!("Sent successfully: {}", stdout)
            } else {
                println!("Error sending: {}", stderr)
            } 
        }
        Err(e) => println!("Failed to spawn process: {:?}", e),
    }
}

pub async fn forward_jsonrpc_pseudo(
    State(state): State<ServerLock>,
    Json(input): Json<JsonRpcInputPseudo>,
) -> impl IntoResponse {
    info!("[SERVER] Verifying arbitrary predicate...");

    let mut state2 = state.write().await;
    let vk = state2.keys.standard_pseudo_verifying_key.clone();
    let db = &mut state2.db;

    let mut reader = &input.proof[..];

    // Deserialize components in order
    let exec: ExecutedMethod<F, Snark, Args, Cr, 1> =
        ExecutedMethod::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes).unwrap();

    let pub_inputs: Vec<F> =
        Vec::<F>::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes).unwrap();

    let claimed = pub_inputs[1];
    info!("[SERVER] Claimed pseudonym: {}", claimed);

    let pub_args = PseudonymArgs {
        context: pub_inputs[0],
        claimed: pub_inputs[1],
    };

    let start_verify = SystemTime::now();

    // Store the interaction to the object bulletin board
    let verify_store = <GRSchnorrObjStore as UserBul<F, MsgUser>>::verify_interact_and_append::<
        PseudonymArgs<F>,
        Groth16<E>,
        1,
    >(
        &mut db.obj_bul,
        exec.new_object.clone(),
        exec.old_nullifier.clone(),
        pub_args.clone(),
        exec.cb_com_list.clone(),
        exec.proof.clone(),
        None,
        &vk,
    )
    .unwrap();

    info!("[SERVER] Verification result: {:?}", verify_store);

    let cb_tickets = &exec.cb_tik_list.clone(); // get callback tickets

    // Store callback-reputation merged record
    let cb_methods = get_callbacks();
    let res = db
        .approve_interaction_and_store::<MsgUser, Groth16<E>, PseudonymArgs<F>, GRSchnorrObjStore, Poseidon<2>, 1>(
            exec,                 
            FakeSigPrivkey::sk(), 
            pub_args,
            &db.obj_bul.clone(),
            cb_methods.clone(),
            Time::from(0),
            db.obj_bul.get_pubkey(),
            true,
            &vk,
            332, // interaction number
        );

    let end_verify = SystemTime::now();

    info!("[SERVER] Verification result: {:?}", res);
    if res.is_ok() {
        info!("[SERVER] Verified and added to bulletin!");
    } else {
        info!("[SERVER] Verification failed. Not added to bulletin.");
    }

    // Write callback commitments to log file
    for (cb_com, _) in cb_tickets {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open("server/zkpair_log.jsonl")
            .unwrap();

        let mut bytes = vec![];
        cb_com
            .serialize_with_mode(&mut bytes, Compress::No)
            .unwrap();

        writeln!(
            file,
            "{{\"callback_com\": \"{}\", \"type\": \"cb\"}}",
            hex::encode(bytes)
        )
        .unwrap();
    }

    let claimed_bytes = claimed.into_bigint().to_bytes_le();
    let mut seed = [0u8; 32];
    seed[..claimed_bytes.len()].copy_from_slice(&claimed_bytes); // zero-pad to 32 bytes

    // Use as RNG seed
    let mut rng1 = StdRng::from_seed(seed);

    let g = Petnames::default();
    let name1 = g.generate(&mut rng1, 2, " ").expect("no name generated");

    let mut pseudo = String::from("FROM: ");
    pseudo.push_str(&name1);
    pseudo.push_str("\n\n");
    pseudo.push_str(&input.message);

    println!("Petname: {}", name1);

    let output = Command::new("signal-cli-client")
        .arg("-a")
        .arg("+15712811486")
        .arg("--json-rpc-tcp")
        .arg("127.0.0.1:7583")
        .arg("send")
        .arg("-g")
        .arg(&input.group_id)
        .arg("-m")
        .arg(&pseudo)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    let end_time = SystemTime::now();

    let start_time = match load_start_time("pseudo_msg") {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to load latency psuedo message start time: {}", e);
            return;
        }
    };

    if let Err(e) = append_timing_line_features("pseudo_msg", start_time, end_time) {
        eprintln!("Failed to write timing file for latency psuedo message: {}", e);
    }

    if let Err(e) = append_timing_line_verify("pseudo_msg", start_verify, end_verify) {
        eprintln!("❌ Failed to write timing file for peudo msg verify: {}", e);
    }
    
    match output {
        Ok(output) => {
            
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("Raw stdout from signal-cli-client: {}", stdout);

            let parsed: Value = serde_json::from_str(&stdout).unwrap();
            let ts = parsed["timestamp"].as_i64().unwrap();
            println!("Timestamp: {}", ts);

            let path = "server/zkpair_log.jsonl";
            let original_lines = read_to_string(path)
                .unwrap_or_default()
                .lines()
                .map(|s| s.to_string())
                .collect::<Vec<_>>();

            // Remove last line and parse callback
            assert!(original_lines.len() >= 1, "Expected at least one cb line before msg");

            let cb_line = &original_lines[original_lines.len() - 1];
            let cb_val: Value = serde_json::from_str(cb_line).unwrap();
            let cb = cb_val["callback_com"].as_str().unwrap();

            // Construct new line
            let new_entry = serde_json::json!({
                "timestamp": ts,
                "reputation": 0,
                "cb": cb,
            });

            // Combine previous lines (minus last) with new entry
            let mut all_entries = original_lines[..original_lines.len() - 1]
                .iter()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .collect::<Vec<_>>();

            all_entries.push(new_entry);

            // Optional: Sort by timestamp if you want strict time order
            all_entries.sort_by_key(|v| v["timestamp"].as_i64().unwrap_or(0));

            // Rewrite the file
            let mut file = File::create(path).unwrap();
            for entry in all_entries {
                writeln!(file, "{}", entry.to_string()).unwrap();
            }

            let stderr = String::from_utf8_lossy(&output.stderr);

            if output.status.success() {
                println!("Sent successfully: {}", stdout)
            } else {
                println!("Error sending: {}", stderr)
            } 
        }
        Err(e) => println!("Failed to spawn process: {:?}", e),
    }
}


pub async fn forward_jsonrpc_pseudo_rate(
    State(state): State<ServerLock>,
    Json(input): Json<JsonRpcInputPseudo>,
) -> impl IntoResponse {
    info!("[SERVER] Verifying arbitrary predicate...");

    let mut state2 = state.write().await;
    let vk = state2.keys.standard_pseudor_verifying_key.clone();
    let db = &mut state2.db;

    let mut reader = &input.proof[..];

    // Deserialize components in order
    let exec: ExecutedMethod<F, Snark, Args, Cr, 1> =
        ExecutedMethod::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes).unwrap();

    let pub_inputs: Vec<F> =
        Vec::<F>::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes).unwrap();

    let claimed = pub_inputs[1];
    info!("[SERVER] Claimed pseudonym: {}", claimed);
    let context = pub_inputs[0];
    info!("[SERVER] Context: {}", context);
    let i = pub_inputs[2];
    info!("[SERVER] i: {}", i);

    // let thread = &input.thread;

    let file = File::open("server/context.jsonl").expect("Failed to open file");
    let reader = BufReader::new(file);

    let mut matched_thread: Option<String> = None;
    for line in reader.lines() {
        let line = line.map_err(error_to_response).unwrap();
        if let Ok(entry) = serde_json::from_str::<ContextJson>(&line) {
            if entry.context == context.to_string() {
                info!("[SERVER] Context matched thread: {}", entry.thread);
                matched_thread = Some(entry.thread);
                break;
            }
        }
    }
    
    // Error if no match found
    let thread = matched_thread.ok_or_else(|| {
        error_to_response("Context not found in context.jsonl")
    }).unwrap();

    let pub_args = PseudonymArgsRate {
        context,
        claimed,
        i,
    };

    let start_verify=SystemTime::now();

    // Store the interaction to the object bulletin board
    let verify_store = <GRSchnorrObjStore as UserBul<F, MsgUser>>::verify_interact_and_append::<
        PseudonymArgsRate<F>,
        // F,
        Groth16<E>,
        1,
    >(
        &mut db.obj_bul,
        exec.new_object.clone(),
        exec.old_nullifier.clone(),
        // F::from(0),
        pub_args.clone(),
        exec.cb_com_list.clone(),
        exec.proof.clone(),
        None,
        &vk,
    )
    .unwrap();

    info!("[SERVER] Verification result: {:?}", verify_store);

    let cb_tickets = &exec.cb_tik_list.clone();
    
    // Store callback-reputation merged record
    let cb_methods = get_callbacks();
    let res = db
        .approve_interaction_and_store::<MsgUser, Groth16<E>, PseudonymArgsRate<F>, GRSchnorrObjStore, Poseidon<2>, 1>(
            exec,                 
            FakeSigPrivkey::sk(), 
            pub_args,
            &db.obj_bul.clone(),
            cb_methods.clone(),
            Time::from(0),
            db.obj_bul.get_pubkey(),
            true,
            &vk,
            332, // interaction number
        );

    let end_verify = SystemTime::now();

    info!("[SERVER] Verification result: {:?}", res);
    if res.is_ok() {
        info!("[SERVER] Verified and added to bulletin!");
    } else {
        info!("[SERVER] Verification failed. Not added to bulletin.");
    }

    // Write callback commitments to log file
    for (cb_com, _) in cb_tickets {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open("server/zkpair_log.jsonl")
            .unwrap();

        let mut bytes = vec![];
        cb_com
            .serialize_with_mode(&mut bytes, Compress::No)
            .unwrap();

        writeln!(
            file,
            "{{\"callback_com\": \"{}\", \"type\": \"cb\"}}",
            hex::encode(bytes)
        )
        .unwrap();
    }

    let claimed_bytes = claimed.into_bigint().to_bytes_le();
    let mut seed = [0u8; 32];
    seed[..claimed_bytes.len()].copy_from_slice(&claimed_bytes); // zero-pad to 32 bytes

    // Use as RNG seed
    let mut rng1 = StdRng::from_seed(seed);

    let g = Petnames::default();
    let name1 = g.generate(&mut rng1, 2, " ").expect("no name generated");

    let mut pseudo = String::from("FROM: ");
    pseudo.push_str(&name1);
    pseudo.push_str("\n\n");
    pseudo.push_str(&input.message);

    println!("Thread: {:?}", &thread);
    println!("Petname: {}", name1);

    let output = Command::new("signal-cli-client")
        .arg("-a")
        .arg("+15712811486")
        .arg("--json-rpc-tcp")
        .arg("127.0.0.1:7583")
        .arg("send")
        .arg("-g")
        .arg(&input.group_id)
        .arg("-m")
        .arg(&pseudo)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    let end_time = SystemTime::now();

    let start_time = match load_start_time("rate_pseudo") {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to load rate pseudo latency start time: {}", e);
            return;
        }
    };

    if let Err(e) = append_timing_line_features("rate_pseudo", start_time, end_time) {
        eprintln!("Failed to write timing file for latency rate pseudo: {}", e);
    }

    if let Err(e) = append_timing_line_verify("rate_pseudo", start_verify, end_verify) {
        eprintln!("❌ Failed to write timing file for rate pseudo verify: {}", e);
    }

    match output {
        Ok(output) => {
            
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("Raw stdout from signal-cli-client: {}", stdout);

            let parsed: Value = serde_json::from_str(&stdout).unwrap();
            let ts = parsed["timestamp"].as_i64().unwrap();
            println!("Timestamp: {}", ts);

            let path = "server/zkpair_log.jsonl";
            let original_lines = read_to_string(path)
                .unwrap_or_default()
                .lines()
                .map(|s| s.to_string())
                .collect::<Vec<_>>();

            // Remove last line and parse callback
            assert!(original_lines.len() >= 1, "Expected at least one cb line before msg");

            let cb_line = &original_lines[original_lines.len() - 1];
            let cb_val: Value = serde_json::from_str(cb_line).unwrap();
            let cb = cb_val["callback_com"].as_str().unwrap();

            // Construct new line
            let new_entry = serde_json::json!({
                "timestamp": ts,
                "reputation": 0,
                "cb": cb,
            });

            // Combine previous lines (minus last) with new entry
            let mut all_entries = original_lines[..original_lines.len() - 1]
                .iter()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .collect::<Vec<_>>();

            all_entries.push(new_entry);

            // Optional: Sort by timestamp if you want strict time order
            all_entries.sort_by_key(|v| v["timestamp"].as_i64().unwrap_or(0));

            // Rewrite the file
            let mut file = File::create(path).unwrap();
            for entry in all_entries {
                writeln!(file, "{}", entry.to_string()).unwrap();
            }

            let stderr = String::from_utf8_lossy(&output.stderr);

            if output.status.success() {
                println!("Sent successfully: {}", stdout)
            } else {
                println!("Error sending: {}", stderr)
            } 
        }
        Err(e) => println!("Failed to spawn process: {:?}", e),
    }
}


pub async fn pseudonym() -> impl IntoResponse {
    let petname = Petnames::default();
    let pseudo_given = petname.generate_one(1, "").unwrap();
    let pseudo_family = petname.generate_one(1, "").unwrap();

    let mut input = pseudo_family.clone();
    input.push_str(&pseudo_given);

    let avatar_path = std::env::current_dir().unwrap().join("avatar.png");

    let avatar_path_str = avatar_path.to_str().unwrap();

    let _ = Identicon::new(&input).save_image(&avatar_path_str);
    assert!(avatar_path.exists(), "avatar.png was not created");

    let output = Command::new("signal-cli-client")
        .arg("-a")
        .arg("+15712811486")
        .arg("--json-rpc-tcp")
        .arg("127.0.0.1:7583")
        .arg("updateProfile")
        .arg("--given-name")
        .arg(&pseudo_given)
        .arg("--family-name")
        .arg(&pseudo_family)
        .arg("--about")
        .arg("Anonymous User")
        .arg("--avatar")
        .arg(avatar_path_str)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            if output.status.success() {
                format!("Sent successfully: {}", stdout)
            } else {
                format!("Error sending: {}", stderr)
            }
        }
        Err(e) => format!("Failed to spawn process: {:?}", e),
    }
}

pub async fn forward_reaction(Json(input): Json<JsonRpcReact>) -> impl IntoResponse {
    // If "upvote" or "downvote" input as string, convert to an emoji 
    let emoji = string_to_emoji(&input.emoji);

    let output = Command::new("signal-cli-client")
        .arg("-a")
        .arg("+15712811486")
        .arg("--json-rpc-tcp")
        .arg("127.0.0.1:7583")
        .arg("send")
        .arg("-g")
        .arg(&input.group_id)
        .arg("-m")
        .arg(&emoji)
        .arg("--quote-timestamp")
        .arg(&input.timestamp.to_string())
        .arg("--quote-author")
        .arg("+15712811486")
        .arg("--quote-message")
        .arg("")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    let emoji_name = emoji_to_name(&emoji);

    match emoji_name {
        "upvote" => update_reaction_log(input.timestamp, 1).unwrap(), // increase reputation
        "downvote" => update_reaction_log(input.timestamp, -1).unwrap(), // decrement reputation
        "hatespeech" => println!("Hate speech flagged."),             // msg flagged for hate speech
        "ban" => println!("Ban suggested."),                          // anon user ban suggested
        "not ban" => println!("Do not ban suggested."), // suggestion to not ban anon user
        "unknown" => println!("Unknown emoji."),
        _ => (),
    }

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            if output.status.success() {
                format!("Sent successfully: {}", stdout)
            } else {
                format!("Error sending: {}", stderr)
            }
        }
        Err(e) => format!("Failed to spawn process: {:?}", e),
    }
}

pub async fn forward_reply(
    State(state): State<ServerLock>,
    Json(input): Json<JsonRpcReply>,
) -> impl IntoResponse {
    info!("[SERVER] Verifying and appending interaction...");

    let mut state2 = state.write().await;
    let vk = state2.keys.standard_verifying_key.clone();
    let db = &mut state2.db;

    let mut reader = &input.proof[..];
    let exec: ExecutedMethod<F, Snark, Args, Cr, 1> =
        ExecutedMethod::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes).unwrap();

    let verified =
        <GRSchnorrObjStore as UserBul<F, MsgUser>>::verify_interact_and_append::<F, Groth16<E>, 1>(
            &mut db.obj_bul,
            exec.new_object.clone(),
            exec.old_nullifier.clone(),
            F::from(0),
            exec.cb_com_list.clone(), 
            exec.proof.clone(),
            None,
            &vk,
        );

    let cb_tickets = &exec.cb_tik_list; // get callback tickets

    for (cb_com, _) in cb_tickets.iter() {

        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open("server/zkpair_log.jsonl")
            .unwrap();

        let mut bytes = vec![];
        cb_com
            .serialize_with_mode(&mut bytes, Compress::No)
            .unwrap();

        writeln!(
            file,
            "{{\"callback_com\": \"{}\", \"type\": \"cb\"}}",
            hex::encode(bytes)
        )
        .unwrap();
    }

    info!("[SERVER] Verification result: {:?}", verified);
    info!("[SERVER] Checking proof and storing interaction...");

    let cb_methods = get_callbacks();
    let res = db
        .approve_interaction_and_store::<MsgUser, Groth16<E>, F, GRSchnorrObjStore, Poseidon<2>, 1>(
            exec,                 // output of interaction
            FakeSigPrivkey::sk(), // for authenticity: verify rerandomization of key produces
            // proper tickets (here it doesn't matter)
            F::from(0),
            &db.obj_bul.clone(),
            cb_methods.clone(),
            Time::from(0),
            db.obj_bul.get_pubkey(),
            true,
            &vk,
            332, // interaction number
        );

    info!("[SERVER] Verification result: {:?}", res);
    if verified.is_ok() && res.is_ok() {
        info!("[SERVER] Verified and added to bulletin!");
    } else {
        info!("[SERVER] Verification failed. Not added to bulletin.");
    }

    let output = Command::new("signal-cli-client")
        .arg("-a")
        .arg("+15712811486")
        .arg("--json-rpc-tcp")
        .arg("127.0.0.1:7583")
        .arg("send")
        .arg("-g")
        .arg(&input.group_id)
        .arg("-m")
        .arg(&input.message)
        .arg("--quote-timestamp")
        .arg(&input.timestamp.to_string())
        .arg("--quote-author")
        .arg("+15712811486")
        .arg("--quote-message")
        .arg("")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    match output {
        Ok(output) => {
            
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("Raw stdout from signal-cli-client: {}", stdout);

            let parsed: Value = serde_json::from_str(&stdout).unwrap();
            let ts = parsed["timestamp"].as_i64().unwrap();
            println!("Timestamp: {}", ts);

            let path = "server/zkpair_log.jsonl";
            let original_lines = read_to_string(path)
                .unwrap_or_default()
                .lines()
                .map(|s| s.to_string())
                .collect::<Vec<_>>();

            // Remove last line and parse callback
            assert!(original_lines.len() >= 1, "Expected at least one cb line before msg");

            let cb_line = &original_lines[original_lines.len() - 1];
            let cb_val: Value = serde_json::from_str(cb_line).unwrap();
            let cb = cb_val["callback_com"].as_str().unwrap();

            // Construct new line
            let new_entry = serde_json::json!({
                "timestamp": ts,
                "reputation": 0,
                "cb": cb,
            });

            // Combine previous lines (minus last) with new entry
            let mut all_entries = original_lines[..original_lines.len() - 1]
                .iter()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .collect::<Vec<_>>();

            all_entries.push(new_entry);

            // Optional: Sort by timestamp if you want strict time order
            all_entries.sort_by_key(|v| v["timestamp"].as_i64().unwrap_or(0));

            // Rewrite the file
            let mut file = File::create(path).unwrap();
            for entry in all_entries {
                writeln!(file, "{}", entry.to_string()).unwrap();
            }

            let stderr = String::from_utf8_lossy(&output.stderr);

            if output.status.success() {
                println!("Sent successfully: {}", stdout)
            } else {
                println!("Error sending: {}", stderr)
            } 
        }
        Err(e) => println!("Failed to spawn process: {:?}", e),
    }
}

pub async fn forward_reply_pseudo(
    State(state): State<ServerLock>,
    Json(input): Json<JsonRpcReplyPseudo>,
) -> impl IntoResponse {
    info!("[SERVER] Verifying arbitrary predicate...");

    let mut state2 = state.write().await;
    let vk = state2.keys.standard_verifying_key.clone();
    let vki = state2.keys.pseudonym_pred_verifying_key.clone();
    let db = &mut state2.db;

    let mut reader = &input.proof[..];

    // Deserialize components in order
    let exec: ExecutedMethod<F, Snark, Args, Cr, 1> =
        ExecutedMethod::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes).unwrap();

    let proof = <Groth16<E> as SNARK<F>>::Proof::deserialize_with_mode(
        &mut reader,
        Compress::No,
        Validate::Yes,
    )
    .unwrap();

    let pub_inputs: Vec<F> =
        Vec::<F>::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes).unwrap();

    let verified = Groth16::<E>::verify(&vki, &pub_inputs, &proof).unwrap();

    info!("[SERVER] Verification result: {}", verified);

    let claimed = pub_inputs[1];
    info!("[SERVER] Claimed pseudonym: {}", claimed);

    // Store the interaction to the object bulletin board
    let verify_store =
        <GRSchnorrObjStore as UserBul<F, MsgUser>>::verify_interact_and_append::<F, Groth16<E>, 1>(
            &mut db.obj_bul,
            exec.new_object.clone(),
            exec.old_nullifier.clone(),
            F::from(0),
            exec.cb_com_list.clone(),
            exec.proof.clone(),
            None,
            &vk,
        )
        .unwrap();

    info!("[SERVER] Verification result: {:?}", verify_store);

    // Write callback commitments to log file
    for (cb_com, _) in &exec.cb_tik_list {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open("server/zkpair_log.jsonl")
            .unwrap();

        let mut bytes = vec![];
        cb_com
            .serialize_with_mode(&mut bytes, Compress::No)
            .unwrap();

        writeln!(
            file,
            "{{\"callback_com\": \"{}\", \"type\": \"cb\"}}",
            hex::encode(bytes)
        )
        .unwrap();
    }

    // Convert Fp to bytes (deterministic serialization)
    let claimed_bytes = claimed.into_bigint().to_bytes_le();
    let mut seed = [0u8; 32];
    seed[..claimed_bytes.len()].copy_from_slice(&claimed_bytes); // zero-pad to 32 bytes

    // Use as RNG seed
    let mut rng1 = StdRng::from_seed(seed);

    let g = Petnames::default();
    let name1 = g.generate(&mut rng1, 2, " ").expect("no name generated");

    let mut pseudo = String::from("FROM: ");
    pseudo.push_str(&name1);
    pseudo.push_str("\n\n");
    pseudo.push_str(&input.message);

    println!("Petname: {}", name1);

    let output = Command::new("signal-cli-client")
        .arg("-a")
        .arg("+15712811486")
        .arg("--json-rpc-tcp")
        .arg("127.0.0.1:7583")
        .arg("send")
        .arg("-g")
        .arg(&input.group_id)
        .arg("-m")
        .arg(&pseudo)
        .arg("--quote-timestamp")
        .arg(&input.timestamp.to_string())
        .arg("--quote-author")
        .arg("+15712811486")
        .arg("--quote-message")
        .arg("")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    match output {
        Ok(output) => {
            
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("Raw stdout from signal-cli-client: {}", stdout);

            let parsed: Value = serde_json::from_str(&stdout).unwrap();
            let ts = parsed["timestamp"].as_i64().unwrap();
            println!("Timestamp: {}", ts);

            let path = "server/zkpair_log.jsonl";
            let original_lines = read_to_string(path)
                .unwrap_or_default()
                .lines()
                .map(|s| s.to_string())
                .collect::<Vec<_>>();

            // Remove last line and parse callback
            assert!(original_lines.len() >= 1, "Expected at least one cb line before msg");

            let cb_line = &original_lines[original_lines.len() - 1];
            let cb_val: Value = serde_json::from_str(cb_line).unwrap();
            let cb = cb_val["callback_com"].as_str().unwrap();

            // Construct new line
            let new_entry = serde_json::json!({
                "timestamp": ts,
                "reputation": 0,
                "cb": cb,
            });

            // Combine previous lines (minus last) with new entry
            let mut all_entries = original_lines[..original_lines.len() - 1]
                .iter()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .collect::<Vec<_>>();

            all_entries.push(new_entry);

            // Optional: Sort by timestamp if you want strict time order
            all_entries.sort_by_key(|v| v["timestamp"].as_i64().unwrap_or(0));

            // Rewrite the file
            let mut file = File::create(path).unwrap();
            for entry in all_entries {
                writeln!(file, "{}", entry.to_string()).unwrap();
            }

            let stderr = String::from_utf8_lossy(&output.stderr);

            if output.status.success() {
                println!("Sent successfully: {}", stdout)
            } else {
                println!("Error sending: {}", stderr)
            } 
        }
        Err(e) => println!("Failed to spawn process: {:?}", e),
    }
}

pub async fn forward_poll(Json(input): Json<JsonRpcPoll>) -> impl IntoResponse {
    // Compose the poll message with a standard header and instructions
    let mut poll_message = String::from("📊 *Poll Time!*\n");
    poll_message.push_str("React with 👍 for *Yes*, 👎 for *No*\n\n");
    poll_message.push_str(&input.message);

    let output = Command::new("signal-cli-client")
        .arg("-a")
        .arg("+15712811486") // your fixed sending bot number
        .arg("--json-rpc-tcp")
        .arg("127.0.0.1:7583")
        .arg("send")
        .arg("-g")
        .arg(&input.group_id) // dynamic group id
        .arg("-m")
        .arg(&poll_message) // dynamic message
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    let context_str = generate_context_string::<F>();

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("Raw stdout from signal-cli-client: {}", stdout);

            // Step 0: Parse signal-cli-client output
            let parsed: serde_json::Value = match serde_json::from_str(&stdout) {
                Ok(val) => val,
                Err(e) => {
                    eprintln!("Failed to parse stdout as JSON: {}", e);
                    return format!("Error parsing output");
                }
            };
            let ts = parsed["timestamp"]
                .as_i64()
                .expect("Missing timestamp field");
            println!("Timestamp: {}", ts);

            let path = "server/poll_log.jsonl";

            // Step 1: Append new poll entry to last line of file
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .expect("Failed to open file for appending");

            // Step 2: Append the merged record
            let merged_entry = serde_json::json!({
                "timestamp": ts,
                "votes": [],
                "ban": 0,
                "context": context_str
            });
            writeln!(file, "{}", merged_entry).expect("Failed to write merged entry");

            // Optional: print stderr if any
            let stderr = String::from_utf8_lossy(&output.stderr);
            if output.status.success() {
                format!("Sent successfully: {}", stdout)
            } else {
                format!("Error sending: {}", stderr)
            }
        }
        Err(e) => format!("Failed to spawn process: {:?}", e),
    }
}

pub async fn forward_ban_poll(Json(input): Json<JsonRpcBanPoll>) -> impl IntoResponse {
    // Compose the poll message with a standard header and instructions
    let mut poll_message = String::from("📊 *Ban Poll Initiated*\n");
    poll_message.push_str("React with ❌ to *Ban* or ✅ to *Keep* this user.\n\n");
    poll_message.push_str("This poll was triggered because the following message may contain harmful, inappropriate, or spam content:\n\n");

    // Use the message if provided, otherwise fall back to a default
    let msg_text = input.message.as_deref().unwrap_or("");
    poll_message.push_str(msg_text);

    let output = Command::new("signal-cli-client")
        .arg("-a")
        .arg("+15712811486") // your fixed sending bot number
        .arg("--json-rpc-tcp")
        .arg("127.0.0.1:7583")
        .arg("send")
        .arg("-g")
        .arg(&input.group_id) // dynamic group id
        .arg("-m")
        .arg(&poll_message) // dynamic message
        .arg("--quote-timestamp")
        .arg(&input.timestamp.to_string())
        .arg("--quote-author")
        .arg("+15712811486")
        .arg("--quote-message")
        .arg("")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    let context_str = generate_context_string::<F>();

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("Raw stdout from signal-cli-client: {}", stdout);

            // Step 0: Parse signal-cli-client output
            let parsed: serde_json::Value = match serde_json::from_str(&stdout) {
                Ok(val) => val,
                Err(e) => {
                    eprintln!("Failed to parse stdout as JSON: {}", e);
                    return format!("Error parsing output");
                }
            };
            let ts = parsed["timestamp"]
                .as_i64()
                .expect("Missing timestamp field");
            println!("Timestamp: {}", ts);

            let path = "server/poll_log.jsonl";

            // Step 1: Append new poll entry to last line of file
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .expect("Failed to open file for appending");

            // Step 2: Append the merged record
            let merged_entry = serde_json::json!({
                "timestamp": ts,
                "votes": [],
                "ban": input.timestamp.clone(),
                "context": context_str
            });
            writeln!(file, "{}", merged_entry).expect("Failed to write merged entry");

            // Optional: print stderr if any
            let stderr = String::from_utf8_lossy(&output.stderr);
            if output.status.success() {
                format!("Sent successfully: {}", stdout)
            } else {
                format!("Error sending: {}", stderr)
            }
        }
        Err(e) => format!("Failed to spawn process: {:?}", e),
    }
}

pub async fn forward_vote(
    State(state): State<ServerLock>,
    Json(input): Json<JsonRpcVote>,
) -> impl IntoResponse {
    let vki = state
        .write()
        .await
        .keys
        .pseudonym_pred_verifying_key
        .clone();

    let claimed_str = &input.claimed;

    // Use fully-qualified syntax to access BigInt
    let claimed_bigint =
        <F as PrimeField>::BigInt::from_str(claimed_str).expect("Invalid claimed string");
    let claimed_fp = F::from_bigint(claimed_bigint).expect("Failed to convert to field element");
    // Convert field element to bytes
    let claimed_bytes = claimed_fp.into_bigint().to_bytes_le(); // or to_bytes_be()

    // Create a 32-byte seed from the field element bytes
    let mut seed = [0u8; 32];
    let copy_len = claimed_bytes.len().min(32);
    seed[..copy_len].copy_from_slice(&claimed_bytes[..copy_len]);

    // Use as RNG seed
    let mut rng1 = StdRng::from_seed(seed);

    let g = Petnames::default();
    let name1 = g.generate(&mut rng1, 2, " ").expect("no name generated");

    // Pseudo proof
    let mut reader = &input.proof[..];

    let proof = <Groth16<E> as SNARK<F>>::Proof::deserialize_with_mode(
        &mut reader,
        Compress::No,
        Validate::Yes,
    )
    .unwrap();

    let pub_inputs: Vec<F> =
        Vec::<F>::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes).unwrap();

    let start_verify = SystemTime::now();

    let verified = Groth16::<E>::verify(&vki, &pub_inputs, &proof).unwrap();

    let end_verify= SystemTime::now();

    info!("Server result: {}", verified);

    // If "upvote", "downvote", "ban", "not ban" is input as string, convert to an emoji 
    let emoji = string_to_emoji(&input.emoji);

    let mut pseudo = String::from("VOTE FROM: ");
    pseudo.push_str(&name1);
    pseudo.push_str("\n\n");
    pseudo.push_str(emoji);

    let output = Command::new("signal-cli-client")
        .arg("-a")
        .arg("+15712811486")
        .arg("--json-rpc-tcp")
        .arg("127.0.0.1:7583")
        .arg("send")
        .arg("-g")
        .arg(&input.group_id)
        .arg("-m")
        .arg(pseudo)
        .arg("--quote-timestamp")
        .arg(&input.timestamp.to_string())
        .arg("--quote-author")
        .arg("+15712811486")
        .arg("--quote-message")
        .arg("")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    let end_time = SystemTime::now();

    let start_time = match load_start_time("pseudo_vote") {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to load latency psuedo vote start time: {}", e);
            return;
        }
    };

    if let Err(e) = append_timing_line_features("pseudo_vote", start_time, end_time) {
        eprintln!("Failed to write timing file for latency psuedo vote: {}", e);
    }

    if let Err(e) = append_timing_line_verify("pseudo_vote", start_verify, end_verify) {
        eprintln!(" Failed to write timing file for pseudo vote verify: {}", e);
    }

    let emoji_name = emoji_to_name(emoji);

    match emoji_name {
        "upvote" | "downvote" | "ban" | "not ban" => {
            append_vote(input.timestamp, &name1, input.claimed.clone(), emoji)
                .expect("Failed to append vote");
        }
        "hatespeech" => {
            println!("Hate speech flagged.");
        }
        "unknown" => {
            println!("Unknown emoji.");
        }
        _ => (),
    }

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            if output.status.success() {
                println!("Sent successfully: {}", stdout)
            } else {
                println!("Error sending: {}", stderr)
            }
        }
        Err(e) => println!("Failed to spawn process: {:?}", e),
    }
}

pub async fn forward_vote_count(Json(input): Json<JsonRpcCountVotes>) -> impl IntoResponse {
    let ts = input.timestamp.try_into().unwrap();

    let (yes, no) = count_votes_by_timestamp(ts);
    let is_ban = is_ban_poll_by_timestamp(ts);

    let total = yes + no;
    let percent = |count| {
        if total == 0 {
            0.0
        } else {
            (count as f64 / total as f64) * 100.0
        }
    };

    // Compose the poll message
    let mut result_message = String::from("📊 *The Results are in!*\n\n");

    if is_ban {
        result_message.push_str("React with ❌ to *Ban* or ✅ to *Keep* this user.\n\n");
        result_message.push_str(&format!(
            "❌ Ban: {} ({:.1}%)\n✅ Keep: {} ({:.1}%)\n",
            yes,
            percent(yes),
            no,
            percent(no)
        ));
    } else {
        result_message.push_str("React with 👍 for *Yes*, 👎 for *No*.\n\n");
        result_message.push_str(&format!(
            "👍 Yes: {} ({:.1}%)\n👎 No: {} ({:.1}%)\n",
            yes,
            percent(yes),
            no,
            percent(no)
        ));
    }

    // Add total and outcome summary
    result_message.push_str(&format!("\n🧮 Total votes: {}\n", total));

    if total == 0 {
        result_message.push_str("⚠️ No votes yet.");
    } else if yes > no {
        let summary = if is_ban {
            "🔨 Majority voted to *Ban*."
        } else {
            "✅ Majority voted *Yes*."
        };
        result_message.push_str(summary);
    } else if no > yes {
        let summary = if is_ban {
            "🛡️ Majority voted to *Keep* the user."
        } else {
            "❌ Majority voted *No*."
        };
        result_message.push_str(summary);
    } else {
        result_message.push_str("🤷 It's a tie!");
    }

    let output = Command::new("signal-cli-client")
        .arg("-a")
        .arg("+15712811486") // your fixed sending bot number
        .arg("--json-rpc-tcp")
        .arg("127.0.0.1:7583")
        .arg("send")
        .arg("-g")
        .arg(&input.group_id) // dynamic group id
        .arg("-m")
        .arg(result_message) // dynamic message
        .arg("--quote-timestamp")
        .arg(&input.timestamp.to_string())
        .arg("--quote-author")
        .arg("+15712811486")
        .arg("--quote-message")
        .arg("")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    if yes > no && is_ban {
        if let Some(ban_flag) = get_ban_from_timestamp(input.timestamp.try_into().unwrap()) {
            if ban_flag >= 0 {
                // Fix this later --> server cannot call client-side function in this way
                // let timestamp = ban_flag as u64;
                // tokio::task::spawn_blocking(move || {
                //     if let Err(e) = ban(timestamp) {
                //         eprintln!("Ban error: {:?}", e);
                //     }
                // });
            }
        } else {
            eprintln!("No ban flag found for timestamp {}", input.timestamp);
        }
    }

    if total != 0 {
        if let Err(e) = delete_poll_entry_by_timestamp(input.timestamp) {
            eprintln!(
                "Failed to delete poll entry for timestamp {}: {}",
                input.timestamp, e
            );
        }
        let _ = delete_poll_pseudo_entry_by_timestamp(input.timestamp);
    }

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            if output.status.success() {
                format!("Vote count done successfully: {}", stdout)
            } else {
                format!("Error sending poll: {}", stderr)
            }
        }
        Err(e) => format!("Failed to spawn process: {:?}", e),
    }
}

pub fn emoji_to_name(emoji: &str) -> &'static str {
    if emoji.starts_with("👍") {
        "upvote"
    } else if emoji.starts_with("👎") {
        "downvote"
    } else {
        match emoji {
            "🤬" => "hatespeech",
            "❌" => "ban",
            "✅" => "not ban",
            _ => "unknown",
        }
    }
}

pub fn string_to_emoji(input: &str) -> &str {
    // Return emoji if input is emoji.
    // Just for different variations of thumbs up and thumbs down.
    if input.starts_with("👍") {
        return input;
    } else if input.starts_with("👎") {
        return input;
    }

    match input {
        // Return emoji if input is emoji.
        "🤬" | "❌" | "✅" => input,
        // Named commands to emojis
        "upvote" => "👍",
        "downvote" => "👎",
        "hatespeech" => "🤬",
        "ban" => "❌",
        "not ban" => "✅",
        _ => "❓",
    }
}

#[tracing::instrument(skip_all)]
pub async fn forward_authorship(
    State(state): State<ServerLock>,
    Json(input): Json<JsonAuthorship>,
) -> impl IntoResponse {
    let vki = state
        .write()
        .await
        .keys
        .authorship_pred_verifying_key
        .clone();

    let mut reader = &input.proof[..];

    let proof = <Groth16<E> as SNARK<F>>::Proof::deserialize_with_mode(
        &mut reader,
        Compress::No,
        Validate::Yes,
    )
    .unwrap();

    let pub_inputs: Vec<F> =
        Vec::<F>::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes).unwrap();


    let start_verify = SystemTime::now();

    let verified = Groth16::<E>::verify(&vki, &pub_inputs, &proof).unwrap();

    let end_verify = SystemTime::now();

    info!("[SERVER] Verification result: {}", verified);

    let claimed1 = pub_inputs[0];
    let claimed2 = pub_inputs[2];

    // Generate petname for claimed1
    let bytes1 = claimed1.into_bigint().to_bytes_le();
    let mut seed1 = [0u8; 32];
    seed1[..bytes1.len()].copy_from_slice(&bytes1[..]);
    let mut rng1 = StdRng::from_seed(seed1);

    let g = Petnames::default();
    let name1 = g.generate(&mut rng1, 2, " ").expect("no name generated");

    // Generate petname for claimed2
    let bytes2 = claimed2.into_bigint().to_bytes_le();
    let mut seed2 = [0u8; 32];
    seed2[..bytes2.len()].copy_from_slice(&bytes2[..]);
    let mut rng2 = StdRng::from_seed(seed2);

    let name2 = g.generate(&mut rng2, 2, " ").expect("no name generated");

    let mut message = String::new();
    message.push_str("CLAIMED AUTHORSHIP INITIATED\n\n");
    message.push_str("This message proves that the following two pseudonyms belong to the same anonymous user:\n\n");
    message.push_str(&format!("• {}\n• {}\n\n", name1, name2));
    message.push_str("This demonstrates authorship continuity without revealing identity.\n\n");

    println!("Claimed authorship message:\n{}", message);

    let output = Command::new("signal-cli-client")
        .arg("-a")
        .arg("+15712811486") // fixed anon bot number
        .arg("--json-rpc-tcp")
        .arg("127.0.0.1:7583")
        .arg("send")
        .arg("-g")
        .arg(&input.group_id)
        .arg("-m")
        .arg(&message)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    let end_time = SystemTime::now();

    let start_time = match load_start_time("author") {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to load latency author start time: {}", e);
            return;
        }
    };

    if let Err(e) = append_timing_line_features("author", start_time, end_time) {
        eprintln!("Failed to write timing file for latency author: {}", e);
    }

    if let Err(e) = append_timing_line_verify("author", start_verify, end_verify) {
        eprintln!(" Failed to write timing file for author verify: {}", e);
    }

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            if output.status.success() {
                println!("Sent successfully: {}", stdout)
            } else {
                println!("Error sending: {}", stderr)
            }
        }
        Err(e) => println!("Failed to spawn process: {:?}", e),
    }
}

#[tracing::instrument(skip_all)]
pub async fn forward_badges(
    State(state): State<ServerLock>,
    Json(input): Json<JsonBadge>,
) -> impl IntoResponse {
    let vki = state.write().await.keys.badge_pred_verifying_key.clone();

    let mut reader = &input.proof[..];

    let proof = <Groth16<E> as SNARK<F>>::Proof::deserialize_with_mode(
        &mut reader,
        Compress::No,
        Validate::Yes,
    )
    .unwrap();

    let pub_inputs: Vec<F> =
        Vec::<F>::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes).unwrap();

    let start_verify = SystemTime::now();

    let verified = Groth16::<E>::verify(&vki, &pub_inputs, &proof).unwrap();

    let end_verify = SystemTime::now();

    info!("[SERVER] Verification result: {}", verified);

    let badge_str = pub_inputs[1].to_string();

    let mut message = String::new();
    message.push_str("CLAIMED BADGE INITIATED\n\n");
    message.push_str("This message demonstrates that the following badge belongs to anonymous user:\n\n");
    message.push_str(&badge_str);

    let output = Command::new("signal-cli-client")
        .arg("-a")
        .arg("+15712811486")
        .arg("--json-rpc-tcp")
        .arg("127.0.0.1:7583")
        .arg("send")
        .arg("-g")
        .arg(&input.group_id)
        .arg("-m")
        .arg(&message)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    let end_time = SystemTime::now();

    let start_time = match load_start_time("badge") {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to load latency badge start time: {}", e);
            return;
        }
    };
    
    if let Err(e) = append_timing_line_features("badge", start_time, end_time) {
        eprintln!("Failed to write timing file for latency badge: {}", e);
    }

    if let Err(e) = append_timing_line_verify("badge", start_verify, end_verify) {
        eprintln!(" Failed to write timing file for badge verify: {}", e);
    }

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            if output.status.success() {
                println!("Sent successfully: {}", stdout)
            } else {
                println!("Error sending: {}", stderr)
            }
        }
        Err(e) => println!("Failed to spawn process: {:?}", e),
    }
}

pub async fn forward_context_ts(Json(payload): Json<TimestampRequest>) -> Response {
    match get_context_from_timestamp(payload.timestamp) {
        Some(context) => {
            let response = ContextResponse { context };
            Json(response).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "No context found for that timestamp"
            })),
        )
            .into_response(),
    }
}

/// Generate a random field element and return it as a string.
pub fn generate_context_string<F: PrimeField + UniformRand>() -> String {
    let mut rng = OsRng;
    let context: F = F::rand(&mut rng);
    context.into_bigint().to_string()
}

#[tracing::instrument(skip_all)]
pub async fn handle_user_join(
    State(state): State<ServerLock>,
    payload: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    info!("[SERVER] handle_user_join called!");

    let mut cursor = std::io::Cursor::new(payload);
    let object = Com::<F>::deserialize_with_mode(&mut cursor, Compress::No, Validate::Yes)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut server = state.write().await;

    let result = <SigObjStore<F, GrumpkinSchnorr> as JoinableBulletin<F, MsgUser>>::join_bul(
        &mut server.db.obj_bul,
        object,
        (),
    );

    match result {
        Ok(()) => Ok(StatusCode::OK),
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

#[tracing::instrument(skip_all)]
pub async fn handle_get_standard_proving_key(
    State(state): State<ServerLock>,
) -> Result<Bytes, ErrorResponse> {
    info!("[GET] Standard proving key");
    let mut keybuf = Vec::new();
    state
        .read()
        .await
        .keys
        .standard_proving_key
        .serialize_with_mode(&mut keybuf, Compress::No)
        .map_err(error_to_response)?;

    Ok(keybuf.into())
}

#[tracing::instrument(skip_all)]
pub async fn handle_get_standard_pseudo_proving_key(
    State(state): State<ServerLock>,
) -> Result<Bytes, ErrorResponse> {
    info!("[GET] Standard pseudo proving key");
    let mut keybuf = Vec::new();
    state
        .read()
        .await
        .keys
        .standard_pseudo_proving_key
        .serialize_with_mode(&mut keybuf, Compress::No)
        .map_err(error_to_response)?;

    Ok(keybuf.into())
}

#[tracing::instrument(skip_all)]
pub async fn handle_get_standard_pseudor_proving_key(
    State(state): State<ServerLock>,
) -> Result<Bytes, ErrorResponse> {
    info!("[GET] Standard pseudo proving key");
    let mut keybuf = Vec::new();
    state
        .read()
        .await
        .keys
        .standard_pseudor_proving_key
        .serialize_with_mode(&mut keybuf, Compress::No)
        .map_err(error_to_response)?;

    Ok(keybuf.into())
}

#[tracing::instrument(skip_all)]
pub async fn handle_get_scan_proving_key(
    State(state): State<ServerLock>,
) -> Result<Bytes, ErrorResponse> {
    info!("[GET] Scan proving key");
    let mut keybuf = Vec::new();
    state
        .read()
        .await
        .keys
        .scan_proving_key
        .serialize_with_mode(&mut keybuf, Compress::No)
        .map_err(error_to_response)?;

    Ok(keybuf.into())
}

#[tracing::instrument(skip_all)]
pub async fn handle_get_arbitrary_pred_proving_key(
    State(state): State<ServerLock>,
) -> Result<Bytes, ErrorResponse> {
    info!("[GET] Standard proving key");
    let mut keybuf = Vec::new();
    state
        .read()
        .await
        .keys
        .pseudonym_pred_proving_key
        .serialize_with_mode(&mut keybuf, Compress::No)
        .map_err(error_to_response)?;

    Ok(keybuf.into())
}

#[tracing::instrument(skip_all)]
pub async fn handle_get_arbitrary_pred_proving_key2(
    State(state): State<ServerLock>,
) -> Result<Bytes, ErrorResponse> {
    info!("[GET] Standard proving key");
    let mut keybuf = Vec::new();
    state
        .read()
        .await
        .keys
        .authorship_pred_proving_key
        .serialize_with_mode(&mut keybuf, Compress::No)
        .map_err(error_to_response)?;

    Ok(keybuf.into())
}

#[tracing::instrument(skip_all)]
pub async fn handle_get_arbitrary_pred_proving_key3(
    State(state): State<ServerLock>,
) -> Result<Bytes, ErrorResponse> {
    info!("[GET] Standard proving key");
    let mut keybuf = Vec::new();
    state
        .read()
        .await
        .keys
        .badge_pred_proving_key
        .serialize_with_mode(&mut keybuf, Compress::No)
        .map_err(error_to_response)?;

    Ok(keybuf.into())
}

#[tracing::instrument(skip_all)]
pub async fn handle_get_user_pubkey(
    State(state): State<ServerLock>,
) -> Result<Bytes, ErrorResponse> {
    info!("[GET] Get pubkey");
    let mut buf = Vec::new();
    state
        .read()
        .await
        .db
        .obj_bul
        .get_pubkey()
        .serialize_with_mode(&mut buf, Compress::No)
        .map_err(error_to_response)?;
    Ok(buf.into())
}

#[tracing::instrument(skip_all)]
pub async fn handle_get_membership_pubkey(
    State(state): State<ServerLock>,
) -> Result<Bytes, ErrorResponse> {
    info!("[GET] Callback membership pubkey");
    let mut keybuf = Vec::new();
    state
        .read()
        .await
        .db
        .callback_bul
        .get_pubkey()
        .serialize_with_mode(&mut keybuf, Compress::No)
        .map_err(error_to_response)?;

    Ok(keybuf.into())
}

#[tracing::instrument(skip_all)]
pub async fn handle_get_nonmembership_pubkey(
    State(state): State<ServerLock>,
) -> Result<Bytes, ErrorResponse> {
    info!("[GET] Callback nonmembership pubkey");
    let mut keybuf = Vec::new();
    state
        .read()
        .await
        .db
        .callback_bul
        .nmemb_bul
        .get_pubkey()
        .serialize_with_mode(&mut keybuf, Compress::No)
        .map_err(error_to_response)?;

    Ok(keybuf.into())
}

#[tracing::instrument(skip_all)]
pub async fn handle_get_user_bulletin(
    State(state): State<ServerLock>,
) -> Result<Bytes, ErrorResponse> {
    info!("[GET] User bulletin");
    let mut keybuf = Vec::new();
    state
        .read()
        .await
        .db
        .obj_bul
        .get_db()
        .serialize_with_mode(&mut keybuf, Compress::No)
        .map_err(error_to_response)?;

    Ok(keybuf.into())
}

#[tracing::instrument(skip_all)]
pub async fn handle_get_callback_bulletin(
    State(state): State<ServerLock>,
) -> Result<Bytes, ErrorResponse> {
    info!("[GET] Callback membership bulletin");
    let mut keybuf = Vec::new();
    state
        .read()
        .await
        .db
        .callback_bul
        .get_db()
        .serialize_with_mode(&mut keybuf, Compress::No)
        .map_err(error_to_response)?;

    Ok(keybuf.into())
}

#[tracing::instrument(skip_all)]
pub async fn handle_get_callback_nmemb_bulletin(
    State(state): State<ServerLock>,
) -> Result<Bytes, ErrorResponse> {
    info!("[GET] Callback nonmembership bulletin");
    let mut keybuf = Vec::new();
    state
        .read()
        .await
        .db
        .callback_bul
        .nmemb_bul
        .get_db()
        .serialize_with_mode(&mut keybuf, Compress::No)
        .map_err(error_to_response)?;

    Ok(keybuf.into())
}

#[tracing::instrument(skip_all)]
pub async fn handle_verify_arb_pred(
    State(state): State<ServerLock>,
    body: Bytes,
) -> impl IntoResponse {
    info!("[SERVER] Verifying arbitrary predicate...");

    let mut reader = &body[..];
    let proof = <Groth16<E> as SNARK<F>>::Proof::deserialize_with_mode(
        &mut reader,
        Compress::No,
        Validate::Yes,
    )
    .unwrap();
    let pub_inputs: Vec<F> =
        Vec::<F>::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes).unwrap();
    let vki: &VerifyingKey<E> = &state.read().await.keys.pseudonym_pred_verifying_key;

    let verified = Groth16::<E>::verify(vki, &pub_inputs, &proof).unwrap();

    info!("[SERVER] Verification result: {}", verified);
}

#[tracing::instrument(skip_all)]
pub async fn handle_get_posts_standard(
    State(state): State<ServerLock>,
    body: Bytes,
) -> impl IntoResponse {
    info!("[SERVER] Verifying and appending interaction...");

    let mut state2 = state.write().await;
    let vk = state2.keys.standard_verifying_key.clone();
    let db = &mut state2.db;

    let mut reader = &body[..];
    let exec: ExecutedMethod<F, Snark, Args, Cr, 1> =
        ExecutedMethod::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes).unwrap();

    let verified =
        <GRSchnorrObjStore as UserBul<F, MsgUser>>::verify_interact_and_append::<F, Groth16<E>, 1>(
            &mut db.obj_bul,
            exec.new_object.clone(),
            exec.old_nullifier.clone(),
            F::from(0),
            exec.cb_com_list.clone(),
            exec.proof.clone(),
            None,
            &vk,
        );

    let cb_tickets = &exec.cb_tik_list; // get callback tickets

    for (cb_com, _) in cb_tickets.iter() {
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open("server/zkpair_log.jsonl")
            .unwrap();

        let mut bytes = vec![];
        cb_com
            .serialize_with_mode(&mut bytes, Compress::No)
            .unwrap();

        writeln!(
            file,
            "{{\"callback_com\": \"{}\", \"type\": \"cb\"}}",
            hex::encode(bytes)
        )
        .unwrap();
    }

    info!("[SERVER] Verification result: {:?}", verified);
    info!("[SERVER] Checking proof and storing interaction...");

    let cb_methods = get_callbacks();
    let res = db
        .approve_interaction_and_store::<MsgUser, Groth16<E>, F, GRSchnorrObjStore, Poseidon<2>, 1>(
            exec,                 // output of interaction
            FakeSigPrivkey::sk(), // for authenticity: verify rerandomization of key produces
            // proper tickets (here it doesn't matter)
            F::from(0),
            &db.obj_bul.clone(),
            cb_methods.clone(),
            Time::from(0),
            db.obj_bul.get_pubkey(),
            true,
            &vk,
            332, // interaction number
        );

    info!("[SERVER] Verification result: {:?}", res);
    if verified.is_ok() && res.is_ok() {
        info!("[SERVER] Verified and added to bulletin!");
    } else {
        info!("[SERVER] Verification failed. Not added to bulletin.");
    }
}

#[tracing::instrument(skip_all)]
pub async fn handle_get_posts_scan(
    State(state): State<ServerLock>,
    body: Bytes,
) -> impl IntoResponse {
    info!("[BULLETIN / SERVER] Verifying and storing scan...");

    let mut state2 = state.write().await;
    let vk = state2.keys.scan_verifying_key.clone(); // clone only small verifying key
    let db = &mut state2.db; // after cloning needed stuff, now safe to borrow mutably

    let mut reader = &body[..];
    let scan_one: ExecutedMethod<F, Snark, Args, Cr, 0> =
        ExecutedMethod::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes).unwrap();

    let memb_pub = db.callback_bul.get_pubkey();
    let nmemb_pub = db.callback_bul.nmemb_bul.get_pubkey();
    let ps = get_extra_pubdata_for_scan2(&db.callback_bul, memb_pub, nmemb_pub, F::from(0));

    let verified = <GRSchnorrObjStore as UserBul<F, MsgUser>>::verify_interact_and_append::<
        PubScan,
        Groth16<E>,
        0,
    >(
        &mut db.obj_bul,
        scan_one.new_object.clone(),
        scan_one.old_nullifier.clone(),
        ps.clone(),
        scan_one.cb_com_list.clone(),
        scan_one.proof.clone(),
        None,
        &vk,
    );

    let cb_methods = get_callbacks();

    let res = db
    .approve_interaction_and_store::<MsgUser, Groth16<E>, PubScan, GRSchnorrObjStore, Poseidon<2>, 0>(
        scan_one,
        FakeSigPrivkey::sk(),
        ps.clone(),
        &db.obj_bul.clone(),
        cb_methods.clone(),
        db.callback_bul.get_epoch(),
        db.obj_bul.get_pubkey(),
        true,
        &vk,
        442,
    );

    info!(
        "[BULLETIN] Checking proof and storing new user... Output: {:?}",
        verified
    );
    info!(
        "[SERVER] Checking proof for first scan... Output: {:?}",
        res
    );

    if verified.is_ok() && res.is_ok() {
        info!("[SERVER] Scan verified and user successfully stored!");
    } else {
        info!("[SERVER] Scan verification and storage failed.");
    }
    (StatusCode::OK, "Scan verified")
}

#[tracing::instrument(skip_all)]
pub async fn handle_send_ban_request(
    State(state): State<ServerLock>,
    bytes: Bytes,
) -> impl IntoResponse {
    info!("[SERVER] Banning user...");
    let db = &mut state.write().await.db;
    let mut rng = rand::thread_rng();

    let cb: CallbackCom<Fr, Fr, PlainTikCrypto<Fr>> =
        CanonicalDeserialize::deserialize_with_mode(&bytes[..], Compress::No, Validate::Yes)
            .expect("Deserialization failed");

    let arg = arg_ban();
    let called = db.call(cb, arg, FakeSigPrivkey::sk()).unwrap();

    <GRSchnorrCallbackStore<Fr> as CallbackBul<Fr, Fr, Cr>>::verify_call_and_append(
        &mut db.callback_bul,
        called.0,
        called.1,
        called.2,
        Time::from(0),
    )
    .unwrap();

    db.callback_bul.update_epoch(&mut rng);
    info!("[SERVER] Banned");
}

#[tracing::instrument(skip_all)]
pub async fn handle_send_rep_request(
    State(state): State<ServerLock>,
    bytes: Bytes,
) -> impl IntoResponse {
    info!("[SERVER] Updating user reputation...");
    let db = &mut state.write().await.db;
    let mut rng = rand::thread_rng();

    let cb: CallbackCom<Fr, Fr, PlainTikCrypto<Fr>> =
        CanonicalDeserialize::deserialize_with_mode(&bytes[..], Compress::No, Validate::Yes)
            .expect("Deserialization failed");

    let cb_hex = hex::encode(&bytes);
    let rep = get_reputation_by_cb(&cb_hex).unwrap();
    println!("{:?}", &rep);
    let arg = arg_rep(rep);
    let called = db.call(cb, arg, FakeSigPrivkey::sk()).unwrap();


    // Start time verify for rep
    let start_call  = SystemTime::now();

    <GRSchnorrCallbackStore<Fr> as CallbackBul<Fr, Fr, Cr>>::verify_call_and_append(
        &mut db.callback_bul,
        called.0,
        called.1,
        called.2,
        Time::from(0),
    )
    .unwrap();
    // end time verify for rep
    let end_call = SystemTime::now();

    // start update epoch time
    let start_epoch  = SystemTime::now();

    db.callback_bul.update_epoch(&mut rng);
    info!("[SERVER] User reputation now updated!");

    // end update epoch time 
    let end_epoch = SystemTime::now();

    if let Err(e) = append_timing_line_call_cb("rep", start_call, end_call) {
        eprintln!("Failed to write timing file for proof gen: {}", e);
    }

    if let Err(e) = append_timing_line_epoch("rep", start_epoch, end_epoch) {
        eprintln!("Failed to write timing file for proof gen: {}", e);
    }
}

#[tracing::instrument(skip_all)]
pub async fn forward_callback(Json(input): Json<TimestampInput>) -> impl IntoResponse {
    match find_callback_by_timestamp(input.timestamp) {
        Ok(cb_bytes) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/octet-stream")
            .body(cb_bytes.into())
            .unwrap(),
        Err(e) => {
            tracing::warn!("Callback retrieval failed: {:?}", e);
            (StatusCode::NOT_FOUND, e.to_string()).into_response()
        }
    }
}

#[tracing::instrument(skip_all)]
pub async fn handle_post_context_and_store(
    State(_state): State<ServerLock>,
    Json(input): Json<ContextRequest>,
) -> Result<Bytes, ErrorResponse> {

     // Check if thread already exists
     if let Ok(file) = File::open("server/context.jsonl") {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line.map_err(error_to_response)?;
            if let Ok(existing) = serde_json::from_str::<ContextJson>(&line) {
                if existing.thread == input.thread {
                    // Already exists — return the existing entry
                    let response = serde_json::to_string(&existing).map_err(error_to_response)?;
                    return Ok(Bytes::from(response));
                }
            }
        }
    }

    // 1. Generate a random field element
    let mut rng = OsRng;
    let context = F::rand(&mut rng);
    let context_str = context.into_bigint().to_string();

    // 2. Create the JSON object
    let json_obj = ContextJson {
        thread: input.thread.clone(),
        context: context_str,
    };

    // 3. Convert to a single JSON line
    let json_line = serde_json::to_string(&json_obj)
        .map_err(error_to_response)?
        + "\n";

    // 4. Append to file
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("server/context.jsonl")
        .map_err(error_to_response)?;
    file.write_all(json_line.as_bytes())
        .map_err(error_to_response)?;

    // 5. Return JSON response
    Ok(Bytes::from(json_line))
}

#[tracing::instrument(skip_all)]
pub async fn handle_get_all_contexts(
    State(_state): State<ServerLock>,
) -> Result<Bytes, ErrorResponse> {
    let content = std::fs::read_to_string("server/context.jsonl").map_err(error_to_response)?;
    Ok(Bytes::from(content))
}
