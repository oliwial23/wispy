pub mod parse;

use crate::parse::{Cli, Command};

use std::{
    fs::File,
    io::Write,
    str::FromStr,
    time::SystemTime,
    usize,
};
use ark_ff::{BigInteger256, PrimeField};
use ark_std::result::Result::Ok;
use clap::Parser;
use client::helpers::{
    append_timing_line_features, ban, compute_pseudo_for_poll, gen_cb_for_msg, gen_pseudo, get_claimed_context_by_index,
    join2, list_all_pseudos_from_log, lookup_context, make_authorship_proof, make_badge_proof, prf2,
    pseudo_proof_vote, pseudo_proof_with_msg, rate_pseudo_proof_with_msg, rep, save_start_time, scan, string_to_f,
};
use common::F;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::task::spawn_blocking;


#[derive(Serialize)]
pub struct JsonRpcInput {
    message: String,
    group_id: String,
    proof: Vec<u8>,
}

#[derive(Serialize)]
pub struct JsonRpcInputPseudo {
    message: String,
    group_id: String,
    proof: Vec<u8>,
}

#[derive(Serialize)]
pub struct JsonRpcReact {
    group_id: String,
    emoji: String,
    timestamp: u64,
}

#[derive(Serialize)]
pub struct JsonRpcReply {
    group_id: String,
    message: String,
    timestamp: u64,
    proof: Vec<u8>,
}

#[derive(Serialize)]
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

#[derive(Serialize)]
pub struct JsonRpcPoll {
    message: String,
    group_id: String,
}

#[derive(Serialize)]
pub struct JsonRpcBanPoll {
    message: Option<String>,
    group_id: String,
    timestamp: u64,
}

#[derive(Serialize)]
pub struct JsonRpcCountVotes {
    group_id: String,
    timestamp: u64,
}

#[derive(Serialize)]
pub struct JsonAuthorship {
    proof: Vec<u8>,
    group_id: String,
}

#[derive(Serialize)]
pub struct JsonBadge {
    proof: Vec<u8>,
    group_id: String,

}

#[derive(Deserialize)]
struct ContextResponse {
    context: String,
}

#[derive(Serialize, Deserialize)]
pub struct ContextRequest {
    thread: String,
}

#[derive(Serialize, Deserialize)]
pub struct ContextJson {
    thread: String,
    context: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let client = Client::new();
    match cli.command {
        Command::ViewPosts => {
            println!("Fetching posts...");
        }
        
        Command::Post { message, group_id } => {      

            match spawn_blocking(|| gen_cb_for_msg()).await {
                Ok(Ok(proof_bytes)) => {

                    let payload = JsonRpcInput {
                        message,
                        group_id,
                        proof: proof_bytes, 
                    };
        
                    if let Err(e) = save_start_time("3") {
                        eprintln!("Failed to save start time: {}", e);
                    }

                    let res = client
                        .post("http://127.0.0.1:3000/api/jsonrpc")
                        .json(&payload)
                        .send()
                        .await
                        .unwrap();

                    println!("Server responded: {}", res.text().await.unwrap());
                }
                Ok(Err(e)) => {
                    eprintln!("[gen_cb_for_msg] Error: {:?}", e);
                }
                Err(join_err) => {
                    eprintln!("[gen_cb_for_msg] Panic inside task: {:?}", join_err);
                }
            }
        }

        Command::PostPseudo {
            message,
            group_id,
            pseudo_idx,
        } => {

            let (claimed_str, context_str) = get_claimed_context_by_index(pseudo_idx)
                .or_else(|| get_claimed_context_by_index(1))
                .expect("Both provided index and fallback index 1 failed");

            let context_f = F::from_bigint(BigInteger256::from_str(&context_str).unwrap()).unwrap();
            let claimed_f = F::from_bigint(BigInteger256::from_str(&claimed_str).unwrap()).unwrap();

            match spawn_blocking(move || pseudo_proof_with_msg(claimed_f, context_f)).await {
                Ok(Ok(proof)) => {
                    let payload = JsonRpcInputPseudo {
                        message,
                        group_id,
                        proof,
                    };

                    if let Err(e) = save_start_time("pseudo_msg") {
                        eprintln!("Failed to save start time: {}", e);
                    }

                    let res = client
                        .post("http://127.0.0.1:3000/api/jsonrpc/pseudo")
                        .json(&payload)
                        .send()
                        .await
                        .unwrap();

                    println!("Server responded: {}", res.text().await.unwrap());
                }
                Ok(Err(e)) => {
                    eprintln!("[pseudo_proof2] Error: {:?}", e);
                }
                Err(join_err) => {
                    eprintln!("[pseudo_proof2] Panic inside task: {:?}", join_err);
                }
            }
        }

        Command::PostPseudoRate {
            message,
            group_id,
            thread,
            pseudo_idx,
        } => {

            let context_f = lookup_context(&thread)
                .expect("Could not find matching context for thread in local file");

            let i = F::from(pseudo_idx as u32);

            let claimed_f = prf2(&context_f, &i);

            match spawn_blocking(move || rate_pseudo_proof_with_msg(claimed_f, context_f, i)).await
            {
                Ok(Ok(proof)) => {
                    let payload = JsonRpcInputPseudo {
                        message,
                        group_id,
                        proof,
                    };

                    if let Err(e) = save_start_time("rate_pseudo") {
                        eprintln!("Failed to save start time: {}", e);
                    }

                    let res = client
                        .post("http://127.0.0.1:3000/api/jsonrpc/pseudo/rate")
                        .json(&payload)
                        .send()
                        .await
                        .unwrap();

                    println!("Server responded: {}", res.text().await.unwrap());
                }
                Ok(Err(e)) => {
                    eprintln!("[pseudo_proof_rate] Error: {:?}", e);
                }
                Err(join_err) => {
                    eprintln!("[pseudo_proof_rate] Panic inside task: {:?}", join_err);
                }
            }
        }

        Command::GenPseudo {} => {
            spawn_blocking(|| gen_pseudo()).await.unwrap();
        }
        Command::PseudoIndex {} => {
            spawn_blocking(|| list_all_pseudos_from_log())
                .await
                .unwrap();
        }

        Command::NewThreadCxt { message } => {
            let req = ContextRequest {
                thread: message.clone(),
            };

            let res = client
                .post("http://127.0.0.1:3000/api/pseudo/new_thread_context")
                .json(&req)
                .send()
                .await
                .unwrap();

            println!("Server responded: {}", res.text().await.unwrap());
        }

        Command::GetContexts => {
            let res = client
                .get("http://127.0.0.1:3000/api/pseudo/get_all_contexts")
                .send()
                .await
                .expect("Request failed");

            let status = res.status();
            let body = res.text().await.unwrap();

            if !status.is_success() {
                eprintln!("Server error ({}): {}", status, body);
                return;
            }

            // Ensure client directory exists
            std::fs::create_dir_all("client").expect("Failed to create client dir");

            // Write the full context.jsonl content to the client's file
            let mut file = File::create("client/contexts.jsonl").expect("Failed to create file");
            file.write_all(body.as_bytes())
                .expect("Failed to write file");

            println!("Downloaded all contexts to client/contexts.jsonl");
        }

        Command::Scan {} => {
            println!("Scanning...");

            match spawn_blocking(|| scan()).await {
                Ok(Ok(proof_bytes)) => {
             
                    let res = client
                        .post("http://127.0.0.1:3000/api/interact/scan")
                        .body(proof_bytes) // sends raw binary, as expected
                        .send()
                        .await
                        .unwrap();

                    println!("Server responded: {}", res.text().await.unwrap());
                }
                Ok(Err(e)) => {
                    eprintln!("[gen_cb_for_msg] Error: {:?}", e);
                }
                Err(join_err) => {
                    eprintln!("[gen_cb_for_msg] Panic inside task: {:?}", join_err);
                }
            }
        }

        Command::Ban { t } => {
            println!("Banning...");

            let start = SystemTime::now();

            match spawn_blocking(move || ban(t)).await {
                Ok(Ok(())) => {
                    // Success
                    let end = SystemTime::now();

                    if let Err(e) = append_timing_line_features("ban", start, end) {
                        eprintln!("Failed to write timing file for proof gen: {}", e);
                    }
                }
                Ok(Err(e)) => {
                    eprintln!("[gen_cb_for_msg] Error: {:?}", e);
                }
                Err(join_err) => {
                    eprintln!("[gen_cb_for_msg] Panic inside task: {:?}", join_err);
                }
            }

            println!("Banned");
        }

        Command::Rep { t } => {
            println!("Recording rep...");

            let start = SystemTime::now();

            match spawn_blocking(move || rep(t)).await {
                Ok(Ok(())) => {
                    // Success
                    let end = SystemTime::now();

                    if let Err(e) = append_timing_line_features("rep", start, end) {
                        eprintln!("Failed to write timing file for proof gen: {}", e);
                    }
                }
                Ok(Err(e)) => {
                    eprintln!("[gen_cb_for_msg] Error: {:?}", e);
                }
                Err(join_err) => {
                    eprintln!("[gen_cb_for_msg] Panic inside task: {:?}", join_err);
                }
            }

            println!("Recorded");
        }

        Command::Join {} => {
            println!("Joining bul...");

            match spawn_blocking(|| join2()).await {
                Ok(Ok(())) => {
                    // success
                }
                Ok(Err(e)) => {
                    eprintln!("[gen_cb_for_msg] Error: {:?}", e);
                }
                Err(join_err) => {
                    eprintln!("[gen_cb_for_msg] Panic inside task: {:?}", join_err);
                }
            }

            println!("Joined");
        }

        Command::Pseudonym {} => {
            let res = client
                .get("http://127.0.0.1:3000/api/pseudonym")
                .send()
                .await
                .unwrap();

            println!("Server responded: {}", res.text().await.unwrap());
        }

        Command::Reaction {
            group_id,
            emoji,
            timestamp,
        } => {
            let payload = JsonRpcReact {
                group_id,
                emoji,
                timestamp,
            };

            let res = client
                .post("http://127.0.0.1:3000/api/react")
                .json(&payload)
                .send()
                .await
                .unwrap();

            println!("Server responded: {}", res.text().await.unwrap());
        }

        Command::Reply {
            group_id,
            message,
            timestamp,
        } => {
            match spawn_blocking(|| gen_cb_for_msg()).await {
                Ok(Ok(proof_bytes)) => {

                    let payload = JsonRpcReply {
                        group_id,
                        message,
                        timestamp,
                        proof: proof_bytes,
                    };

                    let res = client
                        .post("http://127.0.0.1:3000/api/reply")
                        .json(&payload)
                        .send()
                        .await
                        .unwrap();

                    println!("Server responded: {}", res.text().await.unwrap());
                }
                Ok(Err(e)) => {
                    eprintln!("[gen_cb_for_msg] Error: {:?}", e);
                }
                Err(join_err) => {
                    eprintln!("[gen_cb_for_msg] Panic inside task: {:?}", join_err);
                }
            }
        }

        Command::ReplyPseudo {
            group_id,
            message,
            timestamp,
            pseudo_idx,
        } => {
            // Load the pseudonym context and claimed fields from log
            let (claimed_str, context_str) = get_claimed_context_by_index(pseudo_idx)
                .or_else(|| get_claimed_context_by_index(1))
                .expect("Both provided index and fallback index 1 failed");

            let context_f = F::from_bigint(BigInteger256::from_str(&context_str).unwrap()).unwrap();
            let claimed_f = F::from_bigint(BigInteger256::from_str(&claimed_str).unwrap()).unwrap();

            match spawn_blocking(move || pseudo_proof_with_msg(claimed_f, context_f)).await {
                Ok(Ok(proof)) => {
                    let payload = JsonRpcReplyPseudo {
                        group_id,
                        message,
                        timestamp,
                        proof,
                    };

                    let res = client
                        .post("http://127.0.0.1:3000/api/reply/pseudo")
                        .json(&payload)
                        .send()
                        .await
                        .unwrap();

                    println!("Server responded: {}", res.text().await.unwrap());
                }
                Ok(Err(e)) => {
                    eprintln!("[pseudo_proof2] Error: {:?}", e);
                }
                Err(join_err) => {
                    eprintln!("[pseudo_proof2] Panic inside task: {:?}", join_err);
                }
            }
        }

        Command::Vote {
            group_id,
            emoji,
            timestamp,
        } => {
            let payload = serde_json::json!({ "timestamp": timestamp });

            let response = client
                .post("http://127.0.0.1:3000/api/context")
                .json(&payload)
                .send()
                .await
                .expect("Failed to reach context endpoint");

            let context_resp: ContextResponse = response
                .json()
                .await
                .expect("Failed to parse JSON from context server");

            let context_str = context_resp.context;
            let context_f = F::from_bigint(BigInteger256::from_str(&context_str).unwrap()).unwrap();
            let claimed_f = compute_pseudo_for_poll(&context_f);

            match spawn_blocking(move || pseudo_proof_vote(claimed_f, context_f)).await {
                Ok(Ok(proof)) => {
                    let payload = JsonRpcVote {
                        group_id,
                        emoji,
                        timestamp,
                        claimed: claimed_f.to_string(),
                        proof,
                    };

                    if let Err(e) = save_start_time("pseudo_vote") {
                        eprintln!("Failed to save start time: {}", e);
                    }

                    let res = client
                        .post("http://127.0.0.1:3000/api/vote")
                        .json(&payload)
                        .send()
                        .await
                        .unwrap();

                    println!("Server responded: {}", res.text().await.unwrap());
                }
                Ok(Err(e)) => {
                    eprintln!("[pseudo_proof2] Error: {:?}", e);
                }
                Err(join_err) => {
                    eprintln!("[pseudo_proof2] Panic inside task: {:?}", join_err);
                }
            }
        }

        Command::CountVotes {
            group_id,
            timestamp,
        } => {
            let payload = JsonRpcCountVotes {
                group_id,
                timestamp,
            };

            let res = client
                .post("http://127.0.0.1:3000/api/votecount")
                .json(&payload)
                .send()
                .await;

            match res {
                Ok(response) => {
                    println!("Server responded: {}", response.text().await.unwrap());
                }
                Err(e) => {
                    eprintln!("Request failed: {}", e);
                }
            }
        }

        Command::BanPoll {
            message,
            group_id,
            timestamp,
        } => {
            let payload = JsonRpcBanPoll {
                message,
                group_id,
                timestamp,
            };

            let res = client
                .post("http://127.0.0.1:3000/api/banpoll")
                .json(&payload)
                .send()
                .await
                .unwrap();

            println!("Server responded: {}", res.text().await.unwrap());
        }
        Command::Poll { message, group_id } => {
            let payload = JsonRpcPoll { message, group_id };

            let res = client
                .post("http://127.0.0.1:3000/api/poll")
                .json(&payload)
                .send()
                .await
                .unwrap();

            println!("Server responded: {}", res.text().await.unwrap());
        }

        Command::Authorship {
            pseudo_idx1,
            pseudo_idx2,
            group_id,
        } => {
            let payload_result =
                spawn_blocking(move || make_authorship_proof(pseudo_idx1, pseudo_idx2)).await;

            match payload_result {
                Ok(Ok(proof)) => {
                    let payload = JsonAuthorship { proof, group_id };

                    if let Err(e) = save_start_time("author") {
                        eprintln!("Failed to save start time: {}", e);
                    }

                    let res = client
                        .post("http://127.0.0.1:3000/api/authorship")
                        .json(&payload)
                        .send()
                        .await
                        .unwrap();

                    println!("Server responded: {}", res.text().await.unwrap());
                }
                Ok(Err(e)) => {
                    eprintln!("[make_authorship_proof] Error: {:?}", e);
                }
                Err(join_err) => {
                    eprintln!("[make_authorship_proof] Panic inside task: {:?}", join_err);
                }
            }
        }

        Command::Badge { i, claimed, group_id } => {
            let claimed_f = string_to_f(&claimed);
            let payload_result = spawn_blocking(move || make_badge_proof(i, claimed_f)).await;

            match payload_result {
                Ok(Ok(proof)) => {
                    let payload = JsonBadge {proof, group_id};

                    if let Err(e) = save_start_time("badge") {
                        eprintln!("Failed to save start time: {}", e);
                    }

                    let res = client
                        .post("http://127.0.0.1:3000/api/badges")
                        .json(&payload)
                        .send()
                        .await
                        .unwrap();

                    println!("Server responded: {}", res.text().await.unwrap());
                }
                Ok(Err(e)) => {
                    eprintln!("[make_authorship_proof] Error: {:?}", e);
                }
                Err(join_err) => {
                    eprintln!("[make_authorship_proof] Panic inside task: {:?}", join_err);
                }
            }
        }
    }
}

