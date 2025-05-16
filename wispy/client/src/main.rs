pub mod parse;

use crate::parse::Cli;
use crate::parse::Command;
use ark_ff::BigInteger256;
use ark_ff::PrimeField;
use ark_std::result::Result::Ok;
use clap::Parser;
use client::helpers::compute_pseudo_for_poll;
use client::helpers::gen_pseudo;
use client::helpers::get_claimed_context_by_index;
use client::helpers::list_all_pseudos_from_log;
use client::helpers::make_authorship_proof;
use client::helpers::make_badge_proof;
use client::helpers::pseudo_proof_vote;
use client::helpers::pseudo_proof_with_msg;
use client::helpers::string_to_f;
use client::helpers::{ban, gen_cb_for_msg, join2, scan};
use common::F;
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;
use std::str::FromStr;
use std::usize;
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
    // pseudo_idx: usize,
    proof: Vec<u8>,
}

// If Reactions are only allowed for anon msg's then we dont need target author
#[derive(Serialize)]
pub struct JsonRpcReact {
    group_id: String,
    emoji: String,
    timestamp: u64,
    // poll: bool,
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
    // pseudo_idx: usize,
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
}

#[derive(Deserialize)]
struct ContextResponse {
    context: String,
}

use client::helpers::rep;
// use client::helpers::update_reaction_log;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let client = Client::new();

    match cli.command {
        Command::ViewPosts => {
            println!("Fetching posts...");
            // Call view logic here
        }

        // signal-cli-client -a +491724953171 --json-rpc-http "http://127.0.0.1:3000/api/jsonrpc" send -g VON5o2iTrMfkbvxB/ynpTJjU8TvAQd0Dq6oGG6PzCXc= -m 'Hello Rachel2'
        Command::Post { message, group_id } => {
            println!("Posting to group {}: {}", group_id, message);

            match spawn_blocking(|| gen_cb_for_msg()).await {
                Ok(Ok(proof_bytes)) => {
                    // Optional: base64 encode if needed
                    // let proof = base64::encode(&proof_bytes);

                    let payload = JsonRpcInput {
                        message,
                        group_id,
                        proof: proof_bytes, // add this to your input struct
                    };

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
            println!("Posting to group {}: {}", group_id, message);

            let (claimed_str, context_str) = get_claimed_context_by_index(pseudo_idx)
                .or_else(|| get_claimed_context_by_index(1))
                .expect("Both provided index and fallback index 1 failed");

            let context_f = F::from_bigint(BigInteger256::from_str(&context_str).unwrap()).unwrap();
            let claimed_f = F::from_bigint(BigInteger256::from_str(&claimed_str).unwrap()).unwrap();

            // Call pseudo_proof2 in a blocking task
            match spawn_blocking(move || pseudo_proof_with_msg(claimed_f, context_f)).await {
                Ok(Ok(proof)) => {
                    let payload = JsonRpcInputPseudo {
                        message,
                        group_id,
                        // pseudo_idx,
                        proof,
                    };

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

        Command::GenPseudo {} => {
            spawn_blocking(|| gen_pseudo()).await.unwrap();
        }
        Command::PseudoIndex {} => {
            spawn_blocking(|| list_all_pseudos_from_log())
                .await
                .unwrap();
        }

        Command::Scan {} => {
            println!("Scanning...");

            match spawn_blocking(|| scan()).await {
                Ok(Ok(proof_bytes)) => {
                    // Optional: base64 encode if needed
                    // let proof = base64::encode(&proof_bytes);

                    // let payload = JsonRpcInput {
                    //     message,
                    //     group_id,
                    //     proof: proof_bytes, // add this to your input struct
                    // };

                    // let res = client
                    //     .post("http://127.0.0.1:3000/api/interact/scan")
                    //     .json(&proof_bytes)
                    //     .send()
                    //     .await
                    //     .unwrap();
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

            match spawn_blocking(move || ban(t)).await {
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

            println!("Banned");
        }

        Command::Rep { t } => {
            println!("Recording rep...");

            match spawn_blocking(move || rep(t)).await {
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
                // .json()
                .send()
                .await
                .unwrap();

            println!("Server responded: {}", res.text().await.unwrap());
        }

        // Command::ThumbsUp { t } => {
        //     update_reaction_log(t, 1).unwrap();
        // }
        // Command::ThumbsDown { t } => {
        //     update_reaction_log(t, -1).unwrap();
        // }
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
                    // Optional: base64 encode if needed
                    // let proof = base64::encode(&proof_bytes);

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

            // Call pseudo_proof2 in a blocking task
            match spawn_blocking(move || pseudo_proof_with_msg(claimed_f, context_f)).await {
                Ok(Ok(proof)) => {
                    let payload = JsonRpcReplyPseudo {
                        group_id,
                        message,
                        timestamp,
                        // pseudo_idx,
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

            // let context_f = F::from_bigint(BigInteger256::from_str(&context).unwrap()).unwrap();
            // let claimed_f = compute_pseudo_for_poll(&context_f);

            match spawn_blocking(move || pseudo_proof_vote(claimed_f, context_f)).await {
                Ok(Ok(proof)) => {
                    let payload = JsonRpcVote {
                        group_id,
                        emoji,
                        timestamp,
                        claimed: claimed_f.to_string(),
                        proof,
                    };

                    let res = client
                        .post("http://127.0.0.1:3000/api/vote")
                        .json(&payload)
                        .send()
                        .await
                        .unwrap(); // /main.rs:486:26:

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

            //println!("Server responded: {}", res.text().await.unwrap());
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

        Command::Badge { i, claimed } => {
            let claimed_f = string_to_f(&claimed);
            let payload_result = spawn_blocking(move || make_badge_proof(i, claimed_f)).await;

            match payload_result {
                Ok(Ok(proof)) => {
                    let payload = JsonBadge { proof };

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

// fn find_context_for_pseudonym(pseudonym: &str) -> String {
//     let file = File::open("client/pseudo_log.jsonl").expect("Failed to open pseudo_log.jsonl");
//     let reader = BufReader::new(file);

//     for line in reader.lines() {
//         let line = line.expect("Failed to read line");
//         let json: Value = serde_json::from_str(&line).expect("Invalid JSON");

//         let claimed = json["claimed"].as_str().expect("Missing 'claimed' field");

//         if claimed == pseudonym {
//             return json["context"]
//                 .as_str()
//                 .expect("Missing 'context' field")
//                 .to_string();
//         }
//     }

//     panic!("No matching pseudonym found in pseudo_log.jsonl");
// }
