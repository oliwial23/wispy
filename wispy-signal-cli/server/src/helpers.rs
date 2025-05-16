use anyhow::{Context, Result};
use ark_std::result::Result::Ok;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
};

#[derive(Serialize, Deserialize, Clone)]
struct ReputationEntry {
    timestamp: u64,
    reputation: i32,
    cb: String,
}

#[derive(Serialize, Deserialize)]
struct Vote {
    poll_pseudonym: String,
    seed: String,
    emoji: String,
}

#[derive(Serialize, Deserialize)]
struct PollEntry {
    timestamp: u64,
    votes: Vec<Vote>,
    ban: i64,
    context: String,
}

pub fn update_reaction_log(new_ts: u64, new_delta: i32) -> std::io::Result<()> {
    let mut entries: HashMap<u64, ReputationEntry> = HashMap::new();

    if Path::new("server/zkpair_log.jsonl").exists() {
        let file = File::open("server/zkpair_log.jsonl")?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            let json: Value = serde_json::from_str(&line)?;
            if json.get("timestamp").is_some()
                && json.get("reputation").is_some()
                && json.get("cb").is_some()
            {
                let entry: ReputationEntry = serde_json::from_value(json)?;
                entries.insert(entry.timestamp, entry);
            }
        }
    }

    // Update the reputation for the timestamp
    entries
        .entry(new_ts)
        .and_modify(|e| {
            e.reputation = (e.reputation + new_delta).max(0); // clamp to zero
        })
        .or_insert_with(|| ReputationEntry {
            timestamp: new_ts,
            reputation: new_delta.max(0),
            cb: String::from(""), // or panic/context if cb required
        });

    // Rewrite the full file
    let mut file = File::create("server/zkpair_log.jsonl")?;
    for entry in entries.values() {
        let line = format!(
            "{{\"timestamp\": {}, \"reputation\": {}, \"cb\": \"{}\"}}",
            entry.timestamp, entry.reputation, entry.cb
        );
        writeln!(file, "{}", line)?;
    }

    Ok(())
}

pub fn get_reputation_by_cb(cb_hex: &str) -> Result<i64> {
    let file = File::open("server/zkpair_log.jsonl").context("Failed to open log file")?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let json: Value = serde_json::from_str(&line)?;

        if json.get("cb").and_then(|v| v.as_str()) == Some(cb_hex) {
            return json
                .get("reputation")
                .and_then(|r| r.as_i64())
                // .map(|r| r as i32)
                .context("Missing or invalid reputation field");
        }
    }

    Err(anyhow::anyhow!("No entry found for cb {}", cb_hex))
}

// pub fn get_reputation_by_timestamp(timestamp: u64) -> Result<i32> {
//     let file = File::open("zkpair_log.jsonl").context("Failed to open log file")?;
//     let reader = BufReader::new(file);

//     for line in reader.lines() {
//         let line = line?;
//         let json: Value = serde_json::from_str(&line)?;
//         if json.get("timestamp").and_then(|v| v.as_u64()) == Some(timestamp) {
//             return json
//                 .get("reputation")
//                 .and_then(|r| r.as_i64())
//                 .map(|r| r as i32)
//                 .context("Missing or invalid `reputation` field");
//         }
//     }

//     Err(anyhow::anyhow!(
//         "No entry found for timestamp {}",
//         timestamp
//     ))
// }

pub fn delete_poll_pseudo_entry_by_timestamp(
    timestamp: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = "server/poll_pseudo_log.jsonl";
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let filtered_lines: Vec<String> = reader
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            let json: Value = serde_json::from_str(&line).ok()?;
            let ts = json["timestamp"].as_u64()?;
            if ts != timestamp {
                Some(line)
            } else {
                None
            }
        })
        .collect();

    // Rewrite the file with only the remaining lines
    let output = OpenOptions::new().write(true).truncate(true).open(path)?;
    let mut writer = BufWriter::new(output);
    for line in filtered_lines {
        writeln!(writer, "{}", line)?;
    }

    Ok(())
}

pub fn append_vote(
    timestamp: u64,
    pseudonym: &str,
    seed: String,
    emoji: &str,
) -> std::io::Result<()> {
    let path = "server/poll_log.jsonl";

    // Step 1: Read all lines
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;

    let mut updated_lines = Vec::new();
    let mut found = false;

    for line in lines {
        let mut entry: PollEntry = serde_json::from_str(&line)?;

        if entry.timestamp == timestamp {
            found = true;

            // Step 2: Remove existing vote from same pseudonym and seed
            entry
                .votes
                .retain(|v| !(v.poll_pseudonym == pseudonym && v.seed == seed));

            // Step 3: Add the new vote (clone seed here because it's moved)
            entry.votes.push(Vote {
                poll_pseudonym: pseudonym.to_string(),
                seed: seed.clone(), // <-- clone it only here
                emoji: emoji.to_string(),
            });

            // Serialize back to JSON
            let updated_line = serde_json::to_string(&entry)?;
            updated_lines.push(updated_line);
        } else {
            updated_lines.push(line);
        }
    }

    if !found {
        eprintln!("No poll entry found for timestamp {}", timestamp);
        return Ok(());
    }

    // Step 4: Rewrite the whole file
    let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
    for line in updated_lines {
        writeln!(file, "{}", line)?;
    }

    Ok(())
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

pub fn count_votes(val: &Value) -> (usize, usize) {
    let empty_vec = vec![];
    let votes = val["votes"].as_array().unwrap_or(&empty_vec);
    //let votes = val["votes"].as_array().unwrap_or(&vec![]);
    let ban_mode = val["ban"].as_i64().unwrap_or(0) != 0;

    let mut count_1 = 0;
    let mut count_2 = 0;

    for vote in votes {
        if let Some(emoji) = vote["emoji"].as_str() {
            match (ban_mode, emoji_to_name(emoji)) {
                (true, "ban") => count_1 += 1,
                (true, "not ban") => count_2 += 1,
                (false, "upvote") => count_1 += 1,
                (false, "downvote") => count_2 += 1,
                _ => {}
            }
        }
    }

    (count_1, count_2)
}

pub fn count_votes_by_timestamp(target_ts: i64) -> (usize, usize) {
    let file = File::open("server/poll_log.jsonl").expect("Failed to open file");
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.expect("Failed to read line");
        let val: Value = serde_json::from_str(&line).expect("Invalid JSON");

        if val["timestamp"].as_i64() == Some(target_ts) {
            return count_votes(&val);
        }
    }

    (0, 0) // not found
}

pub fn is_ban_poll_by_timestamp(target_ts: i64) -> bool {
    let file = File::open("server/poll_log.jsonl").expect("Failed to open file");
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.expect("Failed to read line");
        let val: Value = serde_json::from_str(&line).expect("Invalid JSON");

        if val["timestamp"].as_i64() == Some(target_ts) {
            return val["ban"].as_i64().unwrap_or(0) != 0;
        }
    }

    false // not found or ban flag is 0
}

pub fn get_ban_from_timestamp(target_ts: i64) -> Option<i64> {
    let file = File::open("server/poll_log.jsonl").ok()?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.ok()?;
        let val: Value = serde_json::from_str(&line).ok()?;

        if val["timestamp"].as_i64() == Some(target_ts) {
            return val["ban"].as_i64();
        }
    }

    None // timestamp not found
}

pub fn get_context_from_timestamp(target_ts: i64) -> Option<String> {
    let file = File::open("server/poll_log.jsonl").ok()?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.ok()?;
        let val: Value = serde_json::from_str(&line).ok()?;

        if val["timestamp"].as_i64() == Some(target_ts) {
            return val["context"].as_str().map(|s| s.to_string());
        }
    }

    None
}

use ark_std::fs;

pub fn delete_poll_entry_by_timestamp(target_ts: u64) -> std::io::Result<()> {
    let path = "server/poll_log.jsonl";

    // Step 1: Read all entries
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut remaining_lines = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let entry: PollEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping invalid line: {}", line);
                continue;
            }
        };

        if entry.timestamp != target_ts {
            remaining_lines.push(line);
        } else {
            println!("Deleting poll entry with timestamp: {}", target_ts);
        }
    }

    // Step 2: Rewrite the file with filtered entries
    let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
    for line in remaining_lines {
        writeln!(file, "{}", line)?;
    }

    Ok(())
}

use hex::FromHex;

pub fn find_callback_by_timestamp(timestamp: u64) -> Result<Vec<u8>> {
    let file = File::open("server/zkpair_log.jsonl").context("Failed to open zkpair_log.jsonl")?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let json: Value = serde_json::from_str(&line)?;

        if json.get("timestamp").and_then(|t| t.as_u64()) == Some(timestamp) {
            let cb_str = json
                .get("cb")
                .and_then(|v| v.as_str())
                .context("Missing `cb` field")?;
            let cb_bytes = Vec::from_hex(cb_str)?;
            return Ok(cb_bytes);
        }
    }

    Err(anyhow::anyhow!(
        "Callback not found for timestamp {}",
        timestamp
    ))
}
