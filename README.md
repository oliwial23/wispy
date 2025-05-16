# wispy-signal-cli

This project allows anonymous and pseudonymous messaging in Signal groups by acting as a proxy between [Axum](https://github.com/tokio-rs/axum) and the [Signal-CLI JSON-RPC daemon](https://github.com/AsamK/signal-cli). A custom CLI binary is used to interface with the Axum server, enabling anonymous group messaging, polls, reactions, and more—all built on top of cryptographically enforced workflows.

---

## ✅ Prerequisites

Make sure you have:

- [`signal-cli`](https://github.com/AsamK/signal-cli) installed (used in daemon mode)
- A Signal number registered
- `cargo` (Rust) installed
- A Signal group already created

For Signal setup steps (e.g. linking a device, creating a group), see [`SIGNALCLI.md`](./SIGNALCLI.md).

---

## 🖥 Running the System

You need **three terminals**:

---

### **Terminal 1: Start the Signal-CLI Daemon**

```bash
signal-cli --service-environment staging daemon --tcp 127.0.0.1:7583
```

This must be running first.

---

### **Build and Install the CLI Tool**

Run the following command to build the project and make the binary globally accessible (temporarily for your current terminal session):

```bash
cargo build --release && \
export PATH="$PATH:$(pwd)/target/release" && \
source ~/.zshrc
```

> 💡 **Note:** The `export PATH=...` part temporarily adds the binary to your `PATH`. If you want it to persist across terminal sessions, add this line to your `~/.zshrc` file manually:
>
> ```bash
> export PATH="$PATH:/full/path/to/your/project/target/release"
> ```
> Then run:
> ```bash
> source ~/.zshrc
> ```


### **Terminal 2: Run the Axum Server**

```bash
cd wispy-signal-cli/
cargo build --release
```

Add your CLI binary to your `$PATH`:

```bash
echo 'export PATH="$PATH:$(pwd)/target/release"' >> ~/.zshrc
source ~/.zshrc
```

```bash
cargo run --bin server
```

The server listens for incoming client commands and communicates with the Signal daemon.

---

### **Terminal 3: Use the Custom CLI to run the Client and Send Anonymous Messages**

```bash
cd wispy-signal-cli/
```

Add your CLI binary to your `$PATH`:

```bash
echo 'export PATH="$PATH:$(pwd)/target/release"' >> ~/.zshrc
source ~/.zshrc
```

Then you can use the CLI directly:

```bash
client join             # Join as an anonymous user
client post -m "Hi" -g "BASE64_GROUP_ID"
```

---

## 🧭 Usage Workflow

1. Start the **Signal daemon**.
2. Start the **Axum server**.
3. In a third terminal:
   - Run `client join` to anonymously join a Signal group.
   - Post messages, create polls, and vote using other CLI commands.

---

## ✨ CLI Command Reference

Below is an in-depth description of all available commands:

---

### `join`

Join the group anonymously.

```bash
client join
```

---

### `post`

Send an anonymous message to a group.

```bash
client post -m "testing" -g "GROUP_ID"
```

- `-m`, `--message`: Your message content
- `-g`, `--group-id`: The Signal base64 group ID

---

### `post-pseudo`

Send a message under a pseudonym you've generated.

```bash
client post-pseudo -m "hello" -g "GROUP_ID" -p 0
```

- `-p`, `--pseudo-idx`: Index of your pseudonym (see `pseudo-index`)

---

### `gen-pseudo`

Generate a new pseudonym.

```bash
client gen-pseudo
```

---

### `pseudo-index`

List all pseudonyms you've generated and their indices.

```bash
client pseudo-index
```

---

### `scan`

Run a ZK-based scan interaction before posting (for stronger anonymity).

```bash
client scan
```

---

### `reaction`

React to a message in a group.

```bash
client reaction -g "GROUP_ID" -e "🔥" -t 1715791234
```

- `-e`, `--emoji`: The reaction emoji
- `-t`, `--timestamp`: Timestamp of the target message

---

### `reply`

Anonymously reply to a message.

```bash
client reply -g "GROUP_ID" -m "I agree" -t 1715791234
```

---

### `reply-pseudo`

Reply to a message using a pseudonym.

```bash
client reply-pseudo -g "GROUP_ID" -m "Good point" -t 1715791234 -p 1
```

---

### `poll`

Create a new poll for users to vote on.

```bash
client poll -m "Should we change topics?" -g "GROUP_ID"
```

---

### `vote`

Submit a vote (emoji) on a poll message.

```bash
client vote -g "GROUP_ID" -t 1715791234 -e "👍"
```

---

### `count-votes`

Count votes for a given poll.

```bash
client count-votes -g "GROUP_ID" -t 1715791234
```

---

### `ban-poll`

Start a vote to ban a message.

```bash
client ban-poll -m "Inappropriate content?" -g "GROUP_ID" -t 1715791234
```

---

### `ban`

Submit a vote to ban a message.

```bash
client ban -t 1715791234
```

---

### `rep`

Submit a reputation signal (upvote/downvote) on a message.

```bash
client rep -t 1715791234
```

---

### `authorship`

Prove that two pseudonyms belong to the same user.

```bash
client authorship -i 0 -j 1 -g "GROUP_ID"
```

---

### `badge`

Claim a badge under a pseudonym.

```bash
client badge -i 0 -b "first-post"
```

---

## ✅ Tips

- You can get your group ID using `signal-cli listGroups`.
- Timestamps for messages are UNIX epoch seconds (provided in the metadata of group messages).
- Use `pseudo-index` before posting pseudonymously.
- The system does **not** require Signal group members to be running this server—only you need the setup for anonymous participation.

---

## 🛠 Development Notes

- All anonymous logic runs through the Axum server which proxies to the Signal daemon.
- Cryptographic logic for anonymity, pseudonymity, and ZK workflows is implemented within Rust (see `src/zk/`).


