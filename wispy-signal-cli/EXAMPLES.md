# JSON-RPC API Example `signal-cli-client` Commands

This document provides example `singal-cli-client` commands for interacting with the JSON-RPC API.

---

# **Send Message**
The `send` command allows you to send messages to a single recipient or a group using `signal-cli-client`. You can include text, attachments, mentions, quotes, stickers, and more.

---

## **Sending a Direct Message**
To send a **message to a single recipient**, use the following command:

```sh
signal-cli-client -a +15555555555 \
  --json-rpc-http "http://127.0.0.1:3000/jsonrpc" \
  send -m "Hello from Signal Client!" \
  +15558675309
```

### **Explanation of Flags:**
- `-a +15555555555` → The account sending the message.  
- `-m "Hello from Signal Client!"` → The message text.  
- `+15558675309` → The recipient of the message.  

If you want to send a message to **multiple recipients**, provide multiple phone numbers:

```sh
signal-cli-client -a +15555555555 \
  --json-rpc-http "http://127.0.0.1:3000/jsonrpc" \
  send -m "Group message to multiple people!" \
  +15558675309 +15559998888 +15557776666
```

---

## **Sending a Message in a Group**
To send a message to a **group**, use the `-g` flag with the group ID:

```sh
signal-cli-client -a +15555555555 \
  --json-rpc-http "http://127.0.0.1:3000/jsonrpc" \
  send -m "Hello, group!" \
  -g "GROUP_ID_HERE"
```

### **Explanation of Flags:**
- `-a +15555555555` → The account sending the message.  
- `-m "Hello, group!"` → The message text.  
- `-g "GROUP_ID_HERE"` → The unique group ID where the message is being sent.  

---

## **Sending a Message to Yourself**
If you want to send a **note to yourself**, use the `--note-to-self` flag:

```sh
signal-cli-client -a +18023199267 \
  --json-rpc-http "http://127.0.0.1:3000/jsonrpc" \
  send -m "Reminder: Buy groceries" \
  --note-to-self
```

---

## **Sending a Message with Attachments**
You can also send **attachments** such as images, documents, or videos using the `-a` flag:

```sh
signal-cli-client -a +15555555555 \
  --json-rpc-http "http://127.0.0.1:3000/jsonrpc" \
  send -m "Check out this image!" \
  -a "/path/to/image.jpg" \
  +15558675309
```

- `-a "/path/to/image.jpg"` → The file path of the attachment.  
- You can send **multiple attachments** by providing multiple `-a` flags.

```sh
signal-cli-client -a +15555555555 \
  --json-rpc-http "http://127.0.0.1:3000/jsonrpc" \
  send -m "Here are some files!" \
  -a "/path/to/image1.jpg" \
  -a "/path/to/document.pdf" \
  +15558675309
```

---

## **Sending a Message with Mentions**
To mention a user in a message, use the `--mention` flag with the recipient's phone number:

```sh
signal-cli-client -a +15555555555 \
  --json-rpc-http "http://127.0.0.1:3000/jsonrpc" \
  send -m "Hello @User!" \
  --mention "+15558675309" \
  -g "GROUP_ID_HERE"
```

---

## **Sending a Quoted Message**
To reply to a specific message, use the `--quote-timestamp` flag along with the original author's number:

```sh
signal-cli-client -a +15555555555 \
  --json-rpc-http "http://127.0.0.1:3000/jsonrpc" \
  send -m "This is a reply!" \
  --quote-timestamp 1700000000000 \
  --quote-author "+15558675309" \
  -g "GROUP_ID_HERE"
```

### **Explanation of Flags:**
- `--quote-timestamp 1700000000000` → The timestamp of the original message.  
- `--quote-author "+15558675309"` → The author of the original message.  

---

## **Sending a Message with a Sticker**
To send a sticker, use the `--sticker` flag:

```sh
signal-cli-client -a +15555555555 \
  --json-rpc-http "http://127.0.0.1:3000/jsonrpc" \
  send --sticker "STICKER_ID" \
  -g "GROUP_ID_HERE"
```

- Replace `"STICKER_ID"` with the **actual sticker ID**.

---

## **Ending a Session**
If you want to **end the current session** and delete session state, use the `-e` flag:

```sh
signal-cli-client -a +15555555555 \
  --json-rpc-http "http://127.0.0.1:3000/jsonrpc" \
  send -e \
  +15558675309
```

- This is useful for **securely ending a Signal session** with a contact.

---

## **Command Breakdown**
| Flag | Description |
|------|------------|
| `-a` | The account sending the message |
| `-m` | The message text |
| `-g` | The group ID (for group messages) |
| `-r` | The recipient(s) (for direct messages) |
| `--note-to-self` | Sends a message to yourself |
| `-a` | Adds an attachment (file, image, video, etc.) |
| `--mention` | Mentions a specific user in the message |
| `--quote-timestamp` | Quotes a specific message timestamp |
| `--quote-author` | Specifies the author of the quoted message |
| `--sticker` | Sends a sticker |
| `-e` | Ends a session |

---

## **Examples Summary**

### **Direct Message**
```sh
signal-cli-client -a +15555555555 \
  --json-rpc-http "http://127.0.0.1:3000/jsonrpc" \
  send -m "Hello from Signal!" \
  +15558675309
```

### **Group Message**
```sh
signal-cli-client -a +15555555555 \
  --json-rpc-http "http://127.0.0.1:3000/jsonrpc" \
  send -m "Hello, everyone!" \
  -g "GROUP_ID_HERE"
```

### **Message with an Attachment**
```sh
signal-cli-client -a +15555555555 \
  --json-rpc-http "http://127.0.0.1:3000/jsonrpc" \
  send -m "Check this out!" \
  -a "/path/to/image.jpg" \
  +15558675309
```

### **Replying to a Message**
```sh
signal-cli-client -a +15555555555 \
  --json-rpc-http "http://127.0.0.1:3000/jsonrpc" \
  send -m "I agree!" \
  --quote-timestamp 1700000000000 \
  --quote-author "+15558675309" \
  -g "GROUP_ID_HERE"
```

---

# **Send Reaction**
This command allows a user to send a reaction to a message. 

For a **single-recipient** message in a non-group setting: 

```sh
signal-cli-client -a  +15558675309 \
  --json-rpc-http "http://127.0.0.1:3000/jsonrpc" \
  sendReaction \
  -r +15555555555 \
  -e "👍" \
  -a +15555555555 \
  -t 0000000000000

```

For a **multi-recipient** message in a group setting: 


The `-a` flag is used to specify the author of the message for which the user wishes to react to. The `-e` flag is used to specify the emoji reaction. The `-r` flag is used to specify one or more recipients who should receive the reaction by the user. The `-t` flag is used to give the timestamp of the target message in which the user wants to react to. The `-g` flag is used to give the group ID(s).

Got it! Here's the entire section in proper Markdown notation:  

```markdown
## **Send Reaction**
The `sendReaction` command allows a user to react to a specific message using an emoji.

### **Reacting to a Direct Message**
To send a reaction to a **single-recipient** message (in a non-group chat):

```sh
signal-cli-client -a +15558675309 \
  --json-rpc-http "http://127.0.0.1:3000/jsonrpc" \
  sendReaction \
  -r +15555555555 \
  -e "👍" \
  -a +15555555555 \
  -t 1700000000000
```

#### **Explanation of Flags:**
- `-a +15558675309` → The account sending the reaction.  
- `-r +15555555555` → The recipient of the reaction (who originally sent the message).  
- `-e "👍"` → The emoji used for the reaction.  
- `-a +15555555555` → The author of the original message.  
- `-t 1700000000000` → The **timestamp** of the message being reacted to.

---

### **Reacting to a Message in a Group**
To send a reaction to a **message within a group chat**, use the `-g` flag to specify the **group ID**:

```sh
signal-cli-client -a +15558675309 \
  --json-rpc-http "http://127.0.0.1:3000/jsonrpc" \
  sendReaction \
  -g "GROUP_ID_HERE" \
  -e "🔥" \
  -a +15555555555 \
  -t 1700000000000
```

#### **Explanation of Flags for Group Messages:**
- `-a +15558675309` → The account sending the reaction.  
- `-g "GROUP_ID_HERE"` → The **group ID** where the message was sent.  
- `-e "🔥"` → The emoji used for the reaction.  
- `-a +15555555555` → The author of the original message.  
- `-t 1700000000000` → The **timestamp** of the message being reacted to.  

Unlike direct messages, **the `-r` flag is not needed** for group messages since the reaction is associated with the group itself.

---

### **Command Breakdown**
| Flag | Description |
|------|------------|
| `-a` | The account sending the reaction |
| `-r` | The recipient (only for direct messages) |
| `-g` | The group ID (only for group messages) |
| `-e` | The emoji reaction |
| `-a` | The author of the original message |
| `-t` | The timestamp of the original message |

This command allows the user (`+15558675309`) to react to a message sent by `+15555555555` either in a **direct chat** or a **group chat**.

--- 

