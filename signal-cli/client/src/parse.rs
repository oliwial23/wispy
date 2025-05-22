use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
pub struct Cli {
    /// User file
    #[arg(short, long, value_name = "FILE")]
    pub user: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// View messages posted.
    ViewPosts,

    /// Send message + update server with callback.
    Post {
        /// Message to be sent anonymously
        #[arg(long = "message", short = 'm')]
        message: String,

        /// Group id for group message
        #[arg(long = "group-id", short = 'g')]
        group_id: String,
    },

    PostPseudo {
        /// Message to be sent anonymously
        #[arg(long = "message", short = 'm')]
        message: String,

        /// Group id for group message
        #[arg(long = "group-id", short = 'g')]
        group_id: String,

        /// Send using a pseudonym. Give the index of the pseudonym. For more details, call "pseudo-index"
        #[arg(long = "pseudo-idx", short = 'i')]
        pseudo_idx: usize,
    },

    PostPseudoRate {
        /// Message to be sent anonymously
        #[arg(long = "message", short = 'm')]
        message: String,

        /// Group id for group message
        #[arg(long = "group-id", short = 'g')]
        group_id: String,

        /// Message to be sent anonymously
        #[arg(long = "thread", short = 't')]
        thread: String,

        /// Send using a pseudonym. Give the index of the pseudonym. For more details, call "pseudo-index"
        #[arg(long = "pseudo-idx", short = 'i')]
        pseudo_idx: usize,
    },

    Pseudonym,
    GenPseudo,
    Scan,
    // PseudoContext,
    /// Submit vote for a poll
    Vote {
        /// Group id of group message to react to
        #[arg(long = "group-id", short = 'g')]
        group_id: String,

        /// Timestamp of message to react to
        #[arg(long = "timestamp", short = 't')]
        timestamp: u64,

        /// Reaction emoji (your vote for the poll)
        #[arg(long = "emoji", short = 'e')]
        emoji: String,
        // /// Context provided by server specific to this poll
        // #[arg(long = "context", short = 'c')]
        // context: String,
    },

    CountVotes {
        /// Group id of group poll or ban poll message
        #[arg(long = "group-id", short = 'g')]
        group_id: String,

        /// Timestamp of poll or ban poll
        #[arg(long = "timestamp", short = 't')]
        timestamp: u64,
    },

    BanPoll {
        /// Optional message for the poll
        #[arg(long = "message", short = 'm')]
        message: Option<String>,

        /// Group id for the ban poll
        #[arg(long = "group-id", short = 'g')]
        group_id: String,

        /// Timestamp of message to vote on for banning
        #[arg(long = "timestamp", short = 't')]
        timestamp: u64,
    },
    // Ban {
    //     /// Index of CB
    //     #[arg(long = "i", short = 'i')]
    //     i: usize,
    //     /// Which
    //     #[arg(long = "j", short = 'j')]
    //     i2: usize,
    // },
    Ban {
        /// Message Timestamp
        #[arg(long = "timestamp", short = 't')]
        t: u64,
    },

    Rep {
        /// Message Timestamp
        #[arg(long = "timestamp", short = 't')]
        t: u64,
    },

    Join,

    /// Get pseudonym index for choosing pseudonym you wish to send messages under
    PseudoIndex,

    /// React to a message
    Reaction {
        /// Group id of group message to react to
        #[arg(long = "group-id", short = 'g')]
        group_id: String,

        /// Reaction emoji
        #[arg(long = "emoji", short = 'e')]
        emoji: String,

        /// Timestamp of message to react to
        #[arg(long = "timestamp", short = 't')]
        timestamp: u64,
    },

    /// Reply to a message
    Reply {
        /// Group id of group message to react to
        #[arg(long = "group-id", short = 'g')]
        group_id: String,

        /// Message to be sent as a reply
        #[arg(long = "message", short = 'm')]
        message: String,

        /// Timestamp of message to reply to
        #[arg(long = "timestamp", short = 't')]
        timestamp: u64,
    },

    /// Reply to a message
    ReplyPseudo {
        /// Group id of group message to react to
        #[arg(long = "group-id", short = 'g')]
        group_id: String,

        /// Message to be sent as a reply
        #[arg(long = "message", short = 'm')]
        message: String,

        /// Timestamp of message to reply to
        #[arg(long = "timestamp", short = 't')]
        timestamp: u64,

        /// Send using a pseudonym. Give the index of the pseudonym. For more details, call "pseudo-index"
        #[arg(long = "pseudo-idx", short = 'p')]
        pseudo_idx: usize,
    },

    GetContexts,
    Poll {
        /// Message for poll for group members to vote on
        #[arg(long = "message", short = 'm')]
        message: String,

        /// Group id for the poll
        #[arg(long = "group-id", short = 'g')]
        group_id: String,
    },
    
    Authorship {
        /// Send using a pseudonym. Give the index of the pseudonym. For more details, call "pseudo-index"
        #[arg(long = "pseudo-idx1", short = 'i')]
        pseudo_idx1: usize,

        /// Send using a pseudonym. Give the index of the pseudonym. For more details, call "pseudo-index"
        #[arg(long = "pseudo-idx2", short = 'j')]
        pseudo_idx2: usize,

        /// Group id for claim authorship message
        #[arg(long = "group-id", short = 'g')]
        group_id: String,
    },

    Badge {
        #[arg(long = "index", short = 'i')]
        i: usize,

        #[arg(long = "badge", short = 'b')]
        claimed: String,
    },

    NewThreadCxt {
        /// Message for poll for group members to vote on
        #[arg(long = "message", short = 'm')]
        message: String,
        // /// Group id for the poll
        // #[arg(long = "group-id", short = 'g')]
        // group_id: String,
    },
}
