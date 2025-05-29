use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// CLI entry point for the anonymous group chat application.
#[derive(Parser)]
pub struct Cli {
    /// Path to the user file (optional)
    #[arg(short, long, value_name = "FILE")]
    pub user: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

/// Enum of available CLI commands.
#[derive(Subcommand)]
pub enum Command {
    /// View messages that have been posted
    ViewPosts,

    /// Send a message anonymously with a callback
    Post {
        /// Message content
        #[arg(long, short = 'm')]
        message: String,

        /// Group ID
        #[arg(long, short = 'g')]
        group_id: String,
    },

    /// Send a message using a pseudonym
    PostPseudo {
        /// Message content
        #[arg(long, short = 'm')]
        message: String,

        /// Group ID
        #[arg(long, short = 'g')]
        group_id: String,

        /// Index of pseudonym to use
        #[arg(long = "pseudo-idx", short = 'i')]
        pseudo_idx: usize,
    },

    /// Send a message with a rate-limited pseudonym
    PostPseudoRate {
        /// Message content
        #[arg(long, short = 'm')]
        message: String,

        /// Group ID
        #[arg(long, short = 'g')]
        group_id: String,

        /// Thread ID for the rate-limited pseudonym
        #[arg(long, short = 't')]
        thread: String,

        /// Index of pseudonym to use
        #[arg(long = "pseudo-idx", short = 'i')]
        pseudo_idx: usize,
    },

    /// Generate a new pseudonym
    GenPseudo,

    /// Send a scan interaction
    Scan,

    /// Submit a vote for a poll
    Vote {
        /// Group ID of the poll message
        #[arg(long, short = 'g')]
        group_id: String,

        /// Timestamp of the poll message
        #[arg(long, short = 't')]
        timestamp: u64,

        /// Emoji representing your vote
        #[arg(long, short = 'e')]
        emoji: String,
    },

    /// Count votes for a poll or ban poll
    CountVotes {
        /// Group ID
        #[arg(long, short = 'g')]
        group_id: String,

        /// Timestamp of the poll message
        #[arg(long, short = 't')]
        timestamp: u64,
    },

    /// Start a ban poll for a message
    BanPoll {
        /// Optional message for the poll
        #[arg(long, short = 'm')]
        message: Option<String>,

        /// Group ID
        #[arg(long, short = 'g')]
        group_id: String,

        /// Timestamp of the message to ban
        #[arg(long, short = 't')]
        timestamp: u64,
    },

    /// Ban a user given a problematic message
    Ban {
        /// Timestamp of the message for banning
        #[arg(long, short = 't')]
        t: u64,
    },

    /// Count all reputation points for a message
    Rep {
        /// Timestamp of the message
        #[arg(long, short = 't')]
        t: u64,
    },

    /// Join a group (e.g., fetch callback object)
    Join,

    /// Print pseudonym index information
    PseudoIndex,

    /// React to a message with an emoji
    Reaction {
        /// Group ID
        #[arg(long, short = 'g')]
        group_id: String,

        /// Emoji to react with
        #[arg(long, short = 'e')]
        emoji: String,

        /// Timestamp of the message to react to
        #[arg(long, short = 't')]
        timestamp: u64,
    },

    /// Reply to a message
    Reply {
        /// Group ID
        #[arg(long, short = 'g')]
        group_id: String,

        /// Message content
        #[arg(long, short = 'm')]
        message: String,

        /// Timestamp of the message to reply to
        #[arg(long, short = 't')]
        timestamp: u64,
    },

    /// Reply to a message using a pseudonym
    ReplyPseudo {
        /// Group ID
        #[arg(long, short = 'g')]
        group_id: String,

        /// Message content
        #[arg(long, short = 'm')]
        message: String,

        /// Timestamp of the message to reply to
        #[arg(long, short = 't')]
        timestamp: u64,

        /// Index of pseudonym to use
        #[arg(long = "pseudo-idx", short = 'p')]
        pseudo_idx: usize,
    },

    /// Fetch all poll contexts from the server
    GetContexts,

    /// Start a new poll
    Poll {
        /// Message content
        #[arg(long, short = 'm')]
        message: String,

        /// Group ID
        #[arg(long, short = 'g')]
        group_id: String,
    },

    /// Claim authorship of a message using two pseudonyms
    Authorship {
        /// First pseudonym index
        #[arg(long = "pseudo-idx1", short = 'i')]
        pseudo_idx1: usize,

        /// Second pseudonym index
        #[arg(long = "pseudo-idx2", short = 'j')]
        pseudo_idx2: usize,

        /// Group ID
        #[arg(long, short = 'g')]
        group_id: String,
    },

    /// Claim a badge under a pseudonym
    Badge {
        /// Pseudonym index
        #[arg(long, short = 'i')]
        i: usize,

        /// Badge string
        #[arg(long, short = 'b')]
        claimed: String,

        /// Group ID
        #[arg(long, short = 'g')]
        group_id: String,
    },

    /// Start a new thread context
    NewThreadCxt {
        /// Message for the thread context
        #[arg(long, short = 'm')]
        message: String,
    },

    /// Generate a new pseudonym (legacy command, for compatibility)
    Pseudonym,
}

