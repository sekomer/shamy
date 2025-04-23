use clap::Subcommand;
use std::path::PathBuf;

pub use clap::Parser;

#[derive(Parser)]
#[command(arg_required_else_help = true)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    Keygen {
        #[arg(short, long)]
        threshold: u32,

        #[arg(short, long)]
        num_shares: u32,

        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    Schnorr {
        #[command(subcommand)]
        command: SchnorrCommands,
    },
}

#[derive(Subcommand)]
pub enum SchnorrCommands {
    Sign {
        #[arg(short, long)]
        challange: String,

        #[arg(short, long)]
        share: String,

        #[arg(short, long)]
        id: u64,

        #[arg(short, long)]
        nonce: String,
    },
    Verify {
        #[arg(short, long)]
        message: String,

        #[arg(short, long)]
        signature: String,

        #[arg(short, long)]
        public_key: String,

        #[arg(short, long)]
        nonce: String,
    },
    Combine {
        #[arg(short, long, value_parser, num_args = 1.., value_delimiter = ' ')]
        ids: Vec<u64>,

        #[arg(short, long, value_parser, num_args = 1.., value_delimiter = ' ')]
        signatures: Vec<String>,

        #[arg(short, long)]
        nonce: String,
    },
    Nonce {
        #[command(subcommand)]
        command: NonceCommands,
    },
    Challenge {
        #[arg(short, long)]
        message: String,

        #[arg(help = "Ids of participants (same order as nonces)")]
        #[arg(short, long, value_parser, num_args = 1.., value_delimiter = ' ')]
        ids: Vec<u64>,

        #[arg(help = "Nonces of participants (same order as ids)")]
        #[arg(short, long, value_parser, num_args = 1.., value_delimiter = ' ')]
        nonces: Vec<String>,

        #[arg(short, long)]
        public_key: String,
    },
}

#[derive(Subcommand)]
pub enum NonceCommands {
    Generate,
    Verify { nonce: String },
}
