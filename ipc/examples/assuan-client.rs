use std::path::PathBuf;

use clap::CommandFactory;
use clap::FromArgMatches;
use clap::Parser;

use futures::StreamExt;
use sequoia_ipc as ipc;
use crate::ipc::assuan::Client;

use sequoia_openpgp as openpgp;
use openpgp::Result;

/// Defines the CLI.
#[derive(Parser, Debug)]
#[clap(
    name = "assuan-client",
    about = "Connects to and sends commands to assuan servers.",
)]
pub struct Cli {
    #[clap(
        long,
        value_name = "PATH",
        help = "Server to connect to",
    )]
    server: PathBuf,

    #[clap(
        long,
        value_name = "COMMAND",
        help = "Commands to send to the server",
        required = true,
    )]
    commands: Vec<String>,
}

fn main() -> Result<()> {
    let version = format!(
        "{} (sequoia-openpgp {}, using {})",
        env!("CARGO_PKG_VERSION"),
        sequoia_openpgp::VERSION,
        sequoia_openpgp::crypto::backend()
    );
    let cli = Cli::command().version(version);
    let matches = Cli::from_arg_matches(&cli.get_matches())?;

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut c = Client::connect(matches.server).await.unwrap();
        for command in matches.commands {
            eprintln!("> {}", command);
            c.send(command).unwrap();
            while let Some(response) = c.next().await {
                eprintln!("< {:?}", response);
            }
        }
    });

    Ok(())
}
