/// Signs data using the openpgp crate and secrets in gpg-agent.

use std::io;
use std::path::PathBuf;

use clap::CommandFactory;
use clap::FromArgMatches;
use clap::Parser;

use sequoia_openpgp as openpgp;
use sequoia_ipc as ipc;

use openpgp::parse::Parse;
use openpgp::serialize::stream::{Armorer, Message, LiteralWriter, Signer};
use openpgp::policy::StandardPolicy as P;
use ipc::gnupg::{Context, KeyPair};

/// Defines the CLI.
#[derive(Parser, Debug)]
#[clap(
    name = "gpg-agent-sign",
    about = "Connects to gpg-agent and creates a dummy signature.",
)]
pub struct Cli {
    #[clap(
        long,
        value_name = "PATH",
        env = "GNUPGHOME",
        help = "Use this GnuPG home directory, default: $GNUPGHOME",
    )]
    homedir: Option<PathBuf>,

    #[clap(
        long,
        value_name = "CERT",
        help = "Public part of the secret keys managed by gpg-agent",
        required = true,
    )]
    cert: Vec<PathBuf>,
}

fn main() -> openpgp::Result<()> {
    let p = &P::new();

    let version = format!(
        "{} (sequoia-openpgp {}, using {})",
        env!("CARGO_PKG_VERSION"),
        sequoia_openpgp::VERSION,
        sequoia_openpgp::crypto::backend());
    let cli = Cli::command().version(version);
    let matches = Cli::from_arg_matches(&cli.get_matches())?;

    let ctx = if let Some(homedir) = matches.homedir {
        Context::with_homedir(homedir)?
    } else {
        Context::new()?
    };

    // Read the Certs from the given files.
    let certs = matches.cert.into_iter().map(
            openpgp::Cert::from_file
        ).collect::<Result<Vec<_>, _>>()?;

    // Construct a KeyPair for every signing-capable (sub)key.
    use openpgp::cert::amalgamation::ValidAmalgamation;
    let mut signers = certs.iter().flat_map(|cert| {
        cert.keys().with_policy(p, None).alive().revoked(false).for_signing()
            .filter_map(|ka| {
                KeyPair::new(&ctx, ka.key())
                    .map(|kp| kp.with_cert(ka.cert()))
                    .ok()
            })
    }).collect::<Vec<KeyPair>>();

    // Compose a writer stack corresponding to the output format and
    // packet structure we want.

    // Stream an OpenPGP message.
    let message = Message::new(io::stdout());

    // We want the output to be ASCII armored.
    let message = Armorer::new(message).build()?;

    // Now, create a signer that emits the signature(s).
    let mut signer =
        Signer::new(message, signers.pop().expect("No key for signing"));
    for s in signers {
        signer = signer.add_signer(s);
    }
    let signer = signer.build()?;

    // Then, create a literal writer to wrap the data in a literal
    // message packet.
    let mut literal = LiteralWriter::new(signer).build()?;

    // Copy all the data.
    io::copy(&mut io::stdin(), &mut literal)?;

    // Finally, teardown the stack to ensure all the data is written.
    literal.finalize()?;

    Ok(())
}
