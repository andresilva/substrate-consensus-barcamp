use sc_cli::Subcommand;
use structopt::StructOpt;

#[allow(missing_docs)]
#[derive(Debug, StructOpt)]
pub struct RunCmd {
    #[allow(missing_docs)]
    #[structopt(flatten)]
    pub base: sc_cli::RunCmd,

    #[structopt(long = "finality-gadget")]
    pub finality_gadget: bool,

    #[structopt(long = "finality-gadget-validator")]
    pub finality_gadget_validator: bool,
}

#[derive(Debug, StructOpt)]
pub struct Cli {
    #[structopt(subcommand)]
    pub subcommand: Option<Subcommand>,

    #[structopt(flatten)]
    pub run: RunCmd,
}
