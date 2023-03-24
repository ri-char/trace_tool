use anyhow::Result;
use clap::{Args, Parser, Subcommand};
mod patch;
mod run;
mod error;

#[derive(Parser)]
#[command(author="riChar", version, about="A tool to get coverage", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the program and record the coverage rate
    Run(RunArgs),
    /// Patch program or library
    Patch(PatchArgs),
}

#[derive(Args)]
pub struct RunArgs {
    /// Save result to file(json format)
    #[arg(short, long)]
    pub output: Option<std::path::PathBuf>,
    /// Patch DB file
    pub db: std::path::PathBuf,
    /// Command to run
    pub cmd: Vec<String>,
}

#[derive(Args)]
pub struct PatchArgs {
    /// File to be patched
    pub elf: String,
    /// Patch DB file
    pub db: std::path::PathBuf,
    /// r2 command
    #[arg(long, default_value="r2")]
    pub r2: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(args) => run::cmd_run(args)?,
        Commands::Patch(args) => patch::cmd_patch(args)?,
    }

    Ok(())
}
