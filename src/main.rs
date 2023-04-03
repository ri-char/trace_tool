use anyhow::Result;
use clap::{Args, Parser, Subcommand};
mod patch;
mod procmaps;
mod run;

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
    /// redis url
    #[arg(long, default_value = "redis://127.0.0.1/", env = "REDIS_URL")]
    pub db: String,
    /// Command to run
    pub cmd: Vec<String>,
    /// max time
    #[arg(long, default_value = "500")]
    pub timeout: Option<u32>,
}

#[derive(Args)]
pub struct PatchArgs {
    /// File to be patched
    pub elf: String,
    /// redis url
    #[arg(long, default_value = "redis://127.0.0.1/", env = "REDIS_URL")]
    pub db: String,
    /// r2 command
    #[arg(long, default_value = "r2")]
    pub r2: String,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Run(args) => run::cmd_run(args)?,
        Commands::Patch(args) => patch::cmd_patch(args)?,
    }

    Ok(())
}
