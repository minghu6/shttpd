use std::path::PathBuf;

use clap::{IntoApp, Parser};
use clap_complete::Shell;

use bas::shell::gen_completions;
use bas::driver::RunCompiler;

use inkwellkit::config::*;

/// Bas Lang Compiler
#[derive(Parser)]
#[clap()]
struct Cli {
    /// Genrerate completion for bin
    #[clap(long = "generate", arg_enum)]
    generator: Option<Shell>,

    // #[clap(subcommand)]
    // command: Option<SubCommand>,

    #[clap(short = 'O', arg_enum)]
    opt: Option<OptLv>,

    #[clap(short = 't', long = "target_type", arg_enum)]
    target_type: Option<TargetType>,

    #[clap(short = 'e', long = "emit_type", arg_enum)]
    emit_type: Option<EmitType>,

    src: PathBuf,

    output: PathBuf
}

// #[derive(Subcommand)]
// enum SubCommand {
// }

// fn format_u32_str(s: &str) -> Result<u32, String> {
//     let s = s.replace("_", "");
//     u32::from_str_radix(&s, 10).or(Err(s))
// }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if let Some(generator) = cli.generator {
        let mut cmd = Cli::command();
        gen_completions(generator, &mut cmd);
        return Ok(());
    }

    let optlv = cli.opt.unwrap_or(OptLv::Debug);
    let target_type = cli.target_type.unwrap_or(TargetType::Bin);
    let emit_type = cli.emit_type.unwrap_or(EmitType::Obj);
    let print_type = if cli.output == PathBuf::from("stderr") {
        PrintTy::StdErr
    }
    else {
        PrintTy::File(cli.output)
    };

    let config = CompilerConfig {
        optlv,
        target_type,
        emit_type,
        print_type,
    };

    RunCompiler::new(&cli.src, config)?;

    Ok(())
}
