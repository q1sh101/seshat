#![forbid(unsafe_code)]

mod atomic;
mod backup;
mod cli;
mod error;
mod output;
mod paths;
mod result;
mod runtime;

fn main() {
    let mut args: Vec<String> = Vec::new();
    for raw in std::env::args_os().skip(1) {
        match raw.into_string() {
            Ok(s) => args.push(s),
            Err(bad) => {
                eprintln!("error: non-UTF-8 argument: {}", bad.to_string_lossy());
                eprintln!();
                eprintln!("{}", cli::USAGE);
                std::process::exit(2);
            }
        }
    }

    match cli::parse(&args) {
        Ok(cli::Command::Help) => {
            println!("{}", cli::USAGE);
        }
        Ok(cmd) => {
            eprintln!("{cmd:?}: not implemented");
            std::process::exit(1);
        }
        Err(msg) => {
            eprintln!("error: {msg}");
            eprintln!();
            eprintln!("{}", cli::USAGE);
            std::process::exit(2);
        }
    }
}
