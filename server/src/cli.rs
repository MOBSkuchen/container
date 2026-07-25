use std::path::PathBuf;
use std::str::FromStr;
use clap_derive::{Parser, Subcommand};
use console::{style, Term};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(short = 'c', long = "config", default_value = "config.chld")]
    pub config_file: PathBuf,
    
    #[command(subcommand)]
    pub command: Option<Commands>
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(long_about = "Starts up")]
    Start {
        #[arg(short = 'b', long = "bootstrap",
              long_help = "Allow the Bootstrap handover for this run even if the config \
                           disables it. Not persisted.")]
        bootstrap: bool
    },
    #[command(long_about = "Initializes a new instance")]
    Init,
    #[command(long_about = "Generates the shared authentication key and saves it to the config")]
    Keygen {
        #[arg(long_help = "Passphrase to derive the key from. Run keygen with the same phrase on \
                           the client to pair them. Omit it for a random key, which must then be \
                           copied across by hand.")]
        phrase: Option<String>,

        #[arg(long, conflicts_with = "phrase",
              long_help = "Use a key printed by `client keygen` verbatim, as hex.")]
        key: Option<String>,
    },
    #[command(long_about = "Removes the instances file.", name = "purge-instances")]
    PurgeInstances,
    #[command(long_about = "Kills the server process running with this config (e.g. a bootstrapped \
                            one that outlived its console), so the address frees up for a restart.",
              name = "stop-runaway")]
    StopRunaway,
}

fn _user_input_read_as<CastType: FromStr + Send + Sync + std::fmt::Display>(term: &Term, initial: &str, default: Option<CastType>) -> anyhow::Result<CastType>
where <CastType as FromStr>::Err: std::error::Error,
      <CastType as FromStr>::Err: Send,
      <CastType as FromStr>::Err: Sync,
      <CastType as FromStr>::Err: 'static,
      CastType: std::clone::Clone
{
    term.clear_line()?;
    term.write_line(initial)?;
    if let Some(d) = default.clone() {
        term.write_line(format!("(default: {d})").as_str())?;
        term.move_cursor_up(2)?;
        term.move_cursor_right(initial.len())?;
    }

    let input = term.read_line()?;
    if input.is_empty() && let Some(default) = default {
        return Ok(default)
    }
    let v = input.parse::<CastType>();
    if v.is_err() {
        term.clear_line()?;
        term.move_cursor_up(2)?;
        term.clear_line()?;
        term.write_line(style("Invalid input. Try again!").underlined().to_string().as_str())?;
        _user_input_read_as(term, initial, default)
    } else {
        Ok(v?)
    }
}

fn _cl_print_val(term: &Term, val: &str) -> anyhow::Result<()> {
    term.clear_line()?;
    term.move_cursor_up(1)?;
    term.clear_line()?;
    term.move_cursor_up(1)?;
    term.clear_line()?;
    term.write_line(val)?;
    Ok(())
}

pub fn gather_value_routine<CastType: FromStr + Send + Sync + std::fmt::Display>(term: &Term, initial: &str, default: Option<CastType>) -> anyhow::Result<CastType>
where <CastType as FromStr>::Err: std::error::Error,
      <CastType as FromStr>::Err: Send,
      <CastType as FromStr>::Err: Sync,
      <CastType as FromStr>::Err: 'static,
      CastType: std::clone::Clone
{
    term.write_line("")?;
    let val = _user_input_read_as(term, initial, default)?;
    _cl_print_val(term, format!("{initial}{val}").as_str())?;
    Ok(val)
}