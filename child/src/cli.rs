use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::str::FromStr;
use clap::{Parser, Subcommand, command};
use clap_derive::{Args, Parser, Subcommand};
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
        #[arg(short = 'b', long = "bootstrap", long_help = "Starts as a daemon")]
        bootstrap: bool
    },
    #[command(long_about = "Initializes a new instance")]
    Init
}

fn _user_input_read_as<CastType: FromStr + Send + Sync + std::fmt::Debug>(term: &Term, initial: &str, default: Option<CastType>) -> anyhow::Result<CastType>
where <CastType as FromStr>::Err: std::error::Error,
      <CastType as FromStr>::Err: Send,
      <CastType as FromStr>::Err: Sync,
      <CastType as FromStr>::Err: 'static,
      CastType: std::clone::Clone
{
    term.clear_line()?;
    term.write_line(initial)?;
    if let Some(d) = default.clone() {
        term.write_line(format!("(default: {:#?})", d).as_str())?;
        term.move_cursor_up(2)?;
        term.move_cursor_right(initial.len())?;
    }

    let input = term.read_line()?;
    if input.is_empty() && let Some(default) = default {
        return Ok(default)
    }
    let v = input.parse::<CastType>();
    if let Err(e) = v {
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

pub fn gather_value_routine<CastType: FromStr + Send + Sync + std::fmt::Debug>(term: &Term, initial: &str, default: Option<CastType>) -> anyhow::Result<CastType>
where <CastType as FromStr>::Err: std::error::Error,
      <CastType as FromStr>::Err: Send,
      <CastType as FromStr>::Err: Sync,
      <CastType as FromStr>::Err: 'static,
      CastType: std::clone::Clone
{
    term.write_line("")?;
    let val = _user_input_read_as(term, initial, default)?;
    _cl_print_val(term, format!("{initial}{:#?}", val).as_str())?;
    Ok(val)
}