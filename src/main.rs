#![feature(ascii_char_variants)]
#![feature(ascii_char)]
#![feature(maybe_uninit_slice)]
#![feature(result_flattening)]
#![feature(coroutines)]
#![feature(async_iterator)]
#![feature(iter_from_coroutine)]

use std::fs::read_to_string;

use clap::Parser;
use conf::{default_log4rs_config, CGIMap, Log, ServConfOpt, SERV_CONF};
use futures::executor;
use serde::Deserialize;

use worker::do_listen;

mod conf;
mod resp;
mod route;
mod worker;

////////////////////////////////////////////////////////////////////////////////
//// Cli

#[derive(Parser)]
#[command(name = "SHTTPD")]
struct Cli {
    #[arg(short, value_parser = read_serv_conf)]
    config_file: Option<ServConfOpt>,
}


////////////////////////////////////////////////////////////////////////////////
//// Functions

fn read_serv_conf(s: &str) -> Result<ServConfOpt, String> {
    let content = read_to_string(s).map_err(|err| err.to_string())?;

    ServConfOpt::deserialize(toml::Deserializer::new(&content))
        .map_err(|err| err.to_string())
}


fn main() {
    let cli = Cli::parse();

    let appconf = cli.config_file.map(|opt| opt.resolve()).unwrap_or_default();

    let mut logconf = match &appconf.log {
        Some(Log { config }) => {
            match log4rs::config::load_config_file(config, Default::default())
            {
                Ok(config) => config,
                Err(err) => panic!("[Load `log4rs` Config File]: {err}"),
            }
        }
        None => default_log4rs_config(),
    };

    /* logger should be configured first! */

    if let Ok(levels) = std::env::var("RUST_LOG") {
        match levels.parse() {
            Ok(level) => {
                logconf.root_mut().set_level(level);
            }
            Err(err) => {
                panic!("[Read `RUST_LOG` Environment Variable]: {err}");
            }
        }
    }

    match log4rs::init_config(logconf) {
        Ok(handler) => handler,
        Err(err) => panic!("[Read `RUST_LOG` Environment Variable]: {err}"),
    };

    /* init appconf persistent/cgi directory */

    let persistroot = appconf.persist.root.as_path();

    for CGIMap { cgi, ..  } in appconf.cgi.mapping.iter() {
        let p = persistroot.join(cgi);

        match std::fs::create_dir_all(p.as_path()) {
            Ok(_) => (),
            Err(err) => panic!("[Init Persistent Directory Faield]: {p:?} {err}", ),
        }
    }

    SERV_CONF.init(appconf).unwrap();

    if let Err(err) = executor::block_on(do_listen()) {
        panic!("[Listen Failed]: {err}");
    };
}


#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn verify_cmd() {
        Cli::command().debug_assert();
    }
}
