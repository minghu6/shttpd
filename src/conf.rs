use std::{
    fs::read,
    io::Write,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use brotli::{BrotliCompress, enc::BrotliEncoderParams};
use flate2::{Compression, write::GzEncoder};
use log4rs::Config;
use m6ptr::OnceStatic;
use serde::Deserialize;

pub static SERV_CONF: OnceStatic<ServConf> = OnceStatic::new();


////////////////////////////////////////////////////////////////////////////////
//// Constants


#[cfg(target_os = "linux")]
pub const SERVER_NAME: &str = "SHTTPD/0.0.1 (Linux)";

#[cfg(target_os = "windows")]
pub const SERVER_NAME: &str = "SHTTPD/0.0.1 (Windows)";

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub const SERVER_NAME: &str = "SHTTPD/0.0.1 (Other)";


////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Debug, Clone)]
pub struct ServConf {
    pub cgi: CGI,
    pub doc: Doc,
    pub persist: Persist,
    pub log: Option<Log>,
    pub listen_port: u16,
    /// in milliseconds
    pub timeout: u64,
    /// in bytes
    pub max_header_size: u64,
    /// in bytes
    pub max_body_size: u64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ServConfOpt {
    pub cgi: Option<CGI>,
    pub doc: Option<Doc>,
    pub persist: Option<Persist>,
    pub log: Option<Log>,
    pub listen_port: Option<u16>,
    pub timeout: Option<u64>,
    pub max_header_size: Option<u64>,
    pub max_body_size: Option<u64>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Log {
    pub config: PathBuf,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CGI {
    pub root: PathBuf,
    pub mapping: Vec<CGIMap>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CGIMap {
    pub route: PathBuf,
    pub cgi: PathBuf,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Doc {
    pub root: PathBuf,
    pub index: PathBuf,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Persist {
    pub root: PathBuf,
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl ServConfOpt {
    pub fn resolve(self) -> ServConf {
        let ServConf {
            listen_port: default_listen_port,
            timeout: default_timeout,
            max_header_size: default_max_header_size,
            max_body_size: default_max_body_size,
            ..
        } = ServConf::default();

        let Self {
            cgi,
            doc,
            persist,
            listen_port,
            timeout,
            max_body_size,
            max_header_size,
            log,
        } = self;

        ServConf {
            cgi: cgi.unwrap_or_default(),
            doc: doc.unwrap_or_default(),
            persist: persist.unwrap_or_default(),
            log,
            listen_port: listen_port.unwrap_or(default_listen_port),
            timeout: timeout.unwrap_or(default_timeout),
            max_header_size: max_header_size
                .unwrap_or(default_max_header_size),
            max_body_size: max_body_size.unwrap_or(default_max_body_size),
        }
    }
}

impl Default for CGI {
    fn default() -> Self {
        Self {
            root: "cgi".into(),
            mapping: Default::default(),
        }
    }
}

impl CGI {
    pub fn get(&self, route: &str) -> Option<&CGIMap> {
        self.mapping
            .iter()
            .find(|map| map.route.as_path() == Path::new(route))
    }
}

impl CGIMap {
    pub fn exec_path(&self) -> PathBuf {
        SERV_CONF.cgi.root.join(&self.cgi.as_path())
    }

    pub fn persis_dir(&self) -> PathBuf {
        SERV_CONF.persist.root.join(self.cgi.as_path())
    }
}

impl Doc {
    /// compressed by `Br`
    pub fn index_html_br(&self) -> Result<&[u8], &str> {
        static INDEX_HTML_BR: LazyLock<Result<Vec<u8>, String>> =
            LazyLock::new(|| {
                SERV_CONF
                    .doc
                    .index_html_raw()
                    .map(|raw_content| {
                        let mut compressed_content = Vec::new();

                        BrotliCompress(
                            &mut &raw_content[..],
                            &mut compressed_content,
                            &BrotliEncoderParams::default(),
                        )
                        .map_err(|err| err.to_string())?;

                        Ok(compressed_content)
                    })
                    .map_err(|err| err.to_owned())
                    .flatten()
            });

        INDEX_HTML_BR
            .as_ref()
            .map(|res| res.as_ref())
            .map_err(|err| err.as_str())
    }

    pub fn index_html_gzip(&self) -> Result<&[u8], &str> {
        static INDEX_HTML_GZIP: LazyLock<Result<Vec<u8>, String>> =
            LazyLock::new(|| {
                SERV_CONF
                    .doc
                    .index_html_raw()
                    .map(|raw_content| {
                        let mut gzencoder =
                            GzEncoder::new(Vec::new(), Compression::default());

                        gzencoder.write_all(raw_content).unwrap();

                        Ok(gzencoder.finish().unwrap())
                    })
                    .map_err(|err| err.to_owned())
                    .flatten()
            });

        INDEX_HTML_GZIP
            .as_ref()
            .map(|res| res.as_ref())
            .map_err(|err| err.as_str())
    }

    pub fn index_html_raw(&self) -> Result<&[u8], &str> {
        static INDEX_HTML_RAW: LazyLock<Result<Vec<u8>, String>> =
            LazyLock::new(|| {
                read(SERV_CONF.doc.index_html_path())
                    .map_err(|err| err.to_string())
            });

        INDEX_HTML_RAW
            .as_ref()
            .map(|res| res.as_ref())
            .map_err(|err| err.as_str())
    }

    pub fn index_html_path(&self) -> PathBuf {
        self.root.join(&self.index)
    }
}

impl Default for Doc {
    fn default() -> Self {
        Self {
            root: "./".into(),
            index: "index.html".into(),
        }
    }
}

impl Default for Persist {
    fn default() -> Self {
        Self {
            root: "persistent".into(),
        }
    }
}

impl Default for ServConf {
    fn default() -> Self {
        Self {
            cgi: Default::default(),
            doc: Default::default(),
            persist: Default::default(),
            log: Default::default(),
            listen_port: 80,
            timeout: 5_000, // 5s
            // 16 KB
            max_header_size: 16 * 1024,
            // 16 MB
            max_body_size: 16 * 1024 * 1024,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
//// Functions

pub fn default_log4rs_config() -> Config {
    use log4rs::{
        Config,
        append::console::ConsoleAppender,
        config::{Appender, Root},
        encode::pattern::PatternEncoder,
    };

    // Create a console appender
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d} - {m}{n}")))
        .build();

    // Create the root logger
    let root = Root::builder()
        .appender("stdout")
        .build(log::LevelFilter::Info);

    // Build the configuration
    Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(root)
        .unwrap()
}


#[cfg(test)]
mod tests {

    #[test]
    fn verify_path_join() {
        use std::path::Path;

        let p0 = Path::new("/abc/def/jkl/");

        println!("{:?}", p0.parent());

        let p1 = p0.to_path_buf().join("");

        assert_eq!(p1, p0);
    }
}
