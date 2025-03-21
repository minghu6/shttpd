use std::{
    fmt::Write, fs::read_to_string, iter::once_with, path::Path,
    process::Command,
};

use chrono::{DateTime, Local};
use log::info;
use m6ptr::{ByteString, FromBytesAs};
use osimodel::application::http::{
    MediaType,
    Method::*,
    Request,
    parameters::ContentCoding,
    writing::{FieldBuf, MediaTypeBuf, ResponseBuf},
};
use qstring::QString;

use crate::{
    conf::{CGIMap, SERV_CONF},
    resp::{classic_ok, internal, just_ok, method_not_allowed, not_found},
};

////////////////////////////////////////////////////////////////////////////////
//// Structures


pub struct CGIMessage {
    /// first line
    pub content_type: MediaTypeBuf,
    pub content: ByteString,
}


////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl TryFrom<ByteString> for CGIMessage {
    type Error = ();

    fn try_from(mut bytes: ByteString) -> Result<Self, Self::Error> {
        let ln_1st_pos = bytes.find(b'\n').ok_or(())?;

        let content = bytes.split_off(ln_1st_pos + 1);
        let content_type =
            MediaType::from_bytes_as(&bytes.as_ref().into())?.into();

        Ok(Self {
            content_type,
            content,
        })
    }
}


pub fn resolve<'a>(request: &Request<'a>) -> ResponseBuf {
    let method = request.method;
    let path = request.target.path();
    let q = QString::from(request.target.query().unwrap_or_default());

    info!("Incomming request: {:#?}", request);

    match method {
        Get => {
            /* index html */
            if path == "/" {
                info!("Get index html");

                match SERV_CONF.doc.index_html() {
                    // use br to compress static file
                    Ok(content) => classic_ok(
                        vec![vec![ContentCoding::Br].into()],
                        content.into(),
                    ),
                    Err(err) => internal(err),
                }
            }
            else if let Some(cgi_map) = SERV_CONF.cgi.get(path) {
                info!("Get cgi item: {cgi_map:?}");

                run_cgi(cgi_map, q).unwrap_or_else(|err| {
                    internal(&format!("run cgi error: {err}"))
                })
            }
            else {
                info!("Get try access dir {path}");

                show_file(path).unwrap_or_else(|err| {
                    internal(&format!("get file info failed: {err}"))
                })
            }
        }
        _ => method_not_allowed(),
    }
}

fn run_cgi(cgi_map: &CGIMap, q: QString) -> Result<ResponseBuf, String> {
    let persis_dir = cgi_map
        .persis_dir()?
        .to_str()
        .ok_or("invalid persist directory")?
        .to_owned();

    let envs = q
        .into_pairs()
        .into_iter()
        .map(|(k, v)| (format!("SHTTPD_Q_{}", k.to_uppercase()), v))
        .chain(once_with(|| ("SHTTPD_PERSIS_DIR".to_owned(), persis_dir)));

    let output = Command::new(cgi_map.exec_path()?)
        .envs(envs)
        .output()
        .map_err(|err| err.to_string())?;

    if !output.stderr.is_empty() {
        Err(std::str::from_utf8(output.stderr.as_ref())
            .map_err(|err| format!("decode (utf8) cgi error output {err}"))
            .unwrap())?;
    }

    let raw_out: ByteString = output.stdout.into();

    let cgi: CGIMessage = raw_out
        .try_into()
        .map_err(|_| "malformed cgi output format".to_owned())?;

    Ok(classic_ok(
        vec![FieldBuf::ContentType(cgi.content_type)],
        cgi.content,
    ))
}

fn show_file(path: &str) -> Result<ResponseBuf, String> {
    let subp = path
        .strip_prefix("/")
        .ok_or("invalid path")
        .map_err(|err| err.to_string())?;

    let docp = SERV_CONF.doc.root.join(subp);

    Ok(if docp.is_file() {
        match read_to_string(docp) {
            Ok(content) => just_ok(content.into_bytes().into()),
            Err(err) => internal(&err.to_string()),
        }
    }
    else if docp.is_dir() {
        fn show_dir(p: &Path) -> Result<String, String> {
            let mut buffer = String::new();

            for entry_res in p.read_dir().map_err(|err| err.to_string())? {
                let entry = entry_res.map_err(|err| err.to_string())?;

                let path = entry.path();
                let name = path.file_name().unwrap().to_string_lossy();
                let meta = entry.metadata().map_err(|err| err.to_string())?;

                let file_type = if meta.is_file() {
                    "-"
                }
                else if meta.is_dir() {
                    "d"
                }
                else if meta.is_symlink() {
                    "s"
                }
                else {
                    ""
                };

                let date_time = DateTime::<Local>::from(
                    if let Ok(modified_time) = meta.modified() {
                        modified_time
                    }
                    else if let Ok(created_time) = meta.created() {
                        created_time
                    }
                    else {
                        Err(format!(
                            "{path:?} get modify/create meta field failed",
                        ))?
                    },
                )
                .to_rfc2822();

                writeln!(&mut buffer, "{file_type:2} {date_time} {name:<20}")
                    .unwrap();
            }

            Ok(buffer)
        }

        match show_dir(&docp) {
            Ok(content) => just_ok(content.into_bytes().into()),
            Err(err) => internal(&err.to_string()),
        }
    }
    else {
        not_found(&docp.to_string_lossy())
    })
}
