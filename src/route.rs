use std::{
    ffi::OsString, fmt::Write, fs::read_to_string, iter::once_with,
    path::Path, process::Command,
};

use chrono::{DateTime, Local};
use log::info;
use m6io::bstr::ByteString;
use osimodel::application::{
    http::{
        Allow, Body, Chunk, ChunkedBody, Codings, CompleteRequest,
        CompleteResponse, ContentEncoding, Field, Fields, MediaType,
        Method::*, Parameters, Request,
        parameters::ContentCoding,
    },
    mime::{self, TextType},
};
use qstring::QString;

use crate::{
    conf::{CGIMap, SERV_CONF},
    resp::{
        bad_request, chunked_ok, classic_ok, internal, just_ok,
        method_not_allowed, not_acceptable, not_found,
    },
    worker::Secondment,
};

////////////////////////////////////////////////////////////////////////////////
//// Structures

pub struct CGIMessage {
    /// first line
    pub content_type: MediaType,
    pub content: ByteString,
}


////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl TryFrom<ByteString> for CGIMessage {
    type Error = String;

    fn try_from(mut bytes: ByteString) -> Result<Self, Self::Error> {
        let fields_pos = bytes.find(b"\r\n").ok_or("No header fields")?;

        let content = bytes.split_off(fields_pos + 2);
        let fields = bytes.parse::<Fields>().map_err(|err| err.to_string())?;

        let Some(content_type) = fields.content_type().cloned()
        else {
            Err(format!("No content-type in fields"))?
        };

        Ok(Self {
            content_type,
            content,
        })
    }
}

impl<'a> Secondment<'a> {
    pub fn resolve_route(
        &mut self,
        request: CompleteRequest,
    ) -> Result<CompleteResponse, CompleteResponse> {
        let CompleteRequest { request, body } = request;

        let method = request.method;
        let Some(path) = request.target.path()
        else {
            Err(bad_request("No Path"))?
        };
        let q = QString::from(request.target.query().unwrap_or_default());

        Ok(match method {
            Get => {
                /* index html */
                if path == "/" {
                    info!("Get index html");

                    load_static(&request)?
                }
                else if path == "/chunked-text" {
                    info!("Get chunked body");

                    send_chunked_text(self, &request)?
                }
                else if let Some(cgi_map) = SERV_CONF.cgi.get(path) {
                    info!("Get cgi item: {cgi_map:?}");

                    run_cgi(cgi_map, q).map_err(|err| {
                        internal(&format!(
                            "run cgi {cgi_map:#?} failed: {err}"
                        ))
                    })?
                }
                else {
                    info!("Get try access dir {path}");

                    show_file(path).map_err(|err| {
                        internal(&format!("get file info failed: {err}"))
                    })?
                }
            }
            Head => just_ok("".into()),
            Options => classic_ok(
                vec![Field::Allow(
                    Allow::new()
                        .method(Get)
                        .method(Head)
                        .method(Post)
                        .method(Options),
                )],
                vec![],
            ),
            Post => {
                match body {
                    Body::Empty | Body::Complete(..) => {
                        method_not_allowed("Only support ")
                    }
                    Body::Chunked => {
                        // chunked `echo`

                        let mut collected = Vec::new();

                        for chunk_res in self.read_chunks() {
                            let Chunk { data, .. } = chunk_res?;

                            collected.push(data.to_vec());
                        }

                        self.read_trailer_section()?;

                        just_ok(collected.join(&b"\n"[..]))
                    }
                }
            }
            _ => method_not_allowed(""),
        })
    }
}


////////////////////////////////////////////////////////////////////////////////
//// Functions

fn load_static(
    request: &Request,
) -> Result<CompleteResponse, CompleteResponse> {
    use ContentCoding::*;

    /* check accept-encoding */

    let options = [
        (Br, SERV_CONF.doc.index_html_br()),
        (Gzip, SERV_CONF.doc.index_html_gzip()),
    ];

    let (found, maybe_coding) = if let Some(accept_encoding) =
        request.fields.accept_encoding()
    {
        let mut maybe_found = None;

        for (coding, _) in accept_encoding.priority_codings() {
            if let Some(i) = options.iter().position(|(coding2, _res)| {
                Codings::Spec(*coding2) == coding || coding == Codings::Star
            }) {
                maybe_found = Some((options[i].1, Some(options[i].0)));
                break;
            }
        }

        if let Some((found, maybe_coding)) = maybe_found {
            (found, maybe_coding)
        }
        else if accept_encoding
            .rejected_codings()
            .into_iter()
            .find(|coding| {
                *coding == Codings::Identity || *coding == Codings::Star
            })
            .is_some()
        {
            Err(not_acceptable())?
        }
        else {
            (SERV_CONF.doc.index_html_raw(), None)
        }
    }
    else {
        (options[0].1, Some(options[0].0))
    };

    match found {
        // use br to compress static file
        Ok(content) => {
            let mut extra_fields = vec![Field::ContentType(MediaType {
                mime: mime::MediaType::Text(TextType::HTML),
                parameters: Parameters::new(),
            })];

            if let Some(coding) = maybe_coding {
                extra_fields.push(Field::ContentEncoding(
                    ContentEncoding::new().content_coding(coding),
                ));
            }

            Ok(classic_ok(extra_fields, content.into()))
        }
        Err(err) => Err(internal(err)),
    }
}

fn send_chunked_text(
    sec: &mut Secondment,
    _request: &Request,
) -> Result<CompleteResponse, CompleteResponse> {
    let raw =
        "两个黄鹂鸣翠柳，一行白鹭上青天。\n窗含西岭千秋雪，门泊东吴万里船。";

    let chunked_body = ChunkedBody::split_as_chunks(raw.as_bytes().into(), 15);

    let stream = std::iter::from_coroutine(
        #[coroutine]
        || {
            let ChunkedBody {
                chunks,
                last_chunk,
                trailer_section: _,
            } = chunked_body;

            for chunk in chunks {
                yield chunk;
            }

            yield last_chunk;
        },
    );

    sec.set_write_chunks(Box::new(stream));

    Ok(chunked_ok(vec![]))
}

fn run_cgi(cgi_map: &CGIMap, q: QString) -> Result<CompleteResponse, String> {
    let persis_dir = cgi_map.persis_dir().as_os_str().to_owned();

    let envs = q
        .into_pairs()
        .into_iter()
        .map(|(k, v)| {
            (format!("SHTTPD_Q_{}", k.to_uppercase()), OsString::from(v))
        })
        .chain(once_with(|| ("SHTTPD_PERSIS_DIR".to_owned(), persis_dir)));

    let output = Command::new(cgi_map.exec_path())
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
        .map_err(|s| format!("malformed cgi output format: {s}"))?;

    Ok(classic_ok(
        vec![Field::ContentType(cgi.content_type)],
        cgi.content.into(),
    ))
}

fn show_file(path: &str) -> Result<CompleteResponse, String> {
    let subp = path
        .strip_prefix("/")
        .ok_or("invalid path")
        .map_err(|err| err.to_string())?;

    let docp = SERV_CONF.doc.root.join(subp);

    Ok(if docp.is_file() {
        match read_to_string(docp) {
            Ok(content) => just_ok(content.into_bytes()),
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
            Ok(content) => just_ok(content.into_bytes()),
            Err(err) => internal(&err.to_string()),
        }
    }
    else {
        not_found(&format!("not found: {}", docp.to_string_lossy()))
    })
}
