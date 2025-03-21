use chrono::Local;
use m6ptr::{ByteStr, ByteString, FromBytesAs};
use osimodel::application::http::{
    Server,
    StatusCode::{self, *},
    Version,
    writing::{FieldBuf, FieldsBuf, ResponseBuf, ServerBuf},
};

use crate::conf::SERVER_NAME;

/// 200
pub fn just_ok(msg: ByteString) -> ResponseBuf {
    error_response(Ok, msg)
}

pub fn classic_ok<'a>(
    extra_fileds: Vec<FieldBuf>,
    body: ByteString,
) -> ResponseBuf {
    let status = Ok;

    ResponseBuf {
        version: Version::HTTP11,
        status,
        reason: Some(status.reason().to_owned()),
        fields: FieldsBuf {
            fields: vec![
                vec![
                    FieldBuf::Date(Local::now().into()),
                    FieldBuf::Server(server_name()),
                ],
                extra_fileds,
            ]
            .into_iter()
            .flatten()
            .collect(),
        },
        body,
    }
}

/// 404
pub fn not_found<'a>(msg: &str) -> ResponseBuf {
    error_response(NotFound, msg.as_bytes().into())
}

/// 405
pub fn method_not_allowed<'a>() -> ResponseBuf {
    error_response(MethodNotAllowed, b"".into())
}

/// 500
pub fn internal(msg: &str) -> ResponseBuf {
    error_response(InternalServerError, msg.as_bytes().into())
}

fn server_name() -> ServerBuf {
    Server::from_bytes_as(&ByteStr::new(SERVER_NAME).into())
        .unwrap()
        .into()
}

fn error_response(status: StatusCode, body: ByteString) -> ResponseBuf {
    ResponseBuf {
        version: Version::HTTP11,
        status,
        reason: Some(status.reason().to_owned()),
        fields: FieldsBuf {
            fields: vec![
                FieldBuf::Date(Local::now().into()),
                FieldBuf::Server(server_name()),
            ],
        },
        body,
    }
}
