use chrono::Local;
use m6io::bstr::ByteStr;
use osimodel::application::http::{
    Body::{ Complete, Chunked }, CompleteResponse, Connection, ConnectionOption, Field, FieldName, Fields, Response, Server, StatusCode::{self, *}, TransferCoding, TransferEncoding, Version
};

use crate::conf::SERVER_NAME;


pub fn close(mut complete_response: CompleteResponse) -> CompleteResponse {
    if !complete_response
        .response
        .fields
        .contains(FieldName::Connection)
    {
        complete_response.response.fields.push(Field::Connection(
            Connection::new().connection(ConnectionOption::Close),
        ));
    }

    complete_response
}

/// 200
pub fn just_ok(msg: Vec<u8>) -> CompleteResponse {
    simplified_response(Ok, msg.into_boxed_slice())
}

pub fn classic_ok<'a>(
    extra_fileds: Vec<Field>,
    body: Vec<u8>,
) -> CompleteResponse {
    complete_response(Ok, extra_fileds, body)
}

pub fn chunked_ok<'a>(
    extra_fileds: Vec<Field>,
) -> CompleteResponse {
    let status = StatusCode::Ok;

    let mut fields = Fields {
        values: vec![
            Field::Date(Local::now().into()),
            Field::Server(server_name()),
            Field::TransferEncoding(
                TransferEncoding::new()
                    .transfer_coding(TransferCoding::chunked()),
            ),
        ],
    };

    fields.extend(extra_fileds);

    CompleteResponse {
        response: Response {
            version: Version::HTTP11,
            status,
            reason: Some(status.reason().to_owned()),
            fields,
        },
        body: Chunked,
    }
}

pub fn complete_response<'a>(
    status: StatusCode,
    extra_fileds: Vec<Field>,
    body: Vec<u8>,
) -> CompleteResponse {
    let mut fields = Fields {
        values: vec![
            Field::Date(Local::now().into()),
            Field::Server(server_name()),
        ],
    };

    if !body.is_empty() {
        fields.push(Field::ContentLength(body.len().try_into().unwrap()));
    }

    fields.extend(extra_fileds);

    CompleteResponse {
        response: Response {
            version: Version::HTTP11,
            status,
            reason: Some(status.reason().to_owned()),
            fields,
        },
        body: Complete(body.into_boxed_slice()),
    }
}

/// 400
pub fn bad_request(msg: &str) -> CompleteResponse {
    simplified_response(BadRequest, msg.as_bytes().into())
}

/// 404
pub fn not_found<'a>(msg: &str) -> CompleteResponse {
    simplified_response(NotFound, msg.as_bytes().into())
}

/// 405
pub fn method_not_allowed<'a>(msg: &str) -> CompleteResponse {
    simplified_response(MethodNotAllowed, msg.as_bytes().into())
}

/// 406
pub fn not_acceptable<'a>() -> CompleteResponse {
    simplified_response(NotAcceptable, Box::new([]))
}

///  408
pub fn request_timeout(msg: &str) -> CompleteResponse {
    simplified_response(RequestTimeout, msg.as_bytes().into())
}

/// 411
#[allow(unused)]
pub fn length_required() -> CompleteResponse {
    simplified_response(LengthRequired, Box::new([]))
}

/// 413
pub fn content_too_large() -> CompleteResponse {
    simplified_response(ContentTooLarge, Box::new([]))
}

/// 500
pub fn internal(msg: &str) -> CompleteResponse {
    simplified_response(InternalServerError, msg.as_bytes().into())
}

///
///
fn server_name() -> Server {
    ByteStr::new(SERVER_NAME).parse().unwrap()
}

fn simplified_response(
    status: StatusCode,
    body: Box<[u8]>,
) -> CompleteResponse {
    complete_response(status, vec![], body.to_vec())
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_server_name() {
        let server = server_name();

        println!("{server:#?}");
    }
}
