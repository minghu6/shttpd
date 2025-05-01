use std::{
    io::{Cursor, ErrorKind, IoSlice, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream},
    time::Duration,
};

use futures::executor::ThreadPool;
use log::{error, trace, warn};
use m6io::{ByteStr, WriteIntoBytes};
use osimodel::application::http::{
    Body, Chunk, ChunkHeader, CompleteRequest, CompleteResponse, Fields, Request, Response, StartLine
};

use crate::{
    conf::SERV_CONF,
    resp::{bad_request, close, content_too_large, internal, request_timeout},
};


////////////////////////////////////////////////////////////////////////////////
//// Structures

pub struct Secondment<'a> {
    stream: &'a mut TcpStream,
    buffer: &'a mut [u8],
    filled: usize,
    read: usize,
    write_chunks: Option<Box<dyn Iterator<Item = Chunk> + 'a>>
}

// struct Watch {
//     instant: Instant,
// }

////////////////////////////////////////////////////////////////////////////////
//// Implementations

// impl Watch {
//     fn start() -> Self {
//         Self {
//             instant: Instant::now(),
//         }
//     }

//     fn timeout(&self) -> bool {
//         if self.instant.elapsed().as_millis() > SERV_CONF.timeout as u128 {
//             true
//         }
//         else {
//             false
//         }
//     }
// }

/// buffer utils
impl<'a> Secondment<'a> {
    fn consume(&mut self, n: usize) {
        self.read += n;

        if self.read > self.filled {
            self.read = self.filled;
        }
    }

    #[allow(unused)]
    fn discard_buffer(&mut self) {
        self.read = 0;
        self.filled = 0;
    }

    fn filled_buffer(&self) -> &ByteStr {
        ByteStr::new(&self.buffer[..self.filled])
    }

    fn unread_buffer(&self) -> &ByteStr {
        ByteStr::new(&self.buffer[self.read..self.filled])
    }

    /// move unread content to the buffer top
    fn re_buffer(&mut self) {
        // move copy

        unsafe {
            std::ptr::copy(
                self.buffer.as_ptr(),
                self.buffer.as_mut_ptr().byte_add(self.read),
                self.filled - self.read,
            )
        }

        self.filled = self.filled - self.read;
        self.read = 0;
    }

    pub(crate) fn set_write_chunks(&mut self, write_chunks: Box<dyn Iterator<Item = Chunk> + 'a>) {
        self.write_chunks = Some(write_chunks)
    }
}

impl<'a> Secondment<'a> {
    fn resolve_work(&mut self) -> Result<CompleteResponse, CompleteResponse> {
        self.do_read("request")?;

        let buf = self.filled_buffer();

        let Some(startline_epos) = ByteStr::new(buf).find(b"\r\n")
        else {
            Err(bad_request("no start-line (endswith CRLF)"))?
        };

        let start_line = match buf[..startline_epos].parse::<StartLine>() {
            Ok(startline) => startline,
            Err(err) => {
                Err(bad_request(&format!("invalid start-line for {err}")))?
            }
        };

        dbg!(&start_line);

        let StartLine::RequestLine(request_line) = start_line
        else {
            Err(bad_request(&format!("found status-line {start_line:#?}")))?
        };

        let Some(fields_epos) = buf.find(b"\r\n\r\n")
        else {
            Err(bad_request("no fields (\"\r\n\r\n\")"))?
        };

        let fields =
            match buf[startline_epos + 2..fields_epos + 2].parse::<Fields>() {
                Ok(fields) => fields,
                Err(err) => {
                    Err(bad_request(&format!("malformed fields for {err:?}")))?
                }
            };

        dbg!(&fields);

        let body_spos = fields_epos + 4;

        dbg!(&buf[body_spos..]);

        let body = if let Some(trans_encoding) = fields.trans_encoding() {
            if trans_encoding.is_chunked() {
                self.consume(body_spos);

                Body::Chunked
            }
            else {
                Err(bad_request(
                    "only accept `chunked` in Transfer-Encoding field",
                ))?
            }
        }
        else if let Some(content_length) = fields.content_length() {
            if content_length > SERV_CONF.max_body_size {
                Err(content_too_large())?
            }

            let body_epos = body_spos + content_length as usize;

            let body = if body_epos > buf.len() {
                let mut body = unsafe {
                    Box::<[u8]>::new_uninit_slice(content_length as usize)
                        .assume_init()
                };

                let readn = body_epos - buf.len();

                body.copy_from_slice(&buf[body_spos..body_spos + readn]);

                if let Err(err) = self.stream.read_exact(&mut body[readn..]) {
                    Err(if err.kind() == ErrorKind::TimedOut {
                        request_timeout("read message body")
                    }
                    else {
                        bad_request(&format!("uncompleted body for {err}"))
                    })?
                }

                body
            }
            else {
                buf[body_spos..body_epos].to_owned().into()
            };

            self.consume(body_epos);

            Body::Complete(body)
        }
        else {
            self.consume(body_spos);

            Body::Empty
        };

        let request = Request::from_parts(request_line, fields);
        let complete_request = CompleteRequest::from_parts(request, body);

        self.resolve_route(complete_request)
    }

    fn read_chunk(&mut self) -> Result<Chunk, CompleteResponse> {
        let mut buf = self.unread_buffer();

        let hdr_epos = if let Some(hdr_epos) = buf.find(b"\r\n") {
            hdr_epos
        }
        else {
            self.re_buffer();
            self.do_read("rem chunk")?;
            buf = self.unread_buffer();

            let Some(hdr_epos) = buf.find(b"\r\n")
            else {
                Err(bad_request(&format!("no chunk header found")))?
            };

            hdr_epos
        };

        dbg!(&buf[..hdr_epos]);
        dbg!(buf.decode_as_utf8().unwrap());

        let header = buf[..hdr_epos].parse::<ChunkHeader>().map_err(|s| {
            bad_request(&format!("malformed chunk header {s}"))
        })?;

        let data_spos = hdr_epos + 2;
        let data_epos = data_spos + header.size as usize;

        if data_epos > buf.len() {
            Err(bad_request(&format!(
                "uncompleted chunk data need {} bytes found {} bytes",
                header.size, self.filled
            )))?
        }

        let data = buf[data_spos..data_epos].to_owned();

        if !header.is_last() {
            self.consume(data_epos + 2); // extra CRLF
        }
        else {
            self.consume(data_epos);
            // remains trailer-section CRLF
        }

        Ok(Chunk::from_parts(header, data))
    }

    pub(crate) fn read_chunks(
        &mut self,
    ) -> impl Iterator<Item = Result<Chunk, CompleteResponse>> {
        std::iter::from_coroutine(
            #[coroutine]
            || {
                loop {
                    match self.read_chunk() {
                        Ok(chunk) => {
                            let is_last = chunk.is_last();

                            yield Ok(chunk);

                            if is_last {
                                break;
                            }
                        }
                        Err(err) => {
                            yield Err(err);
                            break;
                        }
                    }
                }
            },
        )
    }

    pub(crate) fn read_trailer_section(
        &mut self,
    ) -> Result<Fields, CompleteResponse> {
        let buf = self.unread_buffer();

        dbg!(buf);

        let fields = if let Some(fields_epos) = buf.find(b"\r\n\r\n") {
            let fields = buf[..fields_epos + 2].parse::<Fields>().map_err(|err| {
                bad_request(&format!("malformed trailer section for {err:?}"))
            })?;

            self.consume(fields_epos + 4);

            fields
        }
        else if let Some(chunked_body_epos) = buf.find(b"\r\n") {
            self.consume(chunked_body_epos + 2);
            Fields::new()
        }
        else {
            Err(bad_request(&format!("no trailer section")))?
        };

        Ok(fields)
    }

    fn do_read(&mut self, ident: &str) -> Result<usize, CompleteResponse> {
        let n = self.stream.read(&mut self.buffer[self.filled..]).map_err(
            |err| {
                use std::io::ErrorKind::*;

                match err.kind() {
                    TimedOut => {
                        request_timeout(&format!("read {ident} timeout"))
                    }
                    err => close(bad_request(&format!("read {ident} {err}"))),
                }
            },
        )?;

        self.filled += n;

        Ok(n)
    }

    fn write_complete_response(
        &mut self,
        complete_response: &CompleteResponse,
    ) -> Result<(), CompleteResponse> {
        let CompleteResponse { response, body } = complete_response;

        match body {
            Body::Empty => todo!(),
            Body::Complete(body) => {
                self.write_complete_body(response, &body[..])?;
            },
            Body::Chunked => {
                self.write_chunked_body(response)?;
            },
        }

        Ok(())
    }

    fn write_complete_body(
        &mut self,
        response: &Response,
        body: &[u8],
    ) -> Result<(), CompleteResponse> {
        let mut write_buffer = unsafe {
            Box::<[u8]>::new_uninit_slice(SERV_CONF.max_body_size as usize)
                .assume_init()
        };

        if body.len() > SERV_CONF.max_body_size as usize {
            let err_msg = &format!(
                "payload exceed limit {}",
                SERV_CONF.max_body_size
            );

            warn!("{err_msg}");
            Err(internal(&err_msg))?
        }

        // debug!("{response:?}");

        let slice0 = match response
            .write_into_bytes(&mut Cursor::new(&mut write_buffer[..]))
        {
            Ok(n) => &write_buffer[..n],
            Err(err) => Err(internal(&err.to_string()))?,
        };

        let slice1 = ByteStr::new(&body[..]);

        let mut iov =
            &mut [IoSlice::new(slice0), IoSlice::new(slice1)][..];

        /* copy & modifiey from write_all_vectored */

        IoSlice::advance_slices(&mut iov, 0);

        while !iov.is_empty() {
            match self.stream.write_vectored(iov) {
                Ok(n) => {
                    IoSlice::advance_slices(&mut iov, n)
                }
                // Err(ref err) if err.kind() == ErrorKind::WouldBlock =>  {
                //     if watch.timeout() {
                //         Err(request_timeout())?
                //     }
                // },
                Err(ref err) if err.kind() == ErrorKind::TimedOut => {
                    Err(request_timeout("write response timeout"))?
                }
                Err(err) => Err(internal(&err.to_string()))?,
            }
        }

        Ok(())
    }

    fn write_chunked_body(&mut self,
        response: &Response,
    ) -> Result<(), CompleteResponse>  {
        let mut write_buffer = unsafe {
            Box::<[u8]>::new_uninit_slice(SERV_CONF.max_body_size as usize)
                .assume_init()
        };

        let header_buffer = match response
            .write_into_bytes(&mut Cursor::new(&mut write_buffer[..]))
        {
            Ok(n) => &write_buffer[..n],
            Err(err) => Err(internal(&err.to_string()))?,
        };

        match self.stream.write(&header_buffer) {
            Ok(_) => {
                ()
            }
            Err(ref err) if err.kind() == ErrorKind::TimedOut => {
                Err(request_timeout("write header timeout"))?
            }
            Err(err) => Err(internal(&err.to_string()))?,
        }

        let Some(chunks) = self.write_chunks.take() else {
            Err(internal("not set write chunks"))?
        };

        for chunk in chunks {
            let chunk_buffer = match chunk.write_into_bytes(&mut Cursor::new(&mut write_buffer[..])) {
                Ok(n) => &write_buffer[..n],
                Err(err) => Err(internal(&err.to_string()))?,
            };

            match self.stream.write(&chunk_buffer) {
                Ok(_) => {
                    ()
                }
                Err(ref err) if err.kind() == ErrorKind::TimedOut => {
                    Err(request_timeout("write chunk timeout"))?
                }
                Err(err) => Err(internal(&err.to_string()))?,
            }
        }

        // write no trailer-section
        match self.stream.write(b"\r\n") {
            Ok(_) => {
                ()
            }
            Err(ref err) if err.kind() == ErrorKind::TimedOut => {
                Err(request_timeout("write chunked-body timeout"))?
            }
            Err(err) => Err(internal(&err.to_string()))?,
        }

        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////
//// Functions

pub async fn do_work(mut stream: TcpStream) {
    /* set timeout for blocking mode and read_all */

    if let Err(err) =
        stream.set_read_timeout(Some(Duration::from_millis(SERV_CONF.timeout)))
    {
        error!("[Set Read Timeout]: {err}");
        return;
    }

    if let Err(err) = stream
        .set_write_timeout(Some(Duration::from_millis(SERV_CONF.timeout)))
    {
        error!("[Set Write Timeout]: {err}");
        return;
    }

    // // avoid block when buffer is filled fully
    // if let Err(err) = stream.set_nonblocking(true) {
    //     error!("[Set Nonblocking]: {err}");
    //     return;
    // }

    let mut buffer = unsafe {
        Box::<[u8]>::new_uninit_slice(SERV_CONF.max_header_size as usize)
            .assume_init()
    };

    let mut assist = Secondment {
        buffer: &mut buffer,
        stream: &mut stream,
        read: 0,
        filled: 0,
        write_chunks: None
    };

    /* persistent connection >= HTTP/1.1 */

    loop {
        let mut complete_response = assist
            .resolve_work()
            .unwrap_or_else(|respnse| close(respnse));

        /* two phase write */

        /* phase-1 try write */

        if let Err(complete_response_2nd) =
            assist.write_complete_response(&complete_response)
        {
            /* phase-2 write must successful response */

            dbg!(&complete_response_2nd);

            complete_response = complete_response_2nd;

            if let Err(CompleteResponse { response, body }) =
                assist.write_complete_response(&complete_response)
            {
                let Body::Complete(body) = body
                else {
                    unreachable!()
                };

                warn!(
                    "write second response failed {:?}:\n{}",
                    response.status,
                    String::from_utf8_lossy(&body)
                );
                break;
            }
        }

        if complete_response.response.closed() {
            break;
        }
    }

    /* clean-up */

    drop(assist);

    if let Err(err) = stream.shutdown(Shutdown::Both) {
        error!("shutdown stream: {err}");
    }
    else {
        trace!("shutdown stream: {stream:?}");
    };
}

pub async fn do_listen() -> Result<(), String> {
    let servaddr =
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, SERV_CONF.listen_port);

    let listener =
        TcpListener::bind(servaddr).map_err(|err| err.to_string())?;

    let pool = ThreadPool::new().map_err(|err| err.to_string())?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                pool.spawn_ok(do_work(stream));
            }
            Err(err) => Err(err.to_string())?,
        };
    }

    Ok(())
}
