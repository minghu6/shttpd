use std::{
    io::{Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream},
    time::Duration,
};

use futures::executor::ThreadPool;
use log::{error, info, trace, warn};
use m6ptr::WriteIntoBytes;
use osimodel::application::http::{Field, Message};

use crate::{conf::SERV_CONF, route::resolve};

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

pub async fn do_work(mut stream: TcpStream) {
    if let Err(err) =
        stream.set_read_timeout(Some(Duration::from_millis(SERV_CONF.timeout)))
    {
        error!("set read timeout: {err}");
        return;
    }

    if let Err(err) = stream
        .set_write_timeout(Some(Duration::from_millis(SERV_CONF.timeout)))
    {
        error!("set write timeout: {err}");
        return;
    }

    let mut read_buffer = Vec::with_capacity(512);
    let mut write_buffer = Vec::with_capacity(512);

    loop {
        read_buffer.clear();

        let filln = match stream.read_to_end(&mut read_buffer) {
            Ok(fillln) => fillln,
            Err(err) => {
                info!("read from stream: {err}");
                break;
            }
        };

        if filln == 0 {
            warn!("[Empty request]");
            break;
        }

        info!("read {filln} bytes from stream");

        // on guard
        let message = match Message::parse(&read_buffer[..filln]) {
            Ok(message) => message,
            Err(err) => {
                info!("parse http message: {err}");
                break;
            }
        };

        let request = match message {
            Message::Request(request) => request,
            Message::Response(response) => {
                // discard it
                info!("recieve respnse unexpectly: {response:?}");
                break;
            }
        };

        /* maybe need parsing connection: close from request to shutdown */

        let respnse = resolve(&request);

        if let Err(err) = respnse.write_into_bytes(&mut write_buffer) {
            error!("write response to buffer: {err}");
            break;
        }

        if let Err(err) = stream.write_all(&write_buffer) {
            error!("write response[buffered] to stream: {err}");
            break;
        }

        if request
            .fields
            .iter()
            .find(|field| matches!(field, Field::Connection))
            .is_some()
        {
            if let Err(err) = stream.shutdown(Shutdown::Both) {
                error!("shutdown stream: {err}");
            }
            else {
                trace!("shutdown stream: {stream:?}");
            };

            break;
        }
    }
}
