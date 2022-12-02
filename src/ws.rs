use std::{io::Error};

use rocket::tokio::net::{TcpStream, TcpListener};
use tokio_tungstenite::{WebSocketStream, accept_async};


pub type WebSocket = WebSocketStream<TcpStream>;


pub struct WsServer {
    listener: TcpListener,
    handler: fn(WebSocket)
}

impl WsServer {
    pub async fn bind(port: u16, handler: fn(WebSocket)) -> Result<Self, Error> {
        Ok(
            Self {
                listener: TcpListener::bind(format!("0.0.0.0:{port}")).await?,
                handler
            }
        )
    }

    pub async fn start(&self) -> ! {
        loop {
            let stream = match self.listener.accept().await {
                Ok((x, _)) => x,
                Err(_) => continue
            };

            let stream = match accept_async(stream).await {
                Ok(x) => x,
                Err(_) => continue
            };

            (self.handler)(stream);
        }
    }
}
