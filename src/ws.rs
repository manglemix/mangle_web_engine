use std::{io::Error, sync::{Arc}, mem::replace, ops::{DerefMut, Deref}, time::Duration};

use once_cell::sync::OnceCell;
use rocket::{tokio::{net::{TcpStream, TcpListener}, task::JoinHandle, spawn, time::sleep, sync::Mutex}, futures::SinkExt};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

use crate::log::*;


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
                Err(e) => {
                    info!("Error {e:?} while accepting TCP Stream");
                    continue
                }
            };

            let stream = match accept_async(stream).await {
                Ok(x) => x,
                Err(e) => {
                    info!("Error {e:?} while upgrading TCP Stream to WebSocket");
                    continue
                }
            };


            (self.handler)(stream);
        }
    }
}


pub static PING_INTERVAL: OnceCell<Duration> = OnceCell::new();


pub struct WsList {
    sockets: Arc<Mutex<Vec<WebSocket>>>,
    _ping_handle: JoinHandle<()>
}


impl Drop for WsList {
    fn drop(&mut self) {
        self._ping_handle.abort();
    }
}


impl WsList {
    pub fn new() -> Self {
        let sockets: Arc<Mutex<Vec<WebSocket>>> = Default::default();
        let sockets_clone = sockets.clone();

        WsList {
            sockets,
            _ping_handle: spawn(async move {
                let duration = *PING_INTERVAL.get().unwrap();
                loop {
                    sleep(duration).await;
                    
                    Self::send_all_internal(sockets_clone.deref(), Message::Ping("Ping!".as_bytes().into())).await;
                }
            })
        }
    }

    pub async fn add_ws(&self, socket: WebSocket) {
        self.sockets.lock().await.push(socket);
    }

    pub async fn send_all(&self, message: Message) {
        Self::send_all_internal(self.sockets.deref(), message).await;
    }

    async fn send_all_internal(lock: &Mutex<Vec<WebSocket>>, message: Message) {
        let mut lock = lock.lock().await;
        let new_vec = Vec::with_capacity(lock.len());
        let sockets = replace(lock.deref_mut(), new_vec);

        let handles: Vec<_> = sockets
            .into_iter()
            .map(|mut ws| {
                let message = message.clone();

                spawn(async move {
                    if ws.send(message).await.is_err() {
                        None
                    } else {
                        Some(ws)
                    }
                })
            })
            .collect();
        
        for handle in handles {
            match handle.await.unwrap() {
                Some(x) => lock.push(x),
                None => continue
            }
        }
    }
}
