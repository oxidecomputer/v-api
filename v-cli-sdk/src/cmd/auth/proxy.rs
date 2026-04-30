// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// A callback function that receives an incoming HTTP request and returns a response.
pub type Callback = Arc<
    dyn Fn(
            Request<Incoming>,
        )
            -> std::pin::Pin<Box<dyn Future<Output = anyhow::Result<Response<Full<Bytes>>>> + Send>>
        + Send
        + Sync,
>;

/// Start a minimal HTTP server on the given port that forwards every incoming
/// request to `callback` and returns whatever response the callback produces.
///
/// The server will run until a message is sent on the `shutdown` channel, at
/// which point it will stop accepting new connections and return.
pub async fn run_proxy_server(
    port: u16,
    callback: Callback,
    shutdown: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;
    serve_loop(listener, callback, shutdown).await
}

/// Core accept-loop shared by [`run_proxy_server`] and tests.
///
/// Accepts connections on `listener`, forwarding each request to `callback`.
/// Stops when `shutdown` fires.
async fn serve_loop(
    listener: TcpListener,
    callback: Callback,
    shutdown: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                break;
            }
            accepted = listener.accept() => {
                let (stream, _remote_addr) = accepted?;
                let io = TokioIo::new(stream);
                let cb = Arc::clone(&callback);

                tokio::task::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let cb = Arc::clone(&cb);
                        async move { cb(req).await }
                    });

                    if let Err(err) =
                        hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service)
                            .await
                    {
                        eprintln!("Error serving connection: {err}");
                    }
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::StatusCode;

    #[tokio::test]
    async fn test_proxy_server_responds() {
        let callback: Callback = Arc::new(|_req| {
            Box::pin(async {
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from("hello from callback")))
                    .unwrap())
            })
        });

        let (tx, rx) = oneshot::channel::<()>();

        // Use port 0 to let the OS pick an available port.
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = TcpListener::bind(addr).await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn({
            let callback = Arc::clone(&callback);
            async move {
                serve_loop(listener, callback, rx).await.unwrap();
            }
        });

        // Send a request to the server.
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}", local_addr))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "hello from callback");

        // Shut down the server.
        tx.send(()).unwrap();
        server_handle.await.unwrap();
    }
}
