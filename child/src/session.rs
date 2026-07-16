use std::future::Future;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// What the client needs to reach a side-channel session: the ephemeral port
/// (on the same host it already dialed for RPC), the auth token it must send
/// as its first 32 bytes, and how long the offer stays open.
pub struct SessionOffer {
    pub port: u16,
    pub token: Vec<u8>,
    pub ttl_secs: u64,
}

pub const TOKEN_LEN: usize = 32;

fn token_matches(a: &[u8; TOKEN_LEN], b: &[u8; TOKEN_LEN]) -> bool {
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Bind an ephemeral listener and hand the first connection that presents the
/// correct token to `handler`. Connections with a wrong/missing token are
/// dropped but do not consume the offer; the offer dies after `ttl`. The
/// server acks a successful handshake with a single `1` byte before the
/// session protocol begins.
pub async fn open<H, Fut>(ttl: Duration, handler: H) -> std::io::Result<SessionOffer>
where
    H: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind(("0.0.0.0", 0)).await?;
    let port = listener.local_addr()?.port();
    let token: [u8; TOKEN_LEN] = rand::random();

    tokio::spawn(async move {
        let authed = tokio::time::timeout(ttl, async {
            loop {
                let (mut stream, peer) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        eprintln!("session on port {port}: accept failed: {e}");
                        return None;
                    }
                };
                let mut presented = [0u8; TOKEN_LEN];
                let read = tokio::time::timeout(
                    Duration::from_secs(5),
                    stream.read_exact(&mut presented),
                ).await;
                match read {
                    Ok(Ok(_)) if token_matches(&presented, &token) => return Some(stream),
                    _ => eprintln!("session on port {port}: rejected connection from {peer} (bad or missing token)"),
                }
            }
        }).await;

        match authed {
            Ok(Some(mut stream)) => {
                if stream.write_all(&[1u8]).await.is_ok() {
                    handler(stream).await;
                }
            }
            Ok(None) => {}
            Err(_) => eprintln!("session on port {port}: offer expired unused"),
        }
    });

    Ok(SessionOffer { port, token: token.to_vec(), ttl_secs: ttl.as_secs() })
}
