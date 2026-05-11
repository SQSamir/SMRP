//! Minimal SMRP client: connect, send one message, print the echo, close.
//!
//! Usage:
//!   cargo run --example client -- [host:port] [message]
//!
//! Defaults: host=127.0.0.1:9000, message="hello smrp"

use smrp_core::conn::SmrpConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:9000".into());
    let msg = args.next().unwrap_or_else(|| "hello smrp".into());

    let mut conn = SmrpConnection::connect(&addr).await?;
    println!(
        "connected  peer={addr} session={}",
        hex::encode(conn.session_id())
    );

    conn.send(msg.as_bytes()).await?;
    println!("→ sent: {msg:?}");

    if let Some(reply) = conn.recv().await? {
        println!("← reply: {:?}", String::from_utf8_lossy(&reply));
    }

    conn.close().await?;
    println!("done");
    Ok(())
}
