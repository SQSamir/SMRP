//! Minimal SMRP echo server.
//!
//! Usage:
//!   cargo run --example server -- [bind_addr]
//!
//! Default: 0.0.0.0:9000

use smrp_core::conn::SmrpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:9000".into());

    let mut listener = SmrpListener::bind(&addr).await?;
    println!("listening on {addr}");

    while let Some(mut conn) = listener.accept().await {
        let peer = conn.peer_addr();
        let sid = hex::encode(conn.session_id());
        println!("accepted  peer={peer} session={sid}");

        tokio::spawn(async move {
            while let Ok(Some(data)) = conn.recv().await {
                println!("← {peer}/{sid}: {} bytes", data.len());
                if conn.send(&data).await.is_err() {
                    break;
                }
            }
            println!("closed    peer={peer} session={sid}");
        });
    }

    Ok(())
}
