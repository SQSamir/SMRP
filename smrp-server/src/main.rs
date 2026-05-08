use smrp_core::conn::SmrpListener;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:9000".to_string());

    let mut listener = SmrpListener::bind(&addr).await?;
    info!("smrp-server listening on {}", listener.local_addr());

    while let Some(mut conn) = listener.accept().await {
        tokio::spawn(async move {
            let peer = conn.peer_addr();
            let sid = hex::encode(conn.session_id());
            info!("+ connection [{sid}] from {peer}");

            while let Ok(Some(data)) = conn.recv().await {
                let text = String::from_utf8_lossy(&data);
                info!("← [{sid}] \"{text}\"");
                if let Err(e) = conn.send(&data).await {
                    tracing::error!("  send error: {e}");
                    break;
                }
                info!("→ [{sid}] echoed");
            }

            info!("- connection [{sid}] closed");
        });
    }

    Ok(())
}
