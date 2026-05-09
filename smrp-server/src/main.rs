use smrp_core::{
    config::SmrpConfig,
    conn::SmrpListener,
    crypto::SigningKey,
};
use std::{fs, path::Path, sync::Arc};
use tracing::info;

const KEY_FILE: &str = "smrp_server.key";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:9000".to_string());

    // Load a persistent Ed25519 signing key from disk, or generate one.
    let sign_key = if Path::new(KEY_FILE).exists() {
        let bytes = fs::read(KEY_FILE)?;
        SigningKey::from_pkcs8(&bytes).map_err(|e| format!("bad key file: {e}"))?
    } else {
        let key = SigningKey::generate().map_err(|e| format!("keygen: {e}"))?;
        fs::write(KEY_FILE, key.to_pkcs8())?;
        info!("generated new signing key → {KEY_FILE}");
        key
    };

    info!("identity: {}", hex::encode(sign_key.public_key_bytes()));

    let cfg = Arc::new(SmrpConfig::default());
    let mut listener = SmrpListener::bind_with_config_and_key(&addr, cfg, sign_key).await?;
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
