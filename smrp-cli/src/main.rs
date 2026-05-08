use smrp_core::conn::SmrpConnection;
use tracing::info;

fn usage() -> ! {
    eprintln!("usage: smrp-cli <server-addr> <message>");
    eprintln!("  e.g. smrp-cli 127.0.0.1:9000 \"hello world\"");
    std::process::exit(1);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let mut args = std::env::args().skip(1);
    let server  = args.next().unwrap_or_else(|| usage());
    let message = args.next().unwrap_or_else(|| usage());

    let mut conn = SmrpConnection::connect(&server).await?;
    info!("connected  peer={} session={}", conn.peer_addr(), hex::encode(conn.session_id()));

    conn.send(message.as_bytes()).await?;
    info!("→ sent: \"{message}\"");

    match conn.recv().await? {
        Some(reply) => info!("← reply: \"{}\"", String::from_utf8_lossy(&reply)),
        None        => info!("← connection closed by server"),
    }

    conn.close().await?;
    info!("done");
    Ok(())
}
