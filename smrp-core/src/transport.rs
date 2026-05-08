use crate::{
    constants::{HEADER_LEN, MAX_PACKET},
    error::SmrpError,
    packet::{self, SmrpHeader},
};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Serialises `header` + `payload` into a single UDP datagram and sends it to `addr`.
///
/// # Errors
/// Returns [`SmrpError::InternalError`] on socket failure.
pub async fn send_raw(
    socket: &UdpSocket,
    addr: SocketAddr,
    header: &SmrpHeader,
    payload: &[u8],
) -> Result<(), SmrpError> {
    let hdr_bytes = packet::serialize(header);
    let mut buf = Vec::with_capacity(HEADER_LEN + payload.len());
    buf.extend_from_slice(&hdr_bytes);
    buf.extend_from_slice(payload);
    socket
        .send_to(&buf, addr)
        .await
        .map_err(|_| SmrpError::InternalError)?;
    Ok(())
}

/// Receives one UDP datagram and parses it into `(SmrpHeader, payload_bytes, sender_addr)`.
///
/// `ConnectionReset` errors are silently retried: on Windows, sending to a
/// closed UDP port causes the OS to deliver an ICMP "port unreachable" message
/// back to the socket as `WSAECONNRESET`.  This is not a real failure — the
/// loop simply waits for the next genuine datagram.
///
/// # Errors
/// Returns [`SmrpError::InternalError`] on any non-transient socket failure,
/// or a parsing error from [`packet::parse`] if the datagram is malformed.
pub async fn recv_raw(socket: &UdpSocket) -> Result<(SmrpHeader, Vec<u8>, SocketAddr), SmrpError> {
    loop {
        let mut buf = vec![0u8; MAX_PACKET + 32];
        let (len, addr) = match socket.recv_from(&mut buf).await {
            Ok(t) => t,
            // ICMP "port unreachable" feedback from a closed peer — transient, retry.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
            Err(_) => return Err(SmrpError::InternalError),
        };
        buf.truncate(len);
        let header = packet::parse(&buf)?;
        let payload = if buf.len() > HEADER_LEN {
            buf[HEADER_LEN..].to_vec()
        } else {
            Vec::new()
        };
        return Ok((header, payload, addr));
    }
}
