use crate::{
    constants::{HEADER_LEN, MAX_PACKET},
    error::SmrpError,
    packet::{self, SmrpHeader},
};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Marks outgoing packets as ECN-capable (ECT(0), `0x02`) via `IP_TOS` (IPv4)
/// or `IPV6_TCLASS` (IPv6).  Failures are silently ignored — the config field
/// documents that ECN is best-effort when the OS does not support the option.
#[cfg(unix)]
pub fn apply_ecn_socket_option(socket: &UdpSocket) {
    use std::os::unix::io::AsRawFd;
    let fd = socket.as_raw_fd();
    let ect0: libc::c_int = 0x02; // ECT(0)
    let len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let (level, optname) = match socket.local_addr() {
        Ok(addr) if addr.is_ipv4() => (libc::IPPROTO_IP, libc::IP_TOS),
        _ => (libc::IPPROTO_IPV6, libc::IPV6_TCLASS),
    };
    // SAFETY: fd is valid for the lifetime of socket; ect0 lives on the stack.
    unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            std::ptr::addr_of!(ect0).cast::<libc::c_void>(),
            len,
        );
    }
}

#[cfg(not(unix))]
pub fn apply_ecn_socket_option(_socket: &UdpSocket) {}

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
