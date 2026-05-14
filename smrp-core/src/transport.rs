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

/// Enables delivery of the IP TOS / IPv6 TCLASS byte as ancillary data on
/// each received datagram, so that CE marks can be detected in [`recv_raw`].
#[cfg(unix)]
pub fn enable_ecn_recv_option(socket: &UdpSocket) {
    use std::os::unix::io::AsRawFd;
    let fd = socket.as_raw_fd();
    let on: libc::c_int = 1;
    let len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let (level, optname) = match socket.local_addr() {
        Ok(addr) if addr.is_ipv4() => (libc::IPPROTO_IP, libc::IP_RECVTOS),
        _ => (libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS),
    };
    // SAFETY: fd is valid for the lifetime of socket; on lives on the stack.
    unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            std::ptr::addr_of!(on).cast::<libc::c_void>(),
            len,
        );
    }
}

#[cfg(not(unix))]
pub fn enable_ecn_recv_option(_socket: &UdpSocket) {}

/// Non-blocking `recvmsg(2)` wrapper that also extracts the ECN CE bit from
/// the `IP_TOS` / `IPV6_TCLASS` ancillary data.
///
/// Returns `(datagram_bytes, sender_addr, ce_marked)`.
/// Errors include `WouldBlock` (no data ready) and `ConnectionReset` (ICMP).
#[cfg(unix)]
fn recv_one_ecn(
    fd: std::os::unix::io::RawFd,
    is_ipv4: bool,
) -> std::io::Result<(Vec<u8>, SocketAddr, bool)> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    let mut data = vec![0u8; MAX_PACKET + 32];
    // SAFETY: zeroed sockaddr_storage is a valid initial state.
    let mut src: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut ctrl = [0u8; 128];
    // SAFETY: zeroed msghdr is valid; all pointer fields are set below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = std::ptr::addr_of_mut!(src).cast();
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as _;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl.as_mut_ptr().cast();
    msg.msg_controllen = ctrl.len() as _;

    // SAFETY: all fields of msg are initialised above; fd is valid.
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let addr = match i32::from(src.ss_family) {
        libc::AF_INET => {
            // SAFETY: ss_family == AF_INET guarantees sockaddr_in layout.
            let s = unsafe { &*std::ptr::addr_of!(src).cast::<libc::sockaddr_in>() };
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(s.sin_addr.s_addr)),
                u16::from_be(s.sin_port),
            ))
        }
        libc::AF_INET6 => {
            // SAFETY: ss_family == AF_INET6 guarantees sockaddr_in6 layout.
            let s = unsafe { &*std::ptr::addr_of!(src).cast::<libc::sockaddr_in6>() };
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(s.sin6_addr.s6_addr),
                u16::from_be(s.sin6_port),
                s.sin6_flowinfo,
                s.sin6_scope_id,
            ))
        }
        _ => return Err(std::io::Error::from_raw_os_error(libc::EAFNOSUPPORT)),
    };

    // Walk the ancillary data chain looking for TOS / TCLASS.
    let mut ce = false;
    // SAFETY: msg was populated by recvmsg; CMSG_* macros are safe to call
    // on a valid msghdr with a properly sized control buffer.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        // SAFETY: cmsg pointer is within the ctrl buffer and was set by the OS.
        let (level, typ) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
        if is_ipv4 && level == libc::IPPROTO_IP && typ == libc::IP_TOS {
            // SAFETY: cmsg data is a single TOS byte for IP_TOS.
            let tos = unsafe { *libc::CMSG_DATA(cmsg) };
            ce = (tos & 0x03) == 0x03;
        } else if !is_ipv4
            && level == libc::IPPROTO_IPV6 as libc::c_int
            && typ == libc::IPV6_TCLASS as libc::c_int
        {
            // SAFETY: cmsg data is a c_int for IPV6_TCLASS.
            let tclass = unsafe { libc::CMSG_DATA(cmsg).cast::<libc::c_int>().read_unaligned() };
            ce = (tclass & 0x03) == 0x03;
        }
        // SAFETY: cmsg and msg are valid pointers set by recvmsg.
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }

    data.truncate(n as usize);
    Ok((data, addr, ce))
}

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

/// Receives one UDP datagram and parses it into
/// `(SmrpHeader, payload_bytes, sender_addr, ce_marked)`.
///
/// `ce_marked` is `true` when the received datagram carries the ECN
/// Congestion-Experienced (CE, `0b11`) mark in its IP TOS / IPv6 TCLASS field.
/// On non-Unix platforms `ce_marked` is always `false`.
///
/// `ConnectionReset` errors are silently retried (Windows ICMP feedback).
///
/// # Errors
/// Returns [`SmrpError::InternalError`] on any non-transient socket failure,
/// or a parsing error from [`packet::parse`] if the datagram is malformed.
pub async fn recv_raw(
    socket: &UdpSocket,
) -> Result<(SmrpHeader, Vec<u8>, SocketAddr, bool), SmrpError> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let is_ipv4 = socket.local_addr().map_or(true, |a| a.is_ipv4());
        loop {
            // Wait for OS readiness, then call recvmsg non-blocking.
            socket
                .readable()
                .await
                .map_err(|_| SmrpError::InternalError)?;
            match recv_one_ecn(fd, is_ipv4) {
                Ok((buf, addr, ce)) => {
                    let header = packet::parse(&buf)?;
                    let payload = if buf.len() > HEADER_LEN {
                        buf[HEADER_LEN..].to_vec()
                    } else {
                        Vec::new()
                    };
                    return Ok((header, payload, addr, ce));
                }
                // Spurious wakeup — re-arm and wait for the next edge.
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                // Windows-style ICMP feedback on a closed peer port — transient.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
                Err(_) => return Err(SmrpError::InternalError),
            }
        }
    }
    #[cfg(not(unix))]
    {
        loop {
            let mut buf = vec![0u8; MAX_PACKET + 32];
            let (len, addr) = match socket.recv_from(&mut buf).await {
                Ok(t) => t,
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
            return Ok((header, payload, addr, false));
        }
    }
}
