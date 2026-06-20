//! Socket construction + accelerated data-plane primitives.
//!
//! Portable builders use `socket2`. The hot path uses raw syscalls so we can
//! reach the kernel offloads (`UDP_SEGMENT`/`UDP_GRO`, `sendmmsg`/`recvmmsg`).
//! Every accelerated call has a portable fallback in `engine.rs`.

use anyhow::{Context, Result};
use socket2::{Domain, Protocol as S2Proto, SockAddr, Socket, Type};
use std::mem::MaybeUninit;
use std::net::SocketAddr;

/// socket2 wants `&mut [MaybeUninit<u8>]`; our buffers are already initialised,
/// so reinterpreting them for a write target is sound.
#[inline]
fn as_uninit(buf: &mut [u8]) -> &mut [MaybeUninit<u8>] {
    unsafe { &mut *(buf as *mut [u8] as *mut [MaybeUninit<u8>]) }
}

pub fn recv_into(sock: &Socket, buf: &mut [u8]) -> std::io::Result<usize> {
    sock.recv(as_uninit(buf))
}

pub fn recv_from_into(sock: &Socket, buf: &mut [u8]) -> std::io::Result<(usize, SockAddr)> {
    sock.recv_from(as_uninit(buf))
}

pub const DEFAULT_RCVBUF: usize = 8 * 1024 * 1024;
pub const DEFAULT_SNDBUF: usize = 8 * 1024 * 1024;

fn domain_of(addr: &SocketAddr) -> Domain {
    if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    }
}

fn apply_reuse(s: &Socket, reuseport: bool) -> Result<()> {
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    if reuseport {
        // Best-effort: kernels without SO_REUSEPORT just keep one queue.
        let _ = s.set_reuse_port(true);
    }
    #[cfg(not(unix))]
    let _ = reuseport;
    Ok(())
}

/// A connected UDP data socket (matches btest.exe: connect() the peer, big
/// SO_RCVBUF), tuned and ready for the hot loop.
pub fn udp_data_socket(
    local: SocketAddr,
    remote: SocketAddr,
    reuseport: bool,
    rcvbuf: usize,
    sndbuf: usize,
) -> Result<Socket> {
    let s = Socket::new(domain_of(&local), Type::DGRAM, Some(S2Proto::UDP))?;
    apply_reuse(&s, reuseport)?;
    let _ = s.set_recv_buffer_size(rcvbuf);
    let _ = s.set_send_buffer_size(sndbuf);
    s.bind(&local.into())
        .with_context(|| format!("udp bind {local}"))?;
    s.connect(&remote.into())
        .with_context(|| format!("udp connect {remote}"))?;
    Ok(s)
}

/// A bound, listening UDP socket (server side) before we know the peer.
pub fn udp_listen_socket(local: SocketAddr, reuseport: bool, rcvbuf: usize) -> Result<Socket> {
    let s = Socket::new(domain_of(&local), Type::DGRAM, Some(S2Proto::UDP))?;
    apply_reuse(&s, reuseport)?;
    let _ = s.set_recv_buffer_size(rcvbuf);
    s.bind(&local.into())
        .with_context(|| format!("udp bind {local}"))?;
    Ok(s)
}

pub fn tcp_listener(local: SocketAddr, reuseport: bool) -> Result<Socket> {
    let s = Socket::new(domain_of(&local), Type::STREAM, Some(S2Proto::TCP))?;
    apply_reuse(&s, reuseport)?;
    s.bind(&local.into())
        .with_context(|| format!("tcp bind {local}"))?;
    s.listen(1024)?;
    Ok(s)
}

pub fn tune_tcp_stream(s: &Socket) {
    let _ = s.set_recv_buffer_size(DEFAULT_RCVBUF);
    let _ = s.set_send_buffer_size(DEFAULT_SNDBUF);
    // Bulk transfer: Nagle off so our large writes hit the wire immediately;
    // TSO/LRO in the NIC still does the heavy segmentation/coalescing.
    let _ = s.set_nodelay(true);
}

// =====================================================================
// Linux accelerated data plane (raw fd)
// =====================================================================

#[cfg(target_os = "linux")]
pub mod accel {
    use crate::sys::linux_consts::*;
    use libc::{c_int, c_void};
    use std::io;
    use std::os::unix::io::RawFd;

    /// GSO send on a *connected* UDP socket: hand the kernel one big buffer and
    /// a segment size; it (or the NIC) slices it into `segment`-sized datagrams.
    /// One syscall replaces dozens. `segment == 0` => ordinary send.
    pub unsafe fn send_gso(fd: RawFd, buf: &[u8], segment: u16) -> io::Result<usize> {
        let mut iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut c_void,
            iov_len: buf.len(),
        };
        let mut cbuf = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if segment > 0 {
            msg.msg_control = cbuf.as_mut_ptr() as *mut c_void;
            msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = SOL_UDP;
            (*cmsg).cmsg_type = UDP_SEGMENT;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut u16, segment);
        }
        let n = libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL);
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Enable UDP_GRO so recvmsg returns coalesced super-datagrams.
    pub unsafe fn enable_gro(fd: RawFd) -> bool {
        let on: c_int = 1;
        libc::setsockopt(
            fd,
            SOL_UDP,
            UDP_GRO,
            &on as *const _ as *const c_void,
            std::mem::size_of::<c_int>() as libc::socklen_t,
        ) == 0
    }

    /// GRO recv: returns (total_bytes, segment_size). With GRO the kernel may
    /// return many MTU-sized datagrams as one read; segment_size tells us how
    /// they were packed (== total when no coalescing happened).
    pub unsafe fn recv_gro(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, usize)> {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut c_void,
            iov_len: buf.len(),
        };
        let mut cbuf = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = cbuf.len() as _;
        let n = libc::recvmsg(fd, &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut seg = n as usize;
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == SOL_UDP && (*cmsg).cmsg_type == UDP_GRO {
                let v = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const c_int);
                if v > 0 {
                    seg = v as usize;
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
        Ok((n as usize, seg))
    }

    /// Send the same buffer as `count` datagrams in a single `sendmmsg` syscall.
    pub unsafe fn sendmmsg_same(fd: RawFd, buf: &[u8], count: usize) -> io::Result<usize> {
        let mut iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut c_void,
            iov_len: buf.len(),
        };
        let mut msgs: Vec<libc::mmsghdr> = (0..count)
            .map(|_| {
                let mut m: libc::mmsghdr = std::mem::zeroed();
                m.msg_hdr.msg_iov = &mut iov;
                m.msg_hdr.msg_iovlen = 1;
                m
            })
            .collect();
        let n = libc::sendmmsg(fd, msgs.as_mut_ptr(), count as _, libc::MSG_NOSIGNAL);
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Receive up to `slots` datagrams of `slot_len` each into `buf` in one
    /// `recvmmsg` syscall. Returns (datagrams, total_bytes).
    pub unsafe fn recvmmsg_into(
        fd: RawFd,
        buf: &mut [u8],
        slot_len: usize,
        slots: usize,
    ) -> io::Result<(usize, usize)> {
        let mut iovs: Vec<libc::iovec> = Vec::with_capacity(slots);
        for i in 0..slots {
            iovs.push(libc::iovec {
                iov_base: buf[i * slot_len..].as_mut_ptr() as *mut c_void,
                iov_len: slot_len,
            });
        }
        let mut msgs: Vec<libc::mmsghdr> = (0..slots)
            .map(|i| {
                let mut m: libc::mmsghdr = std::mem::zeroed();
                m.msg_hdr.msg_iov = &mut iovs[i];
                m.msg_hdr.msg_iovlen = 1;
                m
            })
            .collect();
        let n = libc::recvmmsg(
            fd,
            msgs.as_mut_ptr(),
            slots as _,
            libc::MSG_WAITFORONE,
            std::ptr::null_mut(),
        );
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut total = 0usize;
        for m in msgs.iter().take(n as usize) {
            total += m.msg_len as usize;
        }
        Ok((n as usize, total))
    }
}
