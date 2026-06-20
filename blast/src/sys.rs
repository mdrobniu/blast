//! Platform/hardware facilities: CPU topology, core pinning, and a buffer
//! allocator that prefers hugepages (fewer TLB misses on the hot path) and
//! falls back gracefully everywhere else.

use std::ops::{Deref, DerefMut};

/// Linux socket-option numbers that older `libc` releases may not re-export.
#[cfg(target_os = "linux")]
pub mod linux_consts {
    pub const SOL_UDP: libc::c_int = 17; // IPPROTO_UDP
    pub const UDP_SEGMENT: libc::c_int = 103; // GSO: kernel/NIC segments one big send
    pub const UDP_GRO: libc::c_int = 104; // GRO: kernel coalesces datagrams on recv
}

pub fn available_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Pin the calling thread to a specific logical core. Aligning workers with the
/// NIC's RX queues keeps each flow on one core and its cache. No-op off Linux.
pub fn pin_to_core(idx: usize) -> bool {
    #[cfg(target_os = "linux")]
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(idx % available_cores(), &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) == 0
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = idx;
        false
    }
}

/// Number of hugepages configured on the system (Linux), else 0.
pub fn hugepages_available() -> usize {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/vm/nr_hugepages")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// A page-aligned data buffer. Hugepage-backed when possible, else heap.
pub enum Buffer {
    Heap(Vec<u8>),
    #[cfg(target_os = "linux")]
    Huge {
        ptr: *mut u8,
        len: usize,
    },
}

const HUGE_2M: usize = 2 * 1024 * 1024;

impl Buffer {
    /// Allocate `len` bytes, preferring 2 MiB hugepages for large buffers.
    pub fn alloc(len: usize) -> Buffer {
        #[cfg(target_os = "linux")]
        {
            if len >= HUGE_2M && hugepages_available() > 0 {
                let rounded = len.div_ceil(HUGE_2M) * HUGE_2M;
                unsafe {
                    let p = libc::mmap(
                        std::ptr::null_mut(),
                        rounded,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB,
                        -1,
                        0,
                    );
                    if p != libc::MAP_FAILED {
                        // First-touch to fault pages onto the local NUMA node.
                        std::ptr::write_bytes(p as *mut u8, 0, rounded);
                        return Buffer::Huge {
                            ptr: p as *mut u8,
                            len: rounded,
                        };
                    }
                }
            }
        }
        Buffer::Heap(vec![0u8; len])
    }

    pub fn is_huge(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            matches!(self, Buffer::Huge { .. })
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

impl Deref for Buffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Buffer::Heap(v) => v,
            #[cfg(target_os = "linux")]
            Buffer::Huge { ptr, len } => unsafe { std::slice::from_raw_parts(*ptr, *len) },
        }
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        match self {
            Buffer::Heap(v) => v,
            #[cfg(target_os = "linux")]
            Buffer::Huge { ptr, len } => unsafe { std::slice::from_raw_parts_mut(*ptr, *len) },
        }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if let Buffer::Huge { ptr, len } = self {
            unsafe {
                libc::munmap(*ptr as *mut libc::c_void, *len);
            }
        }
    }
}

/// Detected acceleration capabilities, shown in the UI banner.
#[derive(Clone, Debug, Default)]
pub struct Caps {
    pub cores: usize,
    pub reuseport: bool,
    pub udp_gso: bool,
    pub udp_gro: bool,
    pub sendmmsg: bool,
    pub io_uring: bool,
    pub af_xdp: bool,
    pub hugepages: usize,
    pub os: &'static str,
}

pub fn detect() -> Caps {
    let mut c = Caps {
        cores: available_cores(),
        hugepages: hugepages_available(),
        os: std::env::consts::OS,
        ..Default::default()
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        c.reuseport = true;
        c.sendmmsg = true;
        let (gso, gro) = probe_udp_offloads();
        c.udp_gso = gso;
        c.udp_gro = gro;
        c.af_xdp = probe_af_xdp();
    }
    #[cfg(target_os = "linux")]
    {
        c.io_uring = crate::uring::available();
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    {
        c.reuseport = true;
        c.sendmmsg = cfg!(any(target_os = "freebsd", target_os = "netbsd"));
    }
    c
}

/// Probe whether the kernel supports AF_XDP sockets (the kernel-bypass tier).
/// Success or EPERM => supported (EPERM just means it needs privilege);
/// EAFNOSUPPORT => not built into the kernel.
#[cfg(target_os = "linux")]
fn probe_af_xdp() -> bool {
    const AF_XDP: libc::c_int = 44;
    unsafe {
        let fd = libc::socket(AF_XDP, libc::SOCK_RAW, 0);
        if fd >= 0 {
            libc::close(fd);
            return true;
        }
        *libc::__errno_location() == libc::EPERM
    }
}

/// Probe whether the kernel accepts UDP_SEGMENT / UDP_GRO on a throwaway socket.
#[cfg(target_os = "linux")]
fn probe_udp_offloads() -> (bool, bool) {
    use linux_consts::*;
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return (false, false);
        }
        let one: libc::c_int = 1408;
        let gso = libc::setsockopt(
            fd,
            SOL_UDP,
            UDP_SEGMENT,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) == 0;
        let on: libc::c_int = 1;
        let gro = libc::setsockopt(
            fd,
            SOL_UDP,
            UDP_GRO,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) == 0;
        libc::close(fd);
        (gso, gro)
    }
}
