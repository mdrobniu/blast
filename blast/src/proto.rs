//! Wire protocol: MikroTik btest compat layer + blast turbo layer.
//!
//! The compat layer is a clean-room reimplementation of the MikroTik
//! bandwidth-test control protocol as documented in `PROTOCOL.md`
//! (Ghidra decompilation of `btest.exe` + public reverse-engineering).

use anyhow::{bail, Result};

// ---------- Enums shared by both layers ----------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}
impl Protocol {
    pub fn wire(self) -> u8 {
        match self {
            Protocol::Tcp => 0x01,
            Protocol::Udp => 0x00,
        }
    }
    pub fn from_wire(b: u8) -> Protocol {
        if b == 0 {
            Protocol::Udp
        } else {
            Protocol::Tcp
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Client transmits to server (upload).
    Tx,
    /// Client receives from server (download).
    Rx,
    /// Both directions simultaneously.
    Both,
}
impl Direction {
    pub fn wire(self) -> u8 {
        match self {
            Direction::Tx => 0x01,
            Direction::Rx => 0x02,
            Direction::Both => 0x03,
        }
    }
    pub fn from_wire(b: u8) -> Result<Direction> {
        Ok(match b {
            0x01 => Direction::Tx,
            0x02 => Direction::Rx,
            0x03 => Direction::Both,
            _ => bail!("invalid direction byte 0x{b:02x}"),
        })
    }
    pub fn local_sends(self) -> bool {
        matches!(self, Direction::Tx | Direction::Both)
    }
    pub fn local_recvs(self) -> bool {
        matches!(self, Direction::Rx | Direction::Both)
    }
    /// The mirror direction (what the server should do given a client request).
    pub fn mirror(self) -> Direction {
        match self {
            Direction::Tx => Direction::Rx,
            Direction::Rx => Direction::Tx,
            Direction::Both => Direction::Both,
        }
    }
}

// ---------- Compat control words ----------

pub const PORT_DEFAULT: u16 = 2000;

pub const HELLO_OK: [u8; 4] = [0x01, 0x00, 0x00, 0x00]; // server hello / auth ok
pub const AUTH_MD5: [u8; 4] = [0x02, 0x00, 0x00, 0x00]; // + 16 challenge bytes
pub const AUTH_SRP: [u8; 4] = [0x03, 0x00, 0x00, 0x00]; // EC-SRP5 (>=6.43)
pub const AUTH_FAIL: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

pub const STATS_OPCODE: u8 = 0x07;

/// The 16-byte command the client sends after the server hello.
#[derive(Copy, Clone, Debug)]
pub struct Command {
    pub proto: Protocol,
    pub direction: Direction,
    /// true => random payload (wire byte 0), false => zero payload (wire byte 1)
    pub random: bool,
    pub conn_count: u8,
    pub remote_size: u16,
    pub local_size: u16,
    pub remote_speed: u32, // bytes/sec, 0 = unlimited
    pub local_speed: u32,  // bytes/sec, 0 = unlimited
}

impl Command {
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0] = self.proto.wire();
        b[1] = self.direction.wire();
        b[2] = if self.random { 0x00 } else { 0x01 };
        b[3] = self.conn_count;
        b[4..6].copy_from_slice(&self.remote_size.to_le_bytes());
        b[6..8].copy_from_slice(&self.local_size.to_le_bytes());
        b[8..12].copy_from_slice(&self.remote_speed.to_le_bytes());
        b[12..16].copy_from_slice(&self.local_speed.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<Command> {
        if b.len() < 16 {
            bail!("short command: {} bytes", b.len());
        }
        Ok(Command {
            proto: Protocol::from_wire(b[0]),
            direction: Direction::from_wire(b[1])?,
            random: b[2] == 0x00,
            conn_count: b[3],
            remote_size: u16::from_le_bytes([b[4], b[5]]),
            local_size: u16::from_le_bytes([b[6], b[7]]),
            remote_speed: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            local_speed: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
        })
    }
}

/// Encode the periodic 12-byte stats heartbeat: `07 00 00 00 <secs u32> <bytes u32>`.
pub fn encode_stats(seconds: u32, bytes: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0] = STATS_OPCODE;
    b[4..8].copy_from_slice(&seconds.to_le_bytes());
    b[8..12].copy_from_slice(&bytes.to_le_bytes());
    b
}

pub fn decode_stats(b: &[u8]) -> Option<(u32, u32)> {
    if b.len() >= 12 && b[0] == STATS_OPCODE {
        let secs = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let bytes = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        Some((secs, bytes))
    } else {
        None
    }
}

/// MikroTik legacy MD5 auth: `md5(password + md5(password + challenge))`.
pub fn md5_auth_digest(password: &str, challenge: &[u8]) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut inner = Md5::new();
    inner.update(password.as_bytes());
    inner.update(challenge);
    let inner = inner.finalize();

    let mut outer = Md5::new();
    outer.update(password.as_bytes());
    outer.update(inner);
    outer.finalize().into()
}

/// Build the 48-byte MD5 auth reply: 32-byte username field + 16-byte digest.
/// (Framing per public RE; verify against a live RouterOS device before relying on it.)
pub fn md5_auth_reply(user: &str, password: &str, challenge: &[u8]) -> [u8; 48] {
    let mut out = [0u8; 48];
    let ub = user.as_bytes();
    let n = ub.len().min(32);
    out[..n].copy_from_slice(&ub[..n]);
    out[32..48].copy_from_slice(&md5_auth_digest(password, challenge));
    out
}

// ---------- blast turbo layer ----------
//
// A native control header used between two blast instances. It removes the
// MikroTik size caps (u16 -> u32), advertises a GSO segment hint, and lets the
// data plane negotiate jumbo buffers. Both ends must run with `--turbo`.

pub const TURBO_MAGIC: [u8; 6] = *b"BLAST\x01";

#[derive(Copy, Clone, Debug)]
pub struct TurboParams {
    pub proto: Protocol,
    pub direction: Direction,
    pub random: bool,
    pub workers: u16,
    /// Application send size (bytes) per submission (may be a GSO super-buffer).
    pub send_size: u32,
    /// GSO segment size hint (0 = no GSO).
    pub gso_segment: u16,
    pub local_speed: u64, // bytes/sec, 0 = unlimited
    pub remote_speed: u64,
    pub duration_secs: u32,
}

impl TurboParams {
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut b = [0u8; 40];
        b[0..6].copy_from_slice(&TURBO_MAGIC);
        b[6] = self.proto.wire();
        b[7] = self.direction.wire();
        b[8] = self.random as u8;
        b[9] = 0; // reserved
        b[10..12].copy_from_slice(&self.workers.to_le_bytes());
        b[12..16].copy_from_slice(&self.send_size.to_le_bytes());
        b[16..18].copy_from_slice(&self.gso_segment.to_le_bytes());
        // 18..20 reserved
        b[20..28].copy_from_slice(&self.local_speed.to_le_bytes());
        b[28..36].copy_from_slice(&self.remote_speed.to_le_bytes());
        b[36..40].copy_from_slice(&self.duration_secs.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<TurboParams> {
        if b.len() < 40 {
            bail!("short turbo header: {} bytes", b.len());
        }
        if b[0..6] != TURBO_MAGIC {
            bail!("bad turbo magic (is the other end running --turbo?)");
        }
        Ok(TurboParams {
            proto: Protocol::from_wire(b[6]),
            direction: Direction::from_wire(b[7])?,
            random: b[8] != 0,
            workers: u16::from_le_bytes([b[10], b[11]]),
            send_size: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
            gso_segment: u16::from_le_bytes([b[16], b[17]]),
            local_speed: u64::from_le_bytes(b[20..28].try_into().unwrap()),
            remote_speed: u64::from_le_bytes(b[28..36].try_into().unwrap()),
            duration_secs: u32::from_le_bytes(b[36..40].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_roundtrip() {
        let c = Command {
            proto: Protocol::Udp,
            direction: Direction::Both,
            random: true,
            conn_count: 4,
            remote_size: 1408,
            local_size: 1408,
            remote_speed: 0,
            local_speed: 1_000_000,
        };
        let b = c.to_bytes();
        assert_eq!(b[0], 0x00); // udp
        assert_eq!(b[1], 0x03); // both
        assert_eq!(b[2], 0x00); // random
        assert_eq!(b[3], 4);
        let d = Command::from_bytes(&b).unwrap();
        assert_eq!(d.remote_size, 1408);
        assert_eq!(d.local_speed, 1_000_000);
    }

    #[test]
    fn stats_roundtrip() {
        let s = encode_stats(1, 0x00036e36);
        assert_eq!(s[0], 0x07);
        assert_eq!(decode_stats(&s), Some((1, 0x00036e36)));
    }

    #[test]
    fn turbo_roundtrip() {
        let p = TurboParams {
            proto: Protocol::Udp,
            direction: Direction::Tx,
            random: false,
            workers: 8,
            send_size: 65536,
            gso_segment: 1448,
            local_speed: 0,
            remote_speed: 0,
            duration_secs: 10,
        };
        let q = TurboParams::from_bytes(&p.to_bytes()).unwrap();
        assert_eq!(q.workers, 8);
        assert_eq!(q.send_size, 65536);
        assert_eq!(q.gso_segment, 1448);
    }
}
