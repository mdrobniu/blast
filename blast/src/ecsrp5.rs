//! MikroTik EC-SRP5 authentication for btest (RouterOS >= 6.43), the `03` path.
//!
//! Ported from `manawenuz/btest-rs` (src/ecsrp5.rs) + the MarginResearch "mtwei"
//! reference, adapted to blocking std I/O. Curve25519 in short-Weierstrass form
//! over num-bigint, SHA-256 only. Verified against live RouterOS 7.22.1.
//!
//! Wire (each message `[len:1][payload]`), after the server's `03 00 00 00`:
//!   MSG1 C->S: username \0  client_pub[32]  client_parity[1]
//!   MSG2 S->C: server_pub[32]  server_parity[1]  salt[16]
//!   MSG3 C->S: client_cc[32]
//!   MSG4 S->C: server_cc[32]

use anyhow::{bail, Result};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::LazyLock;

static P: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::parse_bytes(
        b"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
        16,
    )
    .unwrap()
});
static CURVE_ORDER: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::parse_bytes(
        b"1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
        16,
    )
    .unwrap()
});
static WEIERSTRASS_A: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::parse_bytes(
        b"2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144",
        16,
    )
    .unwrap()
});
const MONT_A: u64 = 486662;

fn modinv(a: &BigUint, m: &BigUint) -> BigUint {
    a.modpow(&(m - BigUint::from(2u32)), m) // Fermat
}

fn legendre(a: &BigUint, p: &BigUint) -> i32 {
    let l = a.modpow(&((p - BigUint::one()) / BigUint::from(2u32)), p);
    if l == p - BigUint::one() {
        -1
    } else if l.is_zero() {
        0
    } else {
        1
    }
}

/// sqrt mod p for Curve25519 (p == 2^255-19 == 5 mod 8), Atkin's algorithm.
fn prime_mod_sqrt(a: &BigUint, p: &BigUint) -> Option<(BigUint, BigUint)> {
    let a = a % p;
    if a.is_zero() {
        return Some((BigUint::zero(), BigUint::zero()));
    }
    if legendre(&a, p) != 1 {
        return None;
    }
    let exp = (p - BigUint::from(5u32)) / BigUint::from(8u32);
    let two_a = (BigUint::from(2u32) * &a) % p;
    let v = two_a.modpow(&exp, p);
    let i_val = (((BigUint::from(2u32) * &a % p) * &v % p) * &v) % p;
    let i_minus_1 = (&i_val + p - BigUint::one()) % p;
    let x = (((&a * &v) % p) * &i_minus_1) % p;
    if (&x * &x) % p == a {
        let other = p - &x;
        Some((x, other))
    } else {
        None
    }
}

#[derive(Clone)]
struct Point {
    x: BigUint,
    y: BigUint,
    infinity: bool,
}

impl Point {
    fn infinity() -> Self {
        Point { x: BigUint::zero(), y: BigUint::zero(), infinity: true }
    }
    fn new(x: BigUint, y: BigUint) -> Self {
        Point { x, y, infinity: false }
    }
    fn add(&self, other: &Point) -> Point {
        let p = &*P;
        if self.infinity {
            return other.clone();
        }
        if other.infinity {
            return self.clone();
        }
        if self.x == other.x && self.y != other.y {
            return Point::infinity();
        }
        let lam = if self.x == other.x && self.y == other.y {
            let three_x_sq = (BigUint::from(3u32) * &self.x * &self.x + &*WEIERSTRASS_A) % p;
            let two_y = (BigUint::from(2u32) * &self.y) % p;
            (three_x_sq * modinv(&two_y, p)) % p
        } else {
            let dy = (&other.y + p - &self.y % p) % p;
            let dx = (&other.x + p - &self.x % p) % p;
            (dy * modinv(&dx, p)) % p
        };
        let lam_sq = (&lam * &lam) % p;
        let sum_x = (&self.x + &other.x) % p;
        let x3 = (&lam_sq + p - &sum_x % p) % p;
        let dxx = (&self.x + p - &x3 % p) % p;
        let prod = (&lam * dxx) % p;
        let y3 = (&prod + p - &self.y % p) % p;
        Point::new(x3, y3)
    }
    fn scalar_mul(&self, scalar: &BigUint) -> Point {
        let mut result = Point::infinity();
        let mut base = self.clone();
        for i in 0..scalar.bits() {
            if scalar.bit(i) {
                result = result.add(&base);
            }
            base = base.add(&base);
        }
        result
    }
}

struct WCurve {
    g: Point,
    conversion_from_m: BigUint,
    conversion_to_m: BigUint,
}

impl WCurve {
    fn new() -> Self {
        let p = &*P;
        let from_m = (&BigUint::from(MONT_A) * modinv(&BigUint::from(3u32), p)) % p;
        let to_m = (p - &from_m) % p;
        let mut c = WCurve { g: Point::infinity(), conversion_from_m: from_m, conversion_to_m: to_m };
        c.g = c.lift_x(&BigUint::from(9u32), false);
        c
    }
    fn to_montgomery(&self, pt: &Point) -> ([u8; 32], u8) {
        let p = &*P;
        let x = (&pt.x + &self.conversion_to_m) % p;
        (bigint_to_32(&x), if pt.y.bit(0) { 1 } else { 0 })
    }
    fn lift_x(&self, x_mont: &BigUint, parity: bool) -> Point {
        let p = &*P;
        let x = x_mont % p;
        let y2 = (&x * &x * &x + BigUint::from(MONT_A) * &x * &x + &x) % p;
        let x_w = (&x + &self.conversion_from_m) % p;
        if let Some((y1, y2r)) = prime_mod_sqrt(&y2, p) {
            let pt1 = Point::new(x_w.clone(), y1);
            let pt2 = Point::new(x_w, y2r);
            if parity {
                if pt1.y.bit(0) { pt1 } else { pt2 }
            } else if !pt1.y.bit(0) {
                pt1
            } else {
                pt2
            }
        } else {
            Point::infinity()
        }
    }
    fn gen_public_key(&self, priv_key: &[u8; 32]) -> ([u8; 32], u8) {
        self.to_montgomery(&self.g.scalar_mul(&BigUint::from_bytes_be(priv_key)))
    }
    /// hash-to-curve (redp1): hash once, then loop hashing again until on-curve.
    fn redp1(&self, x_bytes: &[u8; 32], parity: bool) -> Point {
        let mut x = sha256(x_bytes);
        loop {
            let x2 = sha256(&x);
            let pt = self.lift_x(&BigUint::from_bytes_be(&x2), parity);
            if !pt.infinity {
                return pt;
            }
            let val = BigUint::from_bytes_be(&x) + BigUint::one();
            x = bigint_to_32(&val);
        }
    }
    fn validator_priv(&self, username: &str, password: &str, salt: &[u8; 16]) -> [u8; 32] {
        let inner = sha256(format!("{username}:{password}").as_bytes());
        let mut input = Vec::with_capacity(48);
        input.extend_from_slice(salt);
        input.extend_from_slice(&inner);
        sha256(&input)
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn bigint_to_32(v: &BigUint) -> [u8; 32] {
    let b = v.to_bytes_be();
    let mut out = [0u8; 32];
    let n = b.len().min(32);
    out[32 - n..].copy_from_slice(&b[b.len() - n..]);
    out
}

fn rand_32() -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b)
}

fn write_msg(s: &mut TcpStream, payload: &[u8]) -> Result<()> {
    if payload.len() > 255 {
        bail!("ec-srp5 message too long");
    }
    let mut m = Vec::with_capacity(1 + payload.len());
    m.push(payload.len() as u8);
    m.extend_from_slice(payload);
    s.write_all(&m)?;
    s.flush()?;
    Ok(())
}

fn read_msg(s: &mut TcpStream) -> Result<Vec<u8>> {
    let mut hdr = [0u8; 1];
    s.read_exact(&mut hdr)?;
    let mut body = vec![0u8; hdr[0] as usize];
    s.read_exact(&mut body)?;
    Ok(body)
}

/// Perform EC-SRP5 auth as a client (call after reading `03 00 00 00`).
pub fn client_authenticate(stream: &mut TcpStream, username: &str, password: &str) -> Result<()> {
    let w = WCurve::new();
    let s_a = rand_32()?;
    let (x_w_a, par_a) = w.gen_public_key(&s_a);

    // MSG1: username \0 pubkey[32] parity[1]
    let mut p1 = Vec::with_capacity(username.len() + 34);
    p1.extend_from_slice(username.as_bytes());
    p1.push(0);
    p1.extend_from_slice(&x_w_a);
    p1.push(par_a);
    write_msg(stream, &p1)?;

    // MSG2: server_pub[32] parity[1] salt[16]
    let resp = read_msg(stream)?;
    if resp.len() < 49 {
        bail!("ec-srp5: short server challenge ({} bytes) - user may be unregistered", resp.len());
    }
    let mut x_w_b = [0u8; 32];
    x_w_b.copy_from_slice(&resp[0..32]);
    let par_b = resp[32] != 0;
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&resp[33..49]);

    // Shared secret
    let i = w.validator_priv(username, password, &salt);
    let (x_gamma, _) = w.gen_public_key(&i);
    let v = w.redp1(&x_gamma, true);
    let w_b = w.lift_x(&BigUint::from_bytes_be(&x_w_b), par_b).add(&v);

    let mut j_in = Vec::with_capacity(64);
    j_in.extend_from_slice(&x_w_a);
    j_in.extend_from_slice(&x_w_b);
    let j = sha256(&j_in);

    let scalar = ((BigUint::from_bytes_be(&i) * BigUint::from_bytes_be(&j))
        + BigUint::from_bytes_be(&s_a))
        % &*CURVE_ORDER;
    let (z, _) = w.to_montgomery(&w_b.scalar_mul(&scalar));

    // MSG3: client_cc = SHA256(j || z)
    let mut cc_in = Vec::with_capacity(64);
    cc_in.extend_from_slice(&j);
    cc_in.extend_from_slice(&z);
    let client_cc = sha256(&cc_in);
    write_msg(stream, &client_cc)?;

    // MSG4: verify server_cc = SHA256(j || client_cc || z)
    let server_cc = read_msg(stream)?;
    let mut sc_in = Vec::with_capacity(96);
    sc_in.extend_from_slice(&j);
    sc_in.extend_from_slice(&client_cc);
    sc_in.extend_from_slice(&z);
    if server_cc == sha256(&sc_in) {
        Ok(())
    } else if let Ok(msg) = std::str::from_utf8(&server_cc) {
        bail!("ec-srp5 auth rejected: {msg}");
    } else {
        bail!("ec-srp5 auth failed (server confirmation mismatch)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generator_montgomery_x_is_9() {
        let w = WCurve::new();
        let (x, _) = w.to_montgomery(&w.g);
        assert_eq!(BigUint::from_bytes_be(&x), BigUint::from(9u32));
    }
    #[test]
    fn pubkey_roundtrips_on_curve() {
        let w = WCurve::new();
        let (x, par) = w.gen_public_key(&[7u8; 32]);
        // lifting the advertised x with its parity must land back on the curve
        let pt = w.lift_x(&BigUint::from_bytes_be(&x), par != 0);
        assert!(!pt.infinity);
    }
}
