/// TSIG (RFC 2845) message signing for secure DNS updates.
/// Uses HMAC-SHA256 for authentication.
use std::time::{SystemTime, UNIX_EPOCH};

use super::dns::encode_name;

/// TSIG key configuration
pub struct TsigKey {
    pub name: String,
    pub algorithm: String,
    pub secret: String,
}

/// TSIG algorithm name for wire format
const HMAC_SHA256_NAME: &str = "hmac-sha256";

/// Sign a DNS message with TSIG.
/// Appends the TSIG RR to the additional section and increments ARCOUNT.
pub fn sign_message(message: &mut Vec<u8>, key: &TsigKey, msg_id: u16) {
    // Decode the base64 secret
    let secret = match base64_decode(&key.secret) {
        Some(s) => s,
        None => {
            tracing::warn!("invalid base64 TSIG secret, skipping signing");
            return;
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Build the TSIG variables for MAC computation (RFC 2845 §4.3)
    // MAC input = DNS message (without TSIG) + TSIG variables
    let mut mac_input = Vec::with_capacity(message.len() + 256);

    // The DNS message as-is
    mac_input.extend_from_slice(message);

    // TSIG variables:
    // Key name (wire format)
    let key_name_wire = encode_name(&key.name);
    mac_input.extend_from_slice(&key_name_wire);

    // Class = ANY (255)
    mac_input.extend_from_slice(&255u16.to_be_bytes());

    // TTL = 0
    mac_input.extend_from_slice(&0u32.to_be_bytes());

    // Algorithm name (wire format)
    let alg_name = match key.algorithm.as_str() {
        "hmac-sha256" => "hmac-sha256",
        "hmac-sha512" => "hmac-sha512",
        other => other,
    };
    let alg_wire = encode_name(alg_name);
    mac_input.extend_from_slice(&alg_wire);

    // Time signed (48 bits = 6 bytes)
    let time_hi = ((now >> 32) & 0xFFFF) as u16;
    let time_lo = (now & 0xFFFFFFFF) as u32;
    mac_input.extend_from_slice(&time_hi.to_be_bytes());
    mac_input.extend_from_slice(&time_lo.to_be_bytes());

    // Fudge (300 seconds)
    mac_input.extend_from_slice(&300u16.to_be_bytes());

    // Error = 0
    mac_input.extend_from_slice(&0u16.to_be_bytes());

    // Other len = 0
    mac_input.extend_from_slice(&0u16.to_be_bytes());

    // Compute HMAC-SHA256
    let mac = hmac_sha256(&secret, &mac_input);

    // Build TSIG RR
    let mut tsig_rr = Vec::with_capacity(128);

    // Name (key name)
    tsig_rr.extend_from_slice(&key_name_wire);

    // Type = TSIG (250)
    tsig_rr.extend_from_slice(&250u16.to_be_bytes());

    // Class = ANY (255)
    tsig_rr.extend_from_slice(&255u16.to_be_bytes());

    // TTL = 0
    tsig_rr.extend_from_slice(&0u32.to_be_bytes());

    // RDATA
    let mut rdata = Vec::with_capacity(64 + mac.len());

    // Algorithm name
    rdata.extend_from_slice(&alg_wire);

    // Time signed
    rdata.extend_from_slice(&time_hi.to_be_bytes());
    rdata.extend_from_slice(&time_lo.to_be_bytes());

    // Fudge
    rdata.extend_from_slice(&300u16.to_be_bytes());

    // MAC size
    rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());

    // MAC
    rdata.extend_from_slice(&mac);

    // Original ID
    rdata.extend_from_slice(&msg_id.to_be_bytes());

    // Error = 0
    rdata.extend_from_slice(&0u16.to_be_bytes());

    // Other len = 0
    rdata.extend_from_slice(&0u16.to_be_bytes());

    // RDLENGTH
    tsig_rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    tsig_rr.extend_from_slice(&rdata);

    // Append TSIG RR to message
    message.extend_from_slice(&tsig_rr);

    // Increment ARCOUNT (bytes 10-11 in header)
    let arcount = u16::from_be_bytes([message[10], message[11]]);
    let new_arcount = arcount + 1;
    message[10..12].copy_from_slice(&new_arcount.to_be_bytes());
}

/// Simple HMAC-SHA256 implementation.
/// For a production system, consider using a dedicated crypto crate,
/// but this avoids adding an external dependency for a single function.
fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 64;
    const HASH_SIZE: usize = 32;

    // Prepare key
    let mut k = vec![0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = sha256(key);
        k[..HASH_SIZE].copy_from_slice(&hashed);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    // Inner padding
    let mut ipad = vec![0x36u8; BLOCK_SIZE];
    for (i, byte) in k.iter().enumerate() {
        ipad[i] ^= byte;
    }

    // Outer padding
    let mut opad = vec![0x5cu8; BLOCK_SIZE];
    for (i, byte) in k.iter().enumerate() {
        opad[i] ^= byte;
    }

    // inner = SHA256(ipad || message)
    let mut inner_input = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(message);
    let inner = sha256(&inner_input);

    // outer = SHA256(opad || inner)
    let mut outer_input = Vec::with_capacity(BLOCK_SIZE + HASH_SIZE);
    outer_input.extend_from_slice(&opad);
    outer_input.extend_from_slice(&inner);
    sha256(&outer_input).to_vec()
}

/// SHA-256 implementation (FIPS 180-4)
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    // Pre-processing: pad message
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit (64-byte) block
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    result
}

/// Decode base64 (standard alphabet, with optional padding)
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let input = input.trim();
    let mut buf = Vec::with_capacity(input.len() * 3 / 4);

    let mut accum = 0u32;
    let mut bits = 0u32;

    for c in input.bytes() {
        let val = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => continue,
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        };

        accum = (accum << 6) | val as u32;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            buf.push((accum >> bits) as u8);
            accum &= (1 << bits) - 1;
        }
    }

    Some(buf)
}
