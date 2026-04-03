/// TSIG (RFC 2845) message signing for secure DNS updates.
/// Uses HMAC-SHA256 for authentication.
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::dns::encode_name;

type HmacSha256 = Hmac<Sha256>;

/// TSIG key configuration
pub struct TsigKey {
    pub name: String,
    pub algorithm: String,
    pub secret: String,
}

/// Sign a DNS message with TSIG.
/// Appends the TSIG RR to the additional section and increments ARCOUNT.
pub fn sign_message(message: &mut Vec<u8>, key: &TsigKey, msg_id: u16) {
    // Decode the base64 secret
    let secret = match base64::engine::general_purpose::STANDARD.decode(key.secret.trim()) {
        Ok(s) => s,
        Err(_) => {
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
    let mut hmac = HmacSha256::new_from_slice(&secret)
        .expect("HMAC can take key of any size");
    hmac.update(&mac_input);
    let mac = hmac.finalize().into_bytes();

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
