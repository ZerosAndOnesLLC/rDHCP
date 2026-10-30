use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::protocol::HaMessage;

/// TLS configuration for HA peer connections
pub struct TlsConfig {
    /// TLS connector for outbound peer connections.
    pub connector: TlsConnector,
    /// TLS acceptor for inbound peer connections.
    pub acceptor: TlsAcceptor,
}

impl TlsConfig {
    /// Load TLS config from certificate and key files.
    /// Both peers should use mutual TLS with the same CA.
    pub fn load(
        cert_path: &str,
        key_path: &str,
        ca_cert_path: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Load server cert chain
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()?;

        // Load private key
        let key = PrivateKeyDer::from_pem_file(key_path)?;

        // Load CA cert for peer verification
        let ca_certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_file_iter(ca_cert_path)?.collect::<Result<Vec<_>, _>>()?;

        let mut root_store = rustls::RootCertStore::empty();
        for cert in &ca_certs {
            root_store.add(cert.clone())?;
        }

        // Server config — require client certs (mutual TLS)
        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store.clone()))
                    .build()?,
            )
            .with_single_cert(certs.clone(), key.clone_key())?;

        // Client config — present our cert to the peer
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(certs, key)?;

        Ok(Self {
            connector: TlsConnector::from(Arc::new(client_config)),
            acceptor: TlsAcceptor::from(Arc::new(server_config)),
        })
    }
}

/// Read a single length-prefixed framed message from a stream
pub async fn read_message<S: AsyncReadExt + Unpin>(
    stream: &mut S,
) -> Result<Option<HaMessage>, Box<dyn std::error::Error + Send + Sync>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    let msg_len = u32::from_be_bytes(len_buf) as usize;
    if msg_len > 10 * 1024 * 1024 {
        return Err("message too large (>10MB)".into());
    }

    let mut msg_buf = vec![0u8; msg_len];
    stream.read_exact(&mut msg_buf).await?;

    let msg = HaMessage::decode(&msg_buf)?;
    Ok(Some(msg))
}

/// Write a single length-prefixed framed message to a stream
pub async fn write_message<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    msg: &HaMessage,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let data = msg.encode()?;
    stream.write_all(&data).await?;
    stream.flush().await?;
    Ok(())
}
