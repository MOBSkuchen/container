//! TLS whose trust is anchored in the shared auth key.
//!
//! The server's TLS identity is an Ed25519 key derived from the pre-shared
//! auth key (HKDF-SHA256). The client derives the same public key and pins it:
//! it accepts the connection only if the server proves possession of the
//! matching private key. So holding the key — and nothing else — authenticates
//! the server, with no certificate files, no CA, and no first-use trust leap.
//! A man-in-the-middle without the key cannot complete the handshake.
//!
//! This composes with, and does not replace, `auth`: TLS encrypts the channel
//! and authenticates the *server*; the per-request HMAC authenticates the
//! *client* and guards replay.

use std::sync::Arc;

use bierpc::rpc::ClientTlsConfig;
use bierpc::rustls::{self, pki_types};
use ed25519_dalek::SigningKey;

/// Domain-separation label for the identity derivation. Pinned: both ends must
/// derive byte-identical keys, so it can only change in lockstep (like the KDF
/// constants in `auth`).
const IDENTITY_INFO: &[u8] = b"container-tls-identity-v1";

/// PKCS#8 v1 wrapper for an Ed25519 seed, minus the trailing 32 seed bytes
/// (RFC 8410 §7). Lets rcgen adopt our derived key without a PKCS#8 encoder.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// The server's TLS identity, derived from the shared auth key.
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    pub fn derive(auth_key: &[u8]) -> Self {
        // No salt: the auth key is already high-entropy (random) or stretched
        // (Argon2id). The pinned info string is the only domain separation.
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, auth_key);
        let mut seed = [0u8; 32];
        hk.expand(IDENTITY_INFO, &mut seed).expect("32 is a valid HKDF-SHA256 length");
        Identity { signing: SigningKey::from_bytes(&seed) }
    }

    /// The public key the client pins.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    fn pkcs8_der(&self) -> Vec<u8> {
        let mut der = Vec::with_capacity(ED25519_PKCS8_PREFIX.len() + 32);
        der.extend_from_slice(&ED25519_PKCS8_PREFIX);
        der.extend_from_slice(&self.signing.to_bytes());
        der
    }

    /// A rustls server config presenting a self-signed cert over this identity.
    /// TLS 1.3 only — there is no reason to negotiate down.
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, String> {
        let pkcs8 = pki_types::PrivatePkcs8KeyDer::from(self.pkcs8_der());
        let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_ED25519)
            .map_err(|e| format!("loading the derived key: {e}"))?;
        // The name is irrelevant: the client pins the key, not the hostname.
        let cert = rcgen::CertificateParams::new(vec!["container".to_string()])
            .and_then(|params| params.self_signed(&key_pair))
            .map_err(|e| format!("self-signing the cert: {e}"))?;

        let cert_der = cert.der().clone();
        let key_der = pki_types::PrivateKeyDer::Pkcs8(pki_types::PrivatePkcs8KeyDer::from(self.pkcs8_der()));

        rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| format!("selecting TLS 1.3: {e}"))?
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map(Arc::new)
            .map_err(|e| format!("installing the cert: {e}"))
    }
}

/// A client TLS config that pins `expected_public_key` as the only acceptable
/// server identity. Pair it with the same auth key's `Identity::public_key`.
pub fn client_config(expected_public_key: [u8; 32]) -> ClientTlsConfig {
    let provider = Arc::new(provider());
    let verifier = Arc::new(PinnedServerVerifier { expected_public_key, provider: provider.clone() });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported by the provider")
        .dangerous() // "dangerous" only in that it bypasses the webpki CA path
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    // A placeholder SNI: the verifier ignores the name entirely.
    let server_name = pki_types::ServerName::try_from("container").expect("valid DNS name");
    ClientTlsConfig::new(config, server_name)
}

fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

/// Extract the Ed25519 public key from an end-entity certificate's *structural*
/// SubjectPublicKeyInfo — not a substring scan, so a cert that merely embeds
/// the pinned bytes elsewhere while carrying a different real key is rejected.
fn cert_ed25519_key(cert: &pki_types::CertificateDer) -> Option<[u8; 32]> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;
    let spki = parsed.public_key();
    // OID 1.3.101.112 = Ed25519.
    if spki.algorithm.algorithm.to_id_string() != "1.3.101.112" {
        return None;
    }
    spki.subject_public_key.data.as_ref().try_into().ok()
}

#[derive(Debug)]
struct PinnedServerVerifier {
    expected_public_key: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &pki_types::CertificateDer,
        _intermediates: &[pki_types::CertificateDer],
        _server_name: &pki_types::ServerName,
        _ocsp: &[u8],
        _now: pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match cert_ed25519_key(end_entity) {
            Some(key) if key == self.expected_public_key => {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            // A wrong (or non-Ed25519) key means the peer does not hold this
            // server's auth key — surfaced to the user as a key mismatch.
            _ => Err(rustls::Error::General("server key does not match the pinned identity".into())),
        }
    }

    // Possession of the pinned key is proven by the handshake signature, which
    // the provider verifies against the (now-pinned) cert key.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    // A real localhost TLS 1.3 handshake: it exercises the derived cert, the
    // pinning verifier, and the provider together — the parts that fail as a
    // group, not individually.
    async fn handshake(server_key: &[u8], client_pin: [u8; 32]) -> Result<(), String> {
        let identity = Identity::derive(server_key);
        let server_config = identity.server_config().map_err(|e| format!("server config: {e}"))?;
        let client_config = client_config(client_pin);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.map_err(|e| format!("accept: {e}"))?;
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.map_err(|e| format!("read: {e}"))?;
            tls.write_all(&buf).await.map_err(|e| format!("write: {e}"))?;
            tls.flush().await.ok();
            Ok::<_, String>(())
        });

        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            (*client_config.config).clone(),
        ));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = connector.connect(client_config.server_name.clone(), tcp).await
            .map_err(|e| format!("connect: {e}"))?;
        tls.write_all(b"ping").await.map_err(|e| format!("client write: {e}"))?;
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.map_err(|e| format!("client read: {e}"))?;
        assert_eq!(&buf, b"ping");
        server.await.unwrap()
    }

    #[tokio::test]
    async fn matching_key_handshakes() {
        let key = crate::auth::hash_or_random(None);
        let pin = Identity::derive(&key).public_key();
        handshake(&key, pin).await.expect("matching keys must complete the handshake");
    }

    #[tokio::test]
    async fn mismatched_key_is_refused() {
        let server_key = crate::auth::hash_or_random(None);
        let other_pin = Identity::derive(&crate::auth::hash_or_random(None)).public_key();
        assert!(
            handshake(&server_key, other_pin).await.is_err(),
            "a client pinning a different key must not complete the handshake",
        );
    }

    #[test]
    fn identity_is_deterministic() {
        let key = crate::auth::hash_or_random(Some("pin-me"));
        assert_eq!(Identity::derive(&key).public_key(), Identity::derive(&key).public_key());
    }
}
