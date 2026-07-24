//! Mutual TLS whose trust is anchored in the shared auth key.
//!
//! Both ends derive the *same* Ed25519 identity from the pre-shared auth key
//! (HKDF-SHA256) and each pins the other's public key: the handshake completes
//! only if both parties prove possession of the matching private key. So
//! holding the key — and nothing else — authenticates the connection in both
//! directions, with no certificate files, no CA, and no first-use trust leap.
//!
//! Mutual, not one-sided, because it is what authenticates the *client* on the
//! persistent side-channel path, which carries no per-request HMAC (bierpc
//! sends `Call::Persistent` straight to the handler). On the unary path the
//! `auth` HMAC still runs on top as before.

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

/// The TLS identity derived from the shared auth key. Both ends derive the
/// same one, so a cert built here is what the peer pins.
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

    /// The public key each end pins for the other.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    fn pkcs8_der(&self) -> Vec<u8> {
        let mut der = Vec::with_capacity(ED25519_PKCS8_PREFIX.len() + 32);
        der.extend_from_slice(&ED25519_PKCS8_PREFIX);
        der.extend_from_slice(&self.signing.to_bytes());
        der
    }

    /// A fresh self-signed cert over this identity, and the matching key. The
    /// cert bytes vary per call (serial/validity); only the pinned public key
    /// is checked, so that does not matter.
    fn cert_and_key(&self) -> Result<(pki_types::CertificateDer<'static>, pki_types::PrivateKeyDer<'static>), String> {
        let pkcs8 = pki_types::PrivatePkcs8KeyDer::from(self.pkcs8_der());
        let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_ED25519)
            .map_err(|e| format!("loading the derived key: {e}"))?;
        // The name is irrelevant: the peer pins the key, not the hostname.
        let cert = rcgen::CertificateParams::new(vec!["container".to_string()])
            .and_then(|params| params.self_signed(&key_pair))
            .map_err(|e| format!("self-signing the cert: {e}"))?;
        let key_der = pki_types::PrivateKeyDer::Pkcs8(pki_types::PrivatePkcs8KeyDer::from(self.pkcs8_der()));
        Ok((cert.der().clone(), key_der))
    }

    /// A rustls server config that presents this identity and requires the
    /// client to present the same one. TLS 1.3 only.
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, String> {
        let (cert, key) = self.cert_and_key()?;
        let provider = Arc::new(provider());
        let verifier = Arc::new(PinnedClientVerifier {
            expected_public_key: self.public_key(),
            provider: provider.clone(),
            hint_subjects: Vec::new(),
        });
        rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| format!("selecting TLS 1.3: {e}"))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert], key)
            .map(Arc::new)
            .map_err(|e| format!("installing the cert: {e}"))
    }

    /// A rustls client config that presents this identity and pins the same one
    /// as the only acceptable server. TLS 1.3 only.
    pub fn client_config(&self) -> Result<ClientTlsConfig, String> {
        let (cert, key) = self.cert_and_key()?;
        let provider = Arc::new(provider());
        let verifier = Arc::new(PinnedServerVerifier {
            expected_public_key: self.public_key(),
            provider: provider.clone(),
        });
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| format!("selecting TLS 1.3: {e}"))?
            .dangerous() // "dangerous" only in that it bypasses the webpki CA path
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(vec![cert], key)
            .map_err(|e| format!("installing the client cert: {e}"))?;
        // A placeholder SNI: the verifier ignores the name entirely.
        let server_name = pki_types::ServerName::try_from("container").expect("valid DNS name");
        Ok(ClientTlsConfig::new(config, server_name))
    }
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
            _ => Err(rustls::Error::General("server key does not match the pinned identity".into())),
        }
    }

    // Possession of the pinned key is proven by the handshake signature, which
    // the provider verifies against the (now-pinned) cert key. Never stub these.
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

#[derive(Debug)]
struct PinnedClientVerifier {
    expected_public_key: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
    hint_subjects: Vec<rustls::DistinguishedName>,
}

impl rustls::server::danger::ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &self.hint_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &pki_types::CertificateDer,
        _intermediates: &[pki_types::CertificateDer],
        _now: pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        match cert_ed25519_key(end_entity) {
            Some(key) if key == self.expected_public_key => {
                Ok(rustls::server::danger::ClientCertVerified::assertion())
            }
            _ => Err(rustls::Error::General("client key does not match the pinned identity".into())),
        }
    }

    // As on the server verifier: the signature check proves the client holds
    // the private key, not just a copy of the (public) cert. Never stub these.
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

    /// A real localhost mutual-TLS 1.3 handshake, driven by a client config the
    /// caller supplies so both the matching and the attacker cases share one
    /// path. Exercises the derived certs, both pinning verifiers, and the
    /// provider together — the parts that only fail as a group.
    async fn handshake(server_key: &[u8], client: ClientTlsConfig) -> Result<(), String> {
        let server_config = Identity::derive(server_key).server_config()
            .map_err(|e| format!("server config: {e}"))?;

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

        let connector = tokio_rustls::TlsConnector::from(Arc::new((*client.config).clone()));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = connector.connect(client.server_name.clone(), tcp).await
            .map_err(|e| format!("connect: {e}"))?;
        tls.write_all(b"ping").await.map_err(|e| format!("client write: {e}"))?;
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.map_err(|e| format!("client read: {e}"))?;
        assert_eq!(&buf, b"ping");
        server.await.unwrap()
    }

    /// A client that presents no certificate and trusts any server — an
    /// unauthenticated caller, the exact thing mTLS must turn away.
    fn anonymous_client() -> ClientTlsConfig {
        #[derive(Debug)]
        struct TrustAny;
        impl rustls::client::danger::ServerCertVerifier for TrustAny {
            fn verify_server_cert(&self, _: &pki_types::CertificateDer, _: &[pki_types::CertificateDer], _: &pki_types::ServerName, _: &[u8], _: pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(&self, _: &[u8], _: &pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(&self, _: &[u8], _: &pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                provider().signature_verification_algorithms.supported_schemes()
            }
        }
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
            .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TrustAny))
            .with_no_client_auth();
        ClientTlsConfig::new(config, pki_types::ServerName::try_from("container").unwrap())
    }

    #[tokio::test]
    async fn matching_key_handshakes() {
        let key = crate::auth::hash_or_random(None);
        let client = Identity::derive(&key).client_config().unwrap();
        handshake(&key, client).await.expect("matching keys must complete the handshake");
    }

    #[tokio::test]
    async fn wrong_key_client_is_refused() {
        let server_key = crate::auth::hash_or_random(None);
        let client = Identity::derive(&crate::auth::hash_or_random(None)).client_config().unwrap();
        assert!(
            handshake(&server_key, client).await.is_err(),
            "a client with a different key must not complete the handshake",
        );
    }

    #[tokio::test]
    async fn uncertified_client_is_refused() {
        let server_key = crate::auth::hash_or_random(None);
        assert!(
            handshake(&server_key, anonymous_client()).await.is_err(),
            "a client presenting no certificate must be turned away",
        );
    }

    #[test]
    fn identity_is_deterministic() {
        let key = crate::auth::hash_or_random(Some("pin-me"));
        assert_eq!(Identity::derive(&key).public_key(), Identity::derive(&key).public_key());
    }
}
