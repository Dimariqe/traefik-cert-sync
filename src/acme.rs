use base64::Engine;
use serde::Deserialize;
use std::collections::HashMap;

/// One certificate as served by the dumper: the domain names its output
/// directory after, plus PEM-encoded certificate and private key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CertEntry {
    pub domain: String,
    pub certificate: String,
    pub key: String,
}

#[derive(Debug, Deserialize)]
struct AcmeFile(HashMap<String, Store>);

#[derive(Debug, Deserialize)]
struct Store {
    #[serde(default, alias = "Certificates")]
    certificates: Vec<Cert>,
}

#[derive(Debug, Deserialize)]
struct Cert {
    #[serde(default)]
    domain: Domain,
    #[serde(default)]
    certificate: String,
    #[serde(default)]
    key: String,
}

#[derive(Debug, Default, Deserialize)]
struct Domain {
    #[serde(default)]
    main: String,
    #[serde(default)]
    sans: Vec<String>,
}

/// Parses a Traefik v2 acme.json file into dumpable certificate entries.
///
/// Traefik stores certificate/key as base64 of the PEM text; raw DER (as
/// written by some older setups) is wrapped into PEM as a fallback. Only the
/// main domain of each certificate becomes an output directory, mirroring
/// ldez/traefik-certs-dumper's `--domain-subdir` layout. Later entries win
/// over earlier ones for the same domain, matching repeated file writes.
pub fn parse_acme(json: &str) -> Result<Vec<CertEntry>, String> {
    let file: AcmeFile =
        serde_json::from_str(json).map_err(|e| format!("invalid acme.json: {}", e))?;

    let mut by_domain: HashMap<String, CertEntry> = HashMap::new();
    for store in file.0.values() {
        for cert in &store.certificates {
            let domain = if !cert.domain.main.is_empty() {
                cert.domain.main.clone()
            } else {
                match cert.domain.sans.first() {
                    Some(san) => san.clone(),
                    None => continue,
                }
            };
            let certificate = decode_pem_field(&cert.certificate, None)
                .map_err(|e| format!("certificate of '{}': {}", domain, e))?;
            let key = decode_pem_field(&cert.key, Some(KeyKind::from_cert(&certificate)))
                .map_err(|e| format!("key of '{}': {}", domain, e))?;
            by_domain.insert(
                domain.clone(),
                CertEntry {
                    domain,
                    certificate,
                    key,
                },
            );
        }
    }

    Ok(by_domain.into_values().collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    RsaPkcs1,
    RsaPkcs8,
    EcSec1,
    Unknown,
}

impl KeyKind {
    /// The public key algorithm of the certificate decides how an opaque
    /// private key blob should be labelled if it turns out to be raw DER.
    fn from_cert(cert_pem: &str) -> Self {
        if cert_pem.contains("RSA PUBLIC KEY") {
            Self::RsaPkcs1
        } else {
            Self::Unknown
        }
    }

    fn pem_label(self) -> &'static str {
        match self {
            Self::RsaPkcs1 => "RSA PRIVATE KEY",
            Self::RsaPkcs8 => "PRIVATE KEY",
            Self::EcSec1 => "EC PRIVATE KEY",
            Self::Unknown => "PRIVATE KEY",
        }
    }
}

/// Base64-decodes an acme.json field. The result is PEM text in the normal
/// case; anything else is treated as DER and wrapped, with `hint` choosing
/// the PEM label for keys.
fn decode_pem_field(value: &str, hint: Option<KeyKind>) -> Result<String, String> {
    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|e| format!("invalid base64: {}", e))?;

    if decoded.starts_with(b"-----BEGIN") {
        return Ok(normalize_pem(&String::from_utf8_lossy(&decoded)));
    }

    let label = match hint {
        Some(kind) => sniff_key_kind(&decoded).unwrap_or(kind).pem_label(),
        None => "CERTIFICATE",
    };
    Ok(wrap_der_in_pem(&decoded, &label))
}

/// Normalizes PEM text: LF line endings, no leading blank space, one trailing
/// newline.
pub fn normalize_pem(pem: &str) -> String {
    let replaced = pem.replace("\r\n", "\n");
    let normalized = replaced.trim_matches('\n');
    let mut out = String::with_capacity(normalized.len() + 1);
    for line in normalized.split('\n') {
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

fn wrap_der_in_pem(der: &[u8], label: &str) -> String {
    use std::fmt::Write;

    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        let _ = out.write_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    let _ = writeln!(out, "-----END {}-----", label);
    out
}

/// Walks just enough ASN.1 to tell private key formats apart.
fn sniff_key_kind(der: &[u8]) -> Option<KeyKind> {
    let (tag, content, _) = read_tlv(der)?; // outer SEQUENCE
    if tag != 0x30 {
        return None;
    }
    let (tag, value, rest) = read_tlv(content)?; // version INTEGER
    if tag != 0x02 || value != [0u8] || rest.is_empty() {
        return None;
    }
    match rest[0] {
        0x02 => Some(KeyKind::RsaPkcs1), // INTEGER modulus
        0x30 => Some(KeyKind::RsaPkcs8), // SEQUENCE AlgorithmIdentifier
        0x04 => Some(KeyKind::EcSec1),   // OCTET STRING private key
        _ => None,
    }
}

/// Reads one DER TLV header, returning (tag, value, bytes after the TLV).
fn read_tlv(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&len_byte, rest) = rest.split_first()?;
    let (len, rest) = if len_byte & 0x80 == 0 {
        (len_byte as usize, rest)
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > rest.len() {
            return None;
        }
        let mut len = 0usize;
        for &b in &rest[..n] {
            len = (len << 8) | b as usize;
        }
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../dev/acme.json");

    #[test]
    fn parses_dev_fixture() {
        let certs = parse_acme(FIXTURE).unwrap();
        let mut domains: Vec<&str> = certs.iter().map(|c| c.domain.as_str()).collect();
        domains.sort_unstable();
        assert_eq!(
            domains,
            vec![
                "autodiscover.example.com",
                "example.com",
                "test.example.com"
            ]
        );
        for cert in &certs {
            assert!(cert
                .certificate
                .starts_with("-----BEGIN CERTIFICATE-----\n"));
            assert!(cert.certificate.ends_with("-----END CERTIFICATE-----\n"));
            assert!(cert.key.starts_with("-----BEGIN"));
            assert!(
                cert.key.ends_with("-----END PRIVATE KEY-----\n")
                    || cert.key.contains("KEY-----\n")
            );
        }
    }

    #[test]
    fn later_entry_for_same_domain_wins() {
        let json = r#"{"letsencrypt":{"Certificates":[
            {"domain":{"main":"a.com"},"certificate":"BGFBQVNU","key":"BGFBQVNU"},
            {"domain":{"main":"a.com"},"certificate":"QkxBU1Q=","key":"QkxBU1Q="}
        ]}}"#;
        let certs = parse_acme(json).unwrap();
        assert_eq!(certs.len(), 1);
        assert!(certs[0].certificate.contains("QkxBU1Q"));
    }

    #[test]
    fn entry_without_domains_is_skipped() {
        let json = r#"{"letsencrypt":{"Certificates":[
            {"domain":{"main":"","sans":[]},"certificate":"QUJD","key":"QUJD"}
        ]}}"#;
        assert!(parse_acme(json).unwrap().is_empty());
    }

    #[test]
    fn falls_back_to_first_san_when_main_is_empty() {
        let json = r#"{"letsencrypt":{"Certificates":[
            {"domain":{"main":"","sans":["san.com","other.com"]},"certificate":"QUJD","key":"QUJD"}
        ]}}"#;
        let certs = parse_acme(json).unwrap();
        assert_eq!(certs[0].domain, "san.com");
    }

    #[test]
    fn raw_der_certificate_is_wrapped() {
        // SEQUENCE { INTEGER 0x05 }
        let der = [0x30, 0x03, 0x02, 0x01, 0x05];
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let json = format!(
            r#"{{"letsencrypt":{{"Certificates":[{{"domain":{{"main":"a.com"}},"certificate":"{}","key":"{}"}}]}}}}"#,
            b64, b64
        );
        let certs = parse_acme(&json).unwrap();
        assert!(certs[0]
            .certificate
            .starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn pkcs1_key_der_is_labelled_rsa() {
        // SEQUENCE { INTEGER 0, INTEGER 0xCAFEBABE }
        let der = [
            0x30, 0x09, 0x02, 0x01, 0x00, 0x02, 0x04, 0xCA, 0xFE, 0xBA, 0xBE,
        ];
        assert_eq!(sniff_key_kind(&der), Some(KeyKind::RsaPkcs1));
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let json = format!(
            r#"{{"letsencrypt":{{"Certificates":[{{"domain":{{"main":"a.com"}},"certificate":"QUJD","key":"{}"}}]}}}}"#,
            b64
        );
        let certs = parse_acme(&json).unwrap();
        assert!(certs[0].key.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
    }

    #[test]
    fn pkcs8_key_der_is_labelled_private_key() {
        // SEQUENCE { INTEGER 0, SEQUENCE { ... }, OCTET STRING }
        let der = [
            0x30, 0x0B, 0x02, 0x01, 0x00, 0x30, 0x02, 0x05, 0x00, 0x04, 0x02, 0xAA, 0xBB,
        ];
        assert_eq!(sniff_key_kind(&der), Some(KeyKind::RsaPkcs8));
    }

    #[test]
    fn pem_normalization() {
        assert_eq!(
            normalize_pem("-----BEGIN X-----\r\nabc\r\n-----END X-----\r\n\r\n"),
            "-----BEGIN X-----\nabc\n-----END X-----\n"
        );
    }
}
