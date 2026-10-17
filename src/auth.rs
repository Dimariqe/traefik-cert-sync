use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEME: &str = "TCS1";
/// String covered by the HMAC; binds the token to this endpoint and protocol
/// version so the same timestamp cannot be replayed elsewhere.
const AUTH_CONTEXT: &str = "tcs/1/certs";
/// How far the timestamp may drift from the receiver's clock, in seconds.
pub const TIMESTAMP_WINDOW: i64 = 300;

type HmacSha256 = Hmac<Sha256>;

/// Computes the hex HMAC token for `ts`.
pub fn token(key: &str, ts: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(format!("{}:{}", AUTH_CONTEXT, ts).as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Builds the Authorization header value for a request made now.
pub fn header_value(key: &str) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{} {}:{}", SCHEME, ts, token(key, &ts.to_string()))
}

/// Constant-time equality for equal-length slices; length differences also
/// only surface as a mismatch.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Parses `TCS1 <ts>:<hex>` and verifies timestamp freshness and the HMAC.
pub fn verify_header(key: &str, header: &str, now_unix: i64) -> bool {
    let mut parts = header.trim().split_whitespace();
    let credentials = match (parts.next(), parts.next()) {
        (Some(scheme), Some(credentials)) if scheme.eq_ignore_ascii_case(SCHEME) => credentials,
        _ => return false,
    };

    let mut fields = credentials.splitn(2, ':');
    let (ts, provided) = match (fields.next(), fields.next()) {
        (Some(ts), Some(provided)) => (ts, provided),
        _ => return false,
    };

    let Ok(ts_secs) = ts.parse::<i64>() else {
        return false;
    };
    if (now_unix - ts_secs).abs() > TIMESTAMP_WINDOW {
        return false;
    }

    let expected = token(key, ts);
    ct_eq(expected.as_bytes(), provided.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "test-key";

    #[test]
    fn token_is_deterministic_and_key_dependent() {
        assert_eq!(token(KEY, "123"), token(KEY, "123"));
        assert_ne!(token(KEY, "123"), token("other", "123"));
        assert_ne!(token(KEY, "123"), token(KEY, "124"));
    }

    #[test]
    fn verify_accepts_fresh_token() {
        let t = token(KEY, "1000");
        let header = format!("{} 1000:{}", SCHEME, t);
        assert!(verify_header(KEY, &header, 1000));
        assert!(verify_header(KEY, &header, 1000 + TIMESTAMP_WINDOW));
        assert!(!verify_header(KEY, &header, 1000 + TIMESTAMP_WINDOW + 1));
        assert!(!verify_header(KEY, &header, 1000 - TIMESTAMP_WINDOW - 1));
    }

    #[test]
    fn verify_rejects_wrong_key_scheme_or_garbage() {
        let header = format!("{} 1000:{}", SCHEME, token(KEY, "1000"));
        assert!(!verify_header("wrong", &header, 1000));
        assert!(!verify_header(KEY, "Bearer 1000:abc", 1000));
        assert!(!verify_header(KEY, "garbage", 1000));
        assert!(!verify_header(KEY, "TCS1 not-a-number:abc", 1000));
        // Correct token computed for a different timestamp.
        assert!(!verify_header(
            KEY,
            &format!("{} 999:{}", SCHEME, token(KEY, "1000")),
            1000
        ));
    }
}
