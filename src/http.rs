use std::io::Read;

/// A parsed HTTP response: status code and decoded body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Reads one full HTTP/1.1 response from `stream`, following
/// `Content-Length` and `Transfer-Encoding: chunked`, falling back to
/// read-to-EOF for connection-close responses. Expects the server to close
/// the connection afterwards (we always send `Connection: close`).
pub fn read_response(stream: &mut dyn Read, max_bytes: usize) -> Result<Response, String> {
    let mut buf = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 16 * 1024];
    let head_end = loop {
        if let Some(head_end) = find_head_end(&buf) {
            break head_end;
        }
        if buf.len() > max_bytes {
            return Err("response too large".to_string());
        }
        let n = stream
            .read(&mut chunk)
            .map_err(|e| format!("read failed: {}", e))?;
        if n == 0 {
            return Err("connection closed before response head was complete".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let head = std::str::from_utf8(&buf[..head_end])
        .map_err(|_| "malformed response: header is not UTF-8".to_string())?;
    let status = parse_status(head)?;

    let is_chunked = header_value(head, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);

    if is_chunked {
        while !chunked_complete(&buf[head_end..]) {
            let n = stream
                .read(&mut chunk)
                .map_err(|e| format!("read failed: {}", e))?;
            if n == 0 {
                return Err("connection closed mid-chunked-body".to_string());
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let body = decode_chunked(&buf[head_end..])?;
        return Ok(Response { status, body });
    }

    let mut body_end = None;
    if let Some(len) =
        header_value(head, "content-length").and_then(|v| v.trim().parse::<usize>().ok())
    {
        body_end = Some(head_end + len);
    }
    let body_end = match body_end {
        Some(end) => {
            while buf.len() < end {
                let n = stream
                    .read(&mut chunk)
                    .map_err(|e| format!("read failed: {}", e))?;
                if n == 0 {
                    return Err("connection closed before body was complete".to_string());
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            end
        }
        None => {
            loop {
                if buf.len() > max_bytes {
                    return Err("response too large".to_string());
                }
                let n = match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => return Err(format!("read failed: {}", e)),
                };
                buf.extend_from_slice(&chunk[..n]);
            }
            buf.len()
        }
    };

    Ok(Response {
        status,
        body: buf[head_end..body_end].to_vec(),
    })
}

pub fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn parse_status(head: &str) -> Result<u16, String> {
    let status_line = head.lines().next().unwrap_or_default();
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("malformed status line: {:?}", status_line))
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    for line in head.split("\r\n").skip(1) {
        if let Some((header_name, value)) = line.split_once(':') {
            if header_name.trim().eq_ignore_ascii_case(name) {
                return Some(value.trim());
            }
        }
    }
    None
}

/// Whether a chunked body buffer ends with the zero-length terminator chunk.
fn chunked_complete(body: &[u8]) -> bool {
    decode_chunked(body).is_ok()
}

/// Decodes a complete chunked body; errors if the terminator chunk is
/// missing.
fn decode_chunked(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let line_end = body[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("missing chunk header terminator")?;
        let size_str = std::str::from_utf8(&body[pos..pos + line_end])
            .map_err(|_| "chunk size is not UTF-8".to_string())?;
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("invalid chunk size: {:?}", size_hex))?;
        pos += line_end + 2;
        if size == 0 {
            return Ok(out);
        }
        if body.len() < pos + size + 2 {
            return Err("chunked body truncated".to_string());
        }
        out.extend_from_slice(&body[pos..pos + size]);
        pos += size + 2; // skip trailing CRLF
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader yielding the response in small pieces to exercise buffering.
    struct Piecewise {
        pieces: Vec<Vec<u8>>,
        idx: usize,
    }

    impl Read for Piecewise {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.idx >= self.pieces.len() {
                return Ok(0);
            }
            let piece = &self.pieces[self.idx];
            let n = piece.len().min(buf.len());
            buf[..n].copy_from_slice(&piece[..n]);
            if n == piece.len() {
                self.idx += 1;
            }
            Ok(n)
        }
    }

    fn response_of(pieces: Vec<Vec<u8>>) -> Result<Response, String> {
        read_response(&mut Piecewise { pieces, idx: 0 }, 1024 * 1024)
    }

    #[test]
    fn reads_content_length_response() {
        let r = response_of(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec()
        ])
        .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello");
    }

    #[test]
    fn reads_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3\r\n wo\r\n2\r\nrl\r\n1\r\nd\r\n0\r\n\r\n";
        let r = response_of(vec![raw.to_vec()]).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello world");
    }

    #[test]
    fn reads_connection_close_response_without_length() {
        let r = response_of(vec![b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()]).unwrap();
        assert_eq!(r.status, 204);
        assert!(r.body.is_empty());
    }

    #[test]
    fn handles_split_packets_and_case_insensitive_headers() {
        let r = response_of(vec![
            b"HTTP/1.1 404 Not F".to_vec(),
            b"ound\r\ncontent-LENGTH: 3\r".to_vec(),
            b"\n\r\nabc".to_vec(),
        ])
        .unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(r.body, b"abc");
    }

    #[test]
    fn rejects_truncated_head() {
        assert!(response_of(vec![b"HTTP/1.1 200 OK\r\nContent-Len".to_vec()]).is_err());
    }
}
