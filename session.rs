// =============================================================================
// session.rs — MASQUE Core: Control Plane & Concurrent Forwarding Engine
//
// Implements:
//   • RFC 9298 §3   — CONNECT-UDP handshake validation
//   • RFC 9298 §4   — Context ID = 0 (default UDP proxy context)
//   • RFC 9297 §2   — HTTP Datagram path (QUIC DATAGRAM frames)
//   • RFC 9297 §3   — Capsule path (HTTP/3 DATA stream, streaming decode)
//   • RFC 9298 §7   — Session lifecycle (stream close → tunnel teardown)
// =============================================================================

use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::protocol::{
    decode_capsule, decode_http_datagram, encode_http_datagram, CapsuleType, ProtocolError,
    CONNECT_UDP_DEFAULT_CONTEXT_ID,
};

// -----------------------------------------------------------------------------
// § Error Types
// -----------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("invalid CONNECT-UDP handshake: {reason}")]
    InvalidHandshake { reason: &'static str },

    #[error("path parse error: {0}")]
    ParseError(String),

    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    ProtocolError(#[from] ProtocolError),

    #[error("session channel closed unexpectedly")]
    ChannelClosed,
}

// -----------------------------------------------------------------------------
// § QuicMessage — typed abstraction over the QUIC/H3 receive path
//
// Design rationale:
//   The raw channel carries heterogeneous messages from two distinct H3
//   mechanisms.  Encoding the distinction in the type system — rather than
//   requiring the forwarding engine to guess from byte patterns — keeps each
//   match arm in `run()` single-purpose and eliminates an entire class of
//   ambiguity bugs.
//
//   RFC 9297 §2  → `Datagram`   : one QUIC DATAGRAM frame, self-delimiting.
//   RFC 9297 §3  → `StreamChunk`: raw bytes from an H3 DATA stream, may be
//                                  partial (half-packet / concatenated frames).
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum QuicMessage {
    /// A complete, self-delimiting QUIC DATAGRAM frame payload.
    /// RFC 9297 §2: the entire frame IS the HTTP Datagram.
    Datagram(Bytes),

    /// A raw chunk from an HTTP/3 DATA stream.
    /// RFC 9297 §3: may contain 0..N complete Capsules plus a trailing partial.
    StreamChunk(Bytes),

    /// The QUIC stream (or connection) was closed by the peer.
    /// RFC 9298 §7: "If a CONNECT-UDP stream is closed, the UDP socket
    /// MUST be closed."
    Closed,
}

// -----------------------------------------------------------------------------
// § Handshake Validator
// -----------------------------------------------------------------------------

/// RFC 9298 §3 — Parse and validate an Extended CONNECT request for
/// the `connect-udp` protocol, extracting the target host and port.
///
/// Expected request shape (RFC 9298 §3.1):
///
/// ```text
/// CONNECT /.well-known/masque/udp/{target_host}/{target_port}/ HTTP/3
/// :protocol = connect-udp
/// capsule-protocol = ?1
/// ```
pub fn parse_connect_udp_target(
    req: &http::Request<()>,
) -> Result<(String, u16), SessionError> {
    // RFC 9298 §3: method MUST be CONNECT.
    if req.method() != http::Method::CONNECT {
        return Err(SessionError::InvalidHandshake {
            reason: ":method must be CONNECT",
        });
    }

    // RFC 9220 §3 / RFC 9298 §3: :protocol MUST be "connect-udp".
    // In HTTP/3 this is carried as the `:protocol` pseudo-header.
    // The `http` crate exposes it via the `extensions` map when populated by
    // the H3 layer; we also accept it as a plain header for testability.
    let protocol = req
        .headers()
        .get("x-protocol") // test shim header
        .or_else(|| req.headers().get(":protocol"))
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("");

    // RFC 9298 §3: :protocol MUST be "connect-udp".
    if protocol != "connect-udp" {
        return Err(SessionError::InvalidHandshake {
            reason: ":protocol must be 'connect-udp'",
        });
    }

    // RFC 9298 §3.1 — URI template:
    //   "/.well-known/masque/udp/{target_host}/{target_port}/"
    let path = req.uri().path();
    parse_masque_udp_path(path)
}

/// RFC 9298 §3.1 — Parse the CONNECT-UDP URI template path.
///
/// Valid form: `/.well-known/masque/udp/{target_host}/{target_port}/`
///
/// The trailing slash is required by the template. `target_host` may be
/// a domain name or a percent-encoded IP address literal.
fn parse_masque_udp_path(path: &str) -> Result<(String, u16), SessionError> {
    // RFC 9298 §3.1: prefix is fixed.
    const PREFIX: &str = "/.well-known/masque/udp/";

    let after_prefix = path.strip_prefix(PREFIX).ok_or_else(|| {
        SessionError::ParseError(format!(
            "path '{path}' does not start with '{PREFIX}'"
        ))
    })?;

    // Must end with a trailing slash.
    let without_trailing = after_prefix.strip_suffix('/').ok_or_else(|| {
        SessionError::ParseError(format!(
            "path '{path}' must end with '/'"
        ))
    })?;

    // RFC 9298 §3.1: the remaining segment is "{target_host}/{target_port}".
    // The host itself may contain colons (IPv6) or dots, but the port is
    // always the final path segment.
    let slash_pos = without_trailing.rfind('/').ok_or_else(|| {
        SessionError::ParseError(format!(
            "path '{path}' missing '{{host}}/{{port}}' structure"
        ))
    })?;

    let host_raw = &without_trailing[..slash_pos];
    let port_raw = &without_trailing[slash_pos + 1..];

    if host_raw.is_empty() {
        return Err(SessionError::ParseError(
            "target_host must not be empty".into(),
        ));
    }

    // Percent-decode the host (RFC 9298 §3.1 allows percent-encoding).
    let host = percent_decode(host_raw).map_err(|e| SessionError::ParseError(e))?;

    let port: u16 = port_raw.parse().map_err(|_| {
        SessionError::ParseError(format!("invalid port '{port_raw}'"))
    })?;

    if port == 0 {
        return Err(SessionError::ParseError("port 0 is not valid".into()));
    }

    Ok((host, port))
}

/// Minimal percent-decoder for URI path segments (RFC 3986 §2.1).
/// Only decodes `%XX` sequences; passes everything else through verbatim.
fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(format!("truncated percent-escape at position {i}"));
            }
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                .map_err(|_| format!("non-UTF8 percent-escape at position {i}"))?;
            let byte = u8::from_str_radix(hex, 16)
                .map_err(|_| format!("invalid hex '{hex}' at position {i}"))?;
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "decoded host is not valid UTF-8".into())
}

// -----------------------------------------------------------------------------
// § ConnectUdpSession — Concurrent Bidirectional Forwarding Engine
// -----------------------------------------------------------------------------

/// RFC 9298 §4 — A live CONNECT-UDP tunnel session.
///
/// Owns a bound UDP socket and two ends of the typed QUIC channel:
///
/// ```text
///  H3/QUIC --[h3_rx]--> ConnectUdpSession --UDP--> target
///  H3/QUIC <-[h3_tx]--  ConnectUdpSession <--UDP-- target
/// ```
///
/// The session runs a `tokio::select!` loop that concurrently services both
/// directions until either the QUIC side closes or the UDP socket errors.
pub struct ConnectUdpSession {
    /// Bound UDP socket for communicating with the proxied target.
    udp: UdpSocket,
    /// Connected/remembered target address (set on first downstream packet).
    target_addr: Option<SocketAddr>,
    /// Inbound channel from the QUIC/H3 layer.
    h3_rx: mpsc::Receiver<QuicMessage>,
    /// Outbound channel to the QUIC/H3 layer.
    h3_tx: mpsc::Sender<Bytes>,
    /// Reassembly buffer for the Capsule stream path (RFC 9297 §3).
    capsule_buf: BytesMut,
    /// Maximum UDP datagram size we will read from the socket at once.
    udp_recv_buf_size: usize,
}

impl ConnectUdpSession {
    /// Construct a new session.
    ///
    /// # Arguments
    ///
    /// * `udp`    – A pre-bound `UdpSocket`. The caller is responsible for
    ///              binding to the correct local interface.
    /// * `h3_rx`  – Receives `QuicMessage` frames from the H3 layer.
    /// * `h3_tx`  – Sends encoded `Bytes` back to the H3 layer.
    pub fn new(
        udp: UdpSocket,
        h3_rx: mpsc::Receiver<QuicMessage>,
        h3_tx: mpsc::Sender<Bytes>,
    ) -> Self {
        Self {
            udp,
            target_addr: None,
            h3_rx,
            h3_tx,
            capsule_buf: BytesMut::with_capacity(4096),
            udp_recv_buf_size: 65535,
        }
    }

    /// Override the UDP receive buffer size (default: 65535 bytes).
    pub fn with_udp_recv_buf_size(mut self, size: usize) -> Self {
        self.udp_recv_buf_size = size;
        self
    }

    /// RFC 9298 §4 — Run the bidirectional forwarding loop.
    ///
    /// Returns when the session terminates (peer closed, IO error, channel
    /// closed).  Never panics; all errors are logged and returned.
    pub async fn run(&mut self) -> Result<(), SessionError> {
        // Pre-allocate a reusable UDP receive buffer to avoid per-iteration
        // heap allocation.  We use `BytesMut` so we can freeze sub-slices
        // without copying.
        let mut udp_recv_buf = BytesMut::with_capacity(self.udp_recv_buf_size);

        loop {
            tokio::select! {
                // ── Arm A: QUIC/H3 → UDP (downstream) ───────────────────────
                msg = self.h3_rx.recv() => {
                    match msg {
                        None | Some(QuicMessage::Closed) => {
                            // RFC 9298 §7: "If a CONNECT-UDP stream is closed,
                            // the associated UDP socket MUST be closed."
                            debug!("H3 channel closed; tearing down UDP session");
                            return Ok(());
                        }
                        Some(QuicMessage::Datagram(raw)) => {
                            // RFC 9297 §2: each DATAGRAM frame is self-delimiting.
                            if let Err(e) = self.forward_datagram_to_udp(raw).await {
                                warn!("datagram→udp forward error: {e}");
                                // Non-fatal for datagrams: log and continue.
                            }
                        }
                        Some(QuicMessage::StreamChunk(chunk)) => {
                            // RFC 9297 §3: stream bytes accumulate in the
                            // reassembly buffer; one chunk may carry partial,
                            // one, or multiple Capsules.
                            if let Err(e) = self.forward_stream_chunk_to_udp(chunk).await {
                                warn!("capsule→udp forward error: {e}");
                                // Non-fatal: skip malformed capsule, keep going.
                            }
                        }
                    }
                }

                // ── Arm B: UDP → QUIC/H3 (upstream) ─────────────────────────
                recv_result = self.udp.recv_buf_from(&mut udp_recv_buf) => {
                    match recv_result {
                        Err(e) => {
                            warn!("UDP recv error: {e}");
                            return Err(SessionError::IoError(e));
                        }
                        Ok((_n, peer_addr)) => {
                            // Remember or validate the target address.
                            // RFC 9298 §3.4: the proxy SHOULD verify the source
                            // address matches the expected target.
                            self.record_target(peer_addr);

                            // recv_buf_from *appends* bytes to the BytesMut
                            // write cursor.  We split the entire filled content
                            // off as a frozen Bytes (zero-copy, ref-counted),
                            // then clear so the buffer is empty for next call.
                            let payload: Bytes = udp_recv_buf.split().freeze();

                            if let Err(e) = self.forward_udp_to_h3(payload).await {
                                warn!("udp→h3 forward error: {e}");
                                // If the H3 sender is gone, the tunnel is done.
                                if matches!(e, SessionError::ChannelClosed) {
                                    return Err(e);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// RFC 9297 §2 + RFC 9298 §4 — Handle one QUIC DATAGRAM frame.
    ///
    /// Decodes the HTTP Datagram, validates Context ID = 0, and writes the
    /// UDP payload to the target socket.
    async fn forward_datagram_to_udp(&mut self, raw: Bytes) -> Result<(), SessionError> {
        let dgram = decode_http_datagram(raw)?;

        // RFC 9298 §4: Context ID 0 is the default proxy context.
        // Unknown context IDs MUST be silently ignored.
        if dgram.context_id != CONNECT_UDP_DEFAULT_CONTEXT_ID {
            debug!(
                context_id = dgram.context_id,
                "ignoring datagram with non-zero context id"
            );
            return Ok(());
        }

        self.send_udp_payload(dgram.payload).await
    }

    /// RFC 9297 §3 — Accumulate a stream chunk and drain complete Capsules.
    ///
    /// The `capsule_buf` persists across calls to handle half-packets.
    async fn forward_stream_chunk_to_udp(&mut self, chunk: Bytes) -> Result<(), SessionError> {
        // Append the new chunk to the reassembly buffer.
        self.capsule_buf.extend_from_slice(&chunk);

        // Drain all complete Capsules from the buffer.
        loop {
            match decode_capsule(&mut self.capsule_buf)? {
                None => break, // need more bytes
                Some(capsule) => {
                    match capsule.capsule_type {
                        CapsuleType::Datagram => {
                            // RFC 9297 §3.5: DATAGRAM capsule carries an
                            // HTTP Datagram in its payload.
                            let dgram = decode_http_datagram(capsule.payload)?;
                            if dgram.context_id != CONNECT_UDP_DEFAULT_CONTEXT_ID {
                                debug!(
                                    context_id = dgram.context_id,
                                    "ignoring capsule with non-zero context id"
                                );
                                continue;
                            }
                            self.send_udp_payload(dgram.payload).await?;
                        }
                        CapsuleType::Unknown(t) => {
                            // RFC 9297 §3.3: unknown capsule types MUST be
                            // silently skipped; this was already consumed by
                            // decode_capsule, so we just log.
                            debug!(capsule_type = t, "skipping unknown capsule type");
                        }
                        other => {
                            // Known extension capsules (ADDRESS_ASSIGN, etc.)
                            // are not handled in this minimal implementation.
                            debug!("unhandled known capsule type: {other:?}");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// RFC 9297 §2 + RFC 9298 §4 — Encode a UDP payload as an HTTP Datagram
    /// (Context ID = 0) and send it to the H3 layer.
    async fn forward_udp_to_h3(&self, payload: Bytes) -> Result<(), SessionError> {
        // RFC 9298 §4: upstream datagrams always use Context ID 0.
        let encoded = encode_http_datagram(CONNECT_UDP_DEFAULT_CONTEXT_ID, &payload);
        self.h3_tx
            .send(encoded)
            .await
            .map_err(|_| SessionError::ChannelClosed)
    }

    /// Write `payload` to the UDP socket.
    ///
    /// If a target address has been recorded (learned from the first upstream
    /// packet), we use `send_to` so the socket can remain unconnected and
    /// serve multiple flows.  If not yet known, we fall back to `send` which
    /// requires the socket to be pre-connected by the caller.
    async fn send_udp_payload(&self, payload: Bytes) -> Result<(), SessionError> {
        match self.target_addr {
            Some(addr) => {
                self.udp.send_to(&payload, addr).await?;
            }
            None => {
                // Socket must be connected by caller in this case.
                self.udp.send(&payload).await?;
            }
        }
        Ok(())
    }

    /// Record the target address on first upstream packet.
    fn record_target(&mut self, addr: SocketAddr) {
        if self.target_addr.is_none() {
            debug!(%addr, "learned UDP target address");
            self.target_addr = Some(addr);
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::Request;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration};

    use crate::protocol::{encode_http_datagram, Capsule, CapsuleType, CONNECT_UDP_DEFAULT_CONTEXT_ID};

    // ── Helper ────────────────────────────────────────────────────────────────

    /// Build a minimal Extended CONNECT request for `connect-udp`.
    fn connect_udp_request(path: &str) -> Request<()> {
        Request::builder()
            .method("CONNECT")
            .uri(path)
            .header("x-protocol", "connect-udp")
            .body(())
            .unwrap()
    }

    // =========================================================================
    // § Handshake validation tests
    // =========================================================================

    #[test]
    fn handshake_valid_domain_host() {
        let req = connect_udp_request(
            "/.well-known/masque/udp/example.com/443/",
        );
        let (host, port) = parse_connect_udp_target(&req).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn handshake_valid_ipv4_host() {
        let req = connect_udp_request(
            "/.well-known/masque/udp/192.0.2.1/53/",
        );
        let (host, port) = parse_connect_udp_target(&req).unwrap();
        assert_eq!(host, "192.0.2.1");
        assert_eq!(port, 53);
    }

    #[test]
    fn handshake_valid_percent_encoded_ipv6() {
        // IPv6 literals in URI paths are percent-encoded per RFC 9298 §3.1.
        // "[::1]" → "%5B%3A%3A1%5D"
        let req = connect_udp_request(
            "/.well-known/masque/udp/%5B%3A%3A1%5D/8080/",
        );
        let (host, port) = parse_connect_udp_target(&req).unwrap();
        assert_eq!(host, "[::1]");
        assert_eq!(port, 8080);
    }

    #[test]
    fn handshake_wrong_method_rejected() {
        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/masque/udp/example.com/443/")
            .header("x-protocol", "connect-udp")
            .body(())
            .unwrap();
        let err = parse_connect_udp_target(&req).unwrap_err();
        assert!(matches!(err, SessionError::InvalidHandshake { .. }));
        assert!(err.to_string().contains(":method"));
    }

    #[test]
    fn handshake_wrong_protocol_rejected() {
        let req = Request::builder()
            .method("CONNECT")
            .uri("/.well-known/masque/udp/example.com/443/")
            .header("x-protocol", "websocket") // wrong protocol
            .body(())
            .unwrap();
        let err = parse_connect_udp_target(&req).unwrap_err();
        assert!(matches!(err, SessionError::InvalidHandshake { .. }));
        assert!(err.to_string().contains("connect-udp"));
    }

    #[test]
    fn handshake_missing_protocol_header_rejected() {
        let req = Request::builder()
            .method("CONNECT")
            .uri("/.well-known/masque/udp/example.com/443/")
            // no x-protocol header
            .body(())
            .unwrap();
        let err = parse_connect_udp_target(&req).unwrap_err();
        assert!(matches!(err, SessionError::InvalidHandshake { .. }));
    }

    #[test]
    fn handshake_wrong_prefix_rejected() {
        let req = connect_udp_request("/proxy/udp/example.com/443/");
        let err = parse_connect_udp_target(&req).unwrap_err();
        assert!(matches!(err, SessionError::ParseError(_)));
    }

    #[test]
    fn handshake_missing_trailing_slash_rejected() {
        let req = connect_udp_request(
            "/.well-known/masque/udp/example.com/443", // no trailing slash
        );
        let err = parse_connect_udp_target(&req).unwrap_err();
        assert!(matches!(err, SessionError::ParseError(_)));
    }

    #[test]
    fn handshake_invalid_port_rejected() {
        let req = connect_udp_request(
            "/.well-known/masque/udp/example.com/notaport/",
        );
        let err = parse_connect_udp_target(&req).unwrap_err();
        assert!(matches!(err, SessionError::ParseError(_)));
    }

    #[test]
    fn handshake_port_zero_rejected() {
        let req = connect_udp_request(
            "/.well-known/masque/udp/example.com/0/",
        );
        let err = parse_connect_udp_target(&req).unwrap_err();
        assert!(matches!(err, SessionError::ParseError(_)));
    }

    #[test]
    fn handshake_port_out_of_range_rejected() {
        // 65536 overflows u16
        let req = connect_udp_request(
            "/.well-known/masque/udp/example.com/65536/",
        );
        let err = parse_connect_udp_target(&req).unwrap_err();
        assert!(matches!(err, SessionError::ParseError(_)));
    }

    #[test]
    fn handshake_empty_host_rejected() {
        let req = connect_udp_request(
            "/.well-known/masque/udp//443/",
        );
        let err = parse_connect_udp_target(&req).unwrap_err();
        // Either ParseError or InvalidHandshake is acceptable.
        assert!(
            matches!(err, SessionError::ParseError(_))
                || matches!(err, SessionError::InvalidHandshake { .. })
        );
    }

    // =========================================================================
    // § ConnectUdpSession forwarding engine tests
    // =========================================================================

    /// Spin up a session between two local UDP sockets and two mpsc channels.
    ///
    /// Returns:
    ///   `(h3_tx, h3_rx_out, target_socket, session_handle)`
    ///
    /// Architecture of the test harness:
    ///
    /// ```
    /// test_h3_tx ──► [h3_rx]  session  [h3_tx] ──► test_h3_rx_out
    ///                          │  ▲
    ///                    UDP   │  │  UDP
    ///                          ▼  │
    ///                      target_socket
    /// ```
    async fn setup_session() -> (
        mpsc::Sender<QuicMessage>,   // inject messages from the H3 side
        mpsc::Receiver<Bytes>,       // read what the session sends to H3
        UdpSocket,                   // the "target" UDP endpoint
        SocketAddr,                  // session's UDP socket address
        tokio::task::JoinHandle<Result<(), SessionError>>,
    ) {
        // Channel: test harness → session (simulates H3 layer)
        let (test_h3_tx, session_h3_rx) = mpsc::channel::<QuicMessage>(32);
        // Channel: session → test harness (simulates H3 layer receiving upstream)
        let (session_h3_tx, test_h3_rx_out) = mpsc::channel::<Bytes>(32);

        // Session's own UDP socket (the proxy socket).
        let session_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let session_udp_addr = session_udp.local_addr().unwrap();

        // "Target" UDP socket (simulates the proxied service).
        let target_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_socket.local_addr().unwrap();

        // Pre-connect the session's UDP socket to the target so `send` works
        // before a source address is learned.
        session_udp.connect(target_addr).await.unwrap();

        let mut session = ConnectUdpSession::new(session_udp, session_h3_rx, session_h3_tx);

        let handle = tokio::spawn(async move { session.run().await });

        (test_h3_tx, test_h3_rx_out, target_socket, session_udp_addr, handle)
    }

    // ── Test A: downstream (QUIC Datagram → UDP) ─────────────────────────────

    #[tokio::test]
    async fn test_datagram_downstream_h3_to_udp() {
        let (h3_tx, _h3_rx_out, target_socket, _session_addr, handle) =
            setup_session().await;

        // Build an HTTP Datagram with Context ID = 0 carrying a DNS-like payload.
        let udp_payload = Bytes::from_static(b"\x00\x01\x00\x00dns query bytes");
        let encoded = encode_http_datagram(CONNECT_UDP_DEFAULT_CONTEXT_ID, &udp_payload);

        h3_tx.send(QuicMessage::Datagram(encoded)).await.unwrap();

        // Expect the UDP payload to arrive at the target socket.
        let mut buf = vec![0u8; 256];
        let n = timeout(Duration::from_secs(2), target_socket.recv(&mut buf))
            .await
            .expect("timed out waiting for UDP packet")
            .expect("recv failed");

        assert_eq!(&buf[..n], udp_payload.as_ref());

        // Tear down.
        drop(h3_tx);
        let _ = timeout(Duration::from_secs(1), handle).await;
    }

    // ── Test B: upstream (UDP → QUIC Datagram) ───────────────────────────────

    #[tokio::test]
    async fn test_datagram_upstream_udp_to_h3() {
        let (h3_tx, mut h3_rx_out, target_socket, session_addr, handle) =
            setup_session().await;

        // Target sends a UDP packet to the session's socket.
        let upstream_data = b"upstream DNS response";
        target_socket
            .send_to(upstream_data, session_addr)
            .await
            .unwrap();

        // Expect an HTTP Datagram to emerge from the session on the H3 channel.
        let encoded = timeout(Duration::from_secs(2), h3_rx_out.recv())
            .await
            .expect("timed out waiting for H3 message")
            .expect("channel closed");

        // Decode and verify.
        let dgram = decode_http_datagram(encoded).unwrap();
        assert_eq!(dgram.context_id, CONNECT_UDP_DEFAULT_CONTEXT_ID);
        assert_eq!(dgram.payload.as_ref(), upstream_data);

        drop(h3_tx);
        let _ = timeout(Duration::from_secs(1), handle).await;
    }

    // ── Test C: full round-trip (H3 → UDP → H3) ──────────────────────────────

    #[tokio::test]
    async fn test_full_roundtrip() {
        let (h3_tx, mut h3_rx_out, target_socket, session_addr, handle) =
            setup_session().await;

        // Step 1: send a downstream datagram.
        let query = Bytes::from_static(b"ping payload");
        let encoded_down = encode_http_datagram(CONNECT_UDP_DEFAULT_CONTEXT_ID, &query);
        h3_tx.send(QuicMessage::Datagram(encoded_down)).await.unwrap();

        // Step 2: target receives and echoes back.
        let mut buf = vec![0u8; 256];
        let (n, src) = timeout(Duration::from_secs(2), target_socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"ping payload");

        let response = b"pong response";
        target_socket.send_to(response, src).await.unwrap();
        // Also send to session addr so the session's socket picks it up.
        target_socket.send_to(response, session_addr).await.unwrap();

        // Step 3: session encapsulates and sends upstream.
        let encoded_up = timeout(Duration::from_secs(2), h3_rx_out.recv())
            .await
            .unwrap()
            .unwrap();
        let dgram = decode_http_datagram(encoded_up).unwrap();
        assert_eq!(dgram.context_id, CONNECT_UDP_DEFAULT_CONTEXT_ID);
        assert_eq!(dgram.payload.as_ref(), response);

        drop(h3_tx);
        let _ = timeout(Duration::from_secs(1), handle).await;
    }

    // ── Test D: Capsule stream path with half-packet assembly ─────────────────

    #[tokio::test]
    async fn test_capsule_stream_halfpacket_assembly() {
        let (h3_tx, _h3_rx_out, target_socket, _session_addr, handle) =
            setup_session().await;

        // Build a DATAGRAM Capsule whose payload is an HTTP Datagram.
        let udp_payload = Bytes::from_static(b"capsule stream payload");
        let http_dgram = encode_http_datagram(CONNECT_UDP_DEFAULT_CONTEXT_ID, &udp_payload);
        let capsule = Capsule {
            capsule_type: CapsuleType::Datagram,
            payload: http_dgram,
        };
        let wire = capsule.to_bytes();

        // Split the wire bytes at an arbitrary mid-point.
        let split = wire.len() / 3;
        let part1 = wire.slice(..split);
        let part2 = wire.slice(split..);

        // Send part 1 — the session must buffer it (no UDP output yet).
        h3_tx.send(QuicMessage::StreamChunk(part1)).await.unwrap();

        // Brief pause to let the session process the first chunk.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // No UDP packet should have arrived at target yet.
        // We verify this by attempting a recv with a very short deadline.
        let mut probe = vec![0u8; 256];
        let nothing = timeout(Duration::from_millis(40), target_socket.recv(&mut probe)).await;
        assert!(
            nothing.is_err(),
            "target should not receive anything from a partial capsule"
        );

        // Send part 2 — now the capsule is complete.
        h3_tx.send(QuicMessage::StreamChunk(part2)).await.unwrap();

        // UDP payload must now arrive at the target.
        let n = timeout(Duration::from_secs(2), target_socket.recv(&mut probe))
            .await
            .expect("timed out waiting for assembled capsule UDP output")
            .unwrap();

        assert_eq!(&probe[..n], udp_payload.as_ref());

        drop(h3_tx);
        let _ = timeout(Duration::from_secs(1), handle).await;
    }

    // ── Test E: multiple capsules in one stream chunk ─────────────────────────

    #[tokio::test]
    async fn test_capsule_multiple_in_one_chunk() {
        let (h3_tx, _h3_rx_out, target_socket, _session_addr, handle) =
            setup_session().await;

        let payloads: &[&[u8]] = &[b"first packet", b"second packet", b"third packet"];
        let mut combined = BytesMut::new();

        for p in payloads {
            let http_dgram =
                encode_http_datagram(CONNECT_UDP_DEFAULT_CONTEXT_ID, &Bytes::copy_from_slice(p));
            let cap = Capsule {
                capsule_type: CapsuleType::Datagram,
                payload: http_dgram,
            };
            combined.extend_from_slice(&cap.to_bytes());
        }

        // Send all three capsules in one stream chunk.
        h3_tx
            .send(QuicMessage::StreamChunk(combined.freeze()))
            .await
            .unwrap();

        // All three UDP payloads must arrive at the target.
        let mut buf = vec![0u8; 256];
        for expected in payloads {
            let n = timeout(Duration::from_secs(2), target_socket.recv(&mut buf))
                .await
                .expect("timed out waiting for UDP packet")
                .unwrap();
            assert_eq!(&buf[..n], *expected);
        }

        drop(h3_tx);
        let _ = timeout(Duration::from_secs(1), handle).await;
    }

    // ── Test F: unknown capsule type is silently skipped ──────────────────────

    #[tokio::test]
    async fn test_unknown_capsule_skipped_then_known_forwarded() {
        use crate::protocol::encode_varint;

        let (h3_tx, _h3_rx_out, target_socket, _session_addr, handle) =
            setup_session().await;

        let mut wire = BytesMut::new();

        // 1. Unknown capsule type 0xBEEF with 5 bytes of opaque data.
        encode_varint(&mut wire, 0xBEEF_u64);
        encode_varint(&mut wire, 5u64);
        wire.extend_from_slice(b"junkx");

        // 2. Valid DATAGRAM capsule after the unknown one.
        let udp_payload = Bytes::from_static(b"real payload after unknown");
        let http_dgram = encode_http_datagram(CONNECT_UDP_DEFAULT_CONTEXT_ID, &udp_payload);
        let cap = Capsule {
            capsule_type: CapsuleType::Datagram,
            payload: http_dgram,
        };
        wire.extend_from_slice(&cap.to_bytes());

        h3_tx
            .send(QuicMessage::StreamChunk(wire.freeze()))
            .await
            .unwrap();

        // Only the real payload must arrive; the unknown capsule produces nothing.
        let mut buf = vec![0u8; 256];
        let n = timeout(Duration::from_secs(2), target_socket.recv(&mut buf))
            .await
            .expect("timed out")
            .unwrap();

        assert_eq!(&buf[..n], udp_payload.as_ref());

        drop(h3_tx);
        let _ = timeout(Duration::from_secs(1), handle).await;
    }

    // ── Test G: non-zero context ID datagram is silently ignored ──────────────

    #[tokio::test]
    async fn test_non_zero_context_id_datagram_ignored() {
        let (h3_tx, _h3_rx_out, target_socket, _session_addr, handle) =
            setup_session().await;

        // Context ID 42 — should be ignored.
        let ignored_payload = Bytes::from_static(b"should be dropped");
        let encoded_ignored = encode_http_datagram(42, &ignored_payload);

        // Context ID 0 — should be forwarded.
        let real_payload = Bytes::from_static(b"should arrive");
        let encoded_real =
            encode_http_datagram(CONNECT_UDP_DEFAULT_CONTEXT_ID, &real_payload);

        h3_tx
            .send(QuicMessage::Datagram(encoded_ignored))
            .await
            .unwrap();
        h3_tx
            .send(QuicMessage::Datagram(encoded_real))
            .await
            .unwrap();

        let mut buf = vec![0u8; 256];
        let n = timeout(Duration::from_secs(2), target_socket.recv(&mut buf))
            .await
            .expect("timed out")
            .unwrap();

        // Must be the real payload, not the ignored one.
        assert_eq!(&buf[..n], b"should arrive");

        drop(h3_tx);
        let _ = timeout(Duration::from_secs(1), handle).await;
    }

    // ── Test H: session terminates cleanly on QuicMessage::Closed ────────────

    #[tokio::test]
    async fn test_session_closes_on_quic_closed_message() {
        let (h3_tx, _h3_rx_out, _target, _addr, handle) = setup_session().await;

        h3_tx.send(QuicMessage::Closed).await.unwrap();

        let result = timeout(Duration::from_secs(2), handle)
            .await
            .expect("session did not terminate within deadline")
            .expect("task panicked");

        assert!(
            result.is_ok(),
            "clean close should not return an error: {result:?}"
        );
    }

    // ── Test I: session terminates cleanly when H3 channel is dropped ─────────

    #[tokio::test]
    async fn test_session_closes_when_channel_dropped() {
        let (h3_tx, _h3_rx_out, _target, _addr, handle) = setup_session().await;

        drop(h3_tx); // simulate H3 stream / connection being torn down

        let result = timeout(Duration::from_secs(2), handle)
            .await
            .expect("session did not terminate within deadline")
            .expect("task panicked");

        assert!(result.is_ok());
    }
}
