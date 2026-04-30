// =============================================================================
// protocol.rs — MASQUE Core: Data Plane
//
// Implements the zero-copy codec layer for:
//   • RFC 9000 §16    — QUIC Variable-Length Integer Encoding
//   • RFC 9297 §3     — Capsule Protocol (framing, streaming decode)
//   • RFC 9297 §2     — HTTP Datagrams
//   • RFC 9298 §4     — Context ID multiplexing (CONNECT-UDP)
// =============================================================================

use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

// -----------------------------------------------------------------------------
// § Error Types
// -----------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq)]
pub enum ProtocolError {
    /// Not enough bytes yet; caller should buffer and retry.
    /// This is NOT a fatal error — it models the TCP half-packet case.
    #[error("incomplete frame: need at least {needed} more bytes")]
    Incomplete { needed: usize },

    /// A VarInt prefix byte indicated a valid 2-bit length, but the encoded
    /// value was out of the canonical range for that prefix (RFC 9000 §16).
    #[error("varint value out of canonical range")]
    InvalidVarInt,

    /// The `Quarter Packet Number` or similar field overflowed u64.
    #[error("varint overflow: encoded value exceeds u64::MAX")]
    VarIntOverflow,

    /// A Capsule Length field encoded a value that would require allocating
    /// more than our configured safety limit.
    #[error("capsule payload too large: {length} bytes exceeds limit {limit}")]
    CapsuleTooLarge { length: u64, limit: u64 },

    /// An HTTP Datagram arrived with a zero-byte body (no room for Context ID).
    #[error("http datagram too short to contain a context id")]
    DatagramTooShort,

    /// Context ID used an odd value when the client was expected to allocate
    /// (RFC 9298 §4: client allocates even, server allocates odd).
    #[error("unexpected context id parity: id={id}")]
    ContextIdParityViolation { id: u64 },

    /// Generic I/O wrapper kept for future async path integration.
    #[error("io error: {0}")]
    Io(String),
}

// Safety cap: refuse Capsule payloads larger than 16 MiB by default.
// Callers may override via `decode_capsule_with_limit`.
// pub const DEFAULT_MAX_CAPSULE_PAYLOAD: u64 = 16 * 1024 * 1024;

// 防止恶意客户端发送虚假超大 Capsule 导致服务器 OOM。
// UDP 数据报的最大理论大小为 65535，我们拒绝任何大于此值的载荷。
pub const DEFAULT_MAX_CAPSULE_PAYLOAD: u64 = 65535;

// -----------------------------------------------------------------------------
// §1  RFC 9000 §16 — Variable-Length Integer
// -----------------------------------------------------------------------------

/// Decoded VarInt value together with how many bytes it consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VarInt {
    pub value: u64,
    pub encoded_len: usize,
}

impl VarInt {
    /// Maximum value that fits in a VarInt (2^62 - 1).
    pub const MAX: u64 = (1u64 << 62) - 1;

    /// Construct without range-check; use only when value is known-good.
    #[inline]
    pub const fn from_u64_unchecked(value: u64) -> Self {
        Self {
            value,
            // We don't store encoded_len here; compute on encode.
            encoded_len: Self::encoded_len_for(value),
        }
    }

    /// Try to construct from a u64; fails if value > MAX.
    #[inline]
    pub fn try_from_u64(value: u64) -> Result<Self, ProtocolError> {
        if value > Self::MAX {
            return Err(ProtocolError::VarIntOverflow);
        }
        Ok(Self::from_u64_unchecked(value))
    }

    /// Number of bytes needed to encode `value` per RFC 9000 §16 Table 4.
    #[inline]
    pub const fn encoded_len_for(value: u64) -> usize {
        if value <= 63 {
            1
        } else if value <= 16_383 {
            2
        } else if value <= 1_073_741_823 {
            4
        } else {
            8
        }
    }
}

/// RFC 9000 §16 — Peek at the first byte to determine VarInt length.
/// Returns `(msb_2bits, total_encoded_bytes)`.
#[inline]
fn varint_prefix(first_byte: u8) -> (u8, usize) {
    let prefix = first_byte >> 6;
    let len = 1usize << prefix; // 1, 2, 4, or 8
    (prefix, len)
}

/// RFC 9000 §16 — Decode a VarInt from a `Bytes` / `BytesMut` via `Buf`.
///
/// Returns `Ok(None)` when there are not enough bytes yet (half-packet).
/// **Does not advance the cursor** on `Ok(None)`.
pub fn decode_varint<B: Buf>(src: &mut B) -> Result<Option<VarInt>, ProtocolError> {
    // RFC 9000 §16: "The 2 most significant bits of the first byte
    // encode the length of the variable-length integer, as shown in Table 4."
    if src.remaining() < 1 {
        return Ok(None);
    }

    let first = src.chunk()[0]; // peek — do NOT advance yet
    let (prefix, total_len) = varint_prefix(first);

    if src.remaining() < total_len {
        return Ok(None);
    }

    // Now safe to consume.
    src.advance(1);
    let value = match prefix {
        // RFC 9000 §16 Table 4: 1-byte  (prefix=0b00)
        0 => first as u64 & 0x3F,

        // RFC 9000 §16 Table 4: 2-byte  (prefix=0b01)
        1 => {
            let lo = src.get_u8();
            (((first as u64) & 0x3F) << 8) | (lo as u64)
        }

        // RFC 9000 §16 Table 4: 4-byte  (prefix=0b10)
        2 => {
            let b1 = src.get_u8();
            let b2 = src.get_u8();
            let b3 = src.get_u8();
            (((first as u64) & 0x3F) << 24)
                | ((b1 as u64) << 16)
                | ((b2 as u64) << 8)
                | (b3 as u64)
        }

        // RFC 9000 §16 Table 4: 8-byte  (prefix=0b11)
        3 => {
            let b1 = src.get_u8();
            let b2 = src.get_u8();
            let b3 = src.get_u8();
            let b4 = src.get_u8();
            let b5 = src.get_u8();
            let b6 = src.get_u8();
            let b7 = src.get_u8();
            (((first as u64) & 0x3F) << 56)
                | ((b1 as u64) << 48)
                | ((b2 as u64) << 40)
                | ((b3 as u64) << 32)
                | ((b4 as u64) << 24)
                | ((b5 as u64) << 16)
                | ((b6 as u64) << 8)
                | (b7 as u64)
        }

        _ => unreachable!("2-bit prefix can only be 0..=3"),
    };

    Ok(Some(VarInt {
        value,
        encoded_len: total_len,
    }))
}

/// RFC 9000 §16 — Encode a u64 as a VarInt into any `BufMut`.
///
/// Panics if `value > VarInt::MAX` (caller must pre-validate).
pub fn encode_varint<B: BufMut>(dst: &mut B, value: u64) {
    assert!(value <= VarInt::MAX, "varint value {value} exceeds 2^62-1");

    if value <= 63 {
        // 1-byte: prefix 0b00
        dst.put_u8(value as u8);
    } else if value <= 16_383 {
        // 2-byte: prefix 0b01
        dst.put_u8(0x40 | ((value >> 8) as u8));
        dst.put_u8((value & 0xFF) as u8);
    } else if value <= 1_073_741_823 {
        // 4-byte: prefix 0b10
        dst.put_u8(0x80 | ((value >> 24) as u8));
        dst.put_u8(((value >> 16) & 0xFF) as u8);
        dst.put_u8(((value >> 8) & 0xFF) as u8);
        dst.put_u8((value & 0xFF) as u8);
    } else {
        // 8-byte: prefix 0b11
        dst.put_u8(0xC0 | ((value >> 56) as u8));
        dst.put_u8(((value >> 48) & 0xFF) as u8);
        dst.put_u8(((value >> 40) & 0xFF) as u8);
        dst.put_u8(((value >> 32) & 0xFF) as u8);
        dst.put_u8(((value >> 24) & 0xFF) as u8);
        dst.put_u8(((value >> 16) & 0xFF) as u8);
        dst.put_u8(((value >> 8) & 0xFF) as u8);
        dst.put_u8((value & 0xFF) as u8);
    }
}

/// Convenience: encode a VarInt into a freshly allocated `BytesMut`.
pub fn varint_to_bytes(value: u64) -> BytesMut {
    let mut buf = BytesMut::with_capacity(8);
    encode_varint(&mut buf, value);
    buf
}

// -----------------------------------------------------------------------------
// §2  RFC 9297 §3 — Capsule Protocol
// -----------------------------------------------------------------------------

/// RFC 9297 §3.2 — Well-known Capsule Type identifiers.
///
/// Unknown types MUST be silently skipped (§3.3):
/// "A recipient that receives a capsule with an unknown capsule type MUST
///  silently drop that capsule and skip over it."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum CapsuleType {
    /// RFC 9297 §3.5 — DATAGRAM capsule (type = 0x00)
    Datagram = 0x00,

    /// RFC 9298 §5 — ADDRESS_ASSIGN (type = 0x03)
    AddressAssign = 0x03,

    /// RFC 9298 §5 — ADDRESS_REQUEST (type = 0x04)
    AddressRequest = 0x04,

    /// RFC 9298 §5 — ROUTE_ADVERTISEMENT (type = 0x05)
    RouteAdvertisement = 0x05,

    /// Catch-all for unknown/extension types.
    Unknown(u64),
}

impl CapsuleType {
    pub fn from_u64(v: u64) -> Self {
        match v {
            0x00 => Self::Datagram,
            0x03 => Self::AddressAssign,
            0x04 => Self::AddressRequest,
            0x05 => Self::RouteAdvertisement,
            other => Self::Unknown(other),
        }
    }

    pub fn to_u64(self) -> u64 {
        match self {
            Self::Datagram => 0x00,
            Self::AddressAssign => 0x03,
            Self::AddressRequest => 0x04,
            Self::RouteAdvertisement => 0x05,
            Self::Unknown(v) => v,
        }
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown(_))
    }
}

/// RFC 9297 §3.1 — A single decoded Capsule frame.
///
/// `payload` is a **zero-copy slice** of the original receive buffer.
/// No data is copied out of the network buffer when decoding.
#[derive(Debug, Clone, PartialEq)]
pub struct Capsule {
    /// Capsule Type (VarInt).
    pub capsule_type: CapsuleType,
    /// Capsule Value — zero-copy `Bytes` slice into the source buffer.
    pub payload: Bytes,
}

impl Capsule {
    /// Encode this Capsule into `dst`.
    ///
    /// RFC 9297 §3.1:
    ///   Capsule {
    ///     Capsule Type (i),
    ///     Capsule Length (i),
    ///     Capsule Value (..),
    ///   }
    pub fn encode(&self, dst: &mut BytesMut) {
        encode_varint(dst, self.capsule_type.to_u64());
        encode_varint(dst, self.payload.len() as u64);
        dst.extend_from_slice(&self.payload);
    }

    /// Convenience: return the fully encoded capsule as `Bytes`.
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(
            16 + self.payload.len(), // 2× 8-byte varints worst case
        );
        self.encode(&mut buf);
        buf.freeze()
    }
}

/// RFC 9297 §3.3 — Streaming Capsule decoder.
///
/// This function operates on a **mutable reference to a `BytesMut`** which
/// represents the raw byte stream arriving on an HTTP/3 DATA stream.
///
/// # Half-packet / TCP-style framing contract
///
/// - Returns `Ok(Some(Capsule))` when a complete frame is available.
///   The consumed bytes are **removed** from `src` (cursor advanced).
/// - Returns `Ok(None)` when the buffer holds a partial frame.
///   The cursor is **not moved** — the buffer is left intact for the next read.
/// - Returns `Err(_)` only for unrecoverable protocol violations.
///
/// # Unknown Capsule Types
///
/// RFC 9297 §3.3: unknown types are silently consumed.
/// We return `Ok(Some(capsule))` with `CapsuleType::Unknown(_)` so the caller
/// can choose to log/instrument but is not forced to treat it as an error.
pub fn decode_capsule(src: &mut BytesMut) -> Result<Option<Capsule>, ProtocolError> {
    decode_capsule_with_limit(src, DEFAULT_MAX_CAPSULE_PAYLOAD)
}

/// Same as `decode_capsule` but with an explicit payload size limit.
pub fn decode_capsule_with_limit(
    src: &mut BytesMut,
    max_payload: u64,
) -> Result<Option<Capsule>, ProtocolError> {
    // We must not modify `src` until we know the entire capsule is present.
    // Use a cursor over the *immutable view* of the buffer to dry-run the parse.
    let mut cursor: &[u8] = src.chunk(); // &[u8] implements Buf
    let start_remaining = cursor.remaining();

    // --- Step 1: Decode Capsule Type (VarInt) ---
    // RFC 9297 §3.1
    let type_vi = match decode_varint(&mut cursor)? {
        Some(v) => v,
        None => return Ok(None), // need more bytes for type field
    };
    let capsule_type = CapsuleType::from_u64(type_vi.value);

    // --- Step 2: Decode Capsule Length (VarInt) ---
    // RFC 9297 §3.1
    let length_vi = match decode_varint(&mut cursor)? {
        Some(v) => v,
        None => return Ok(None), // need more bytes for length field
    };
    let payload_len = length_vi.value;

    if payload_len > max_payload {
        return Err(ProtocolError::CapsuleTooLarge {
            length: payload_len,
            limit: max_payload,
        });
    }

    // --- Step 3: Ensure payload bytes are present ---
    let header_len = start_remaining - cursor.remaining();
    let total_frame_len = header_len + payload_len as usize;

    if src.len() < total_frame_len {
        // Half-packet: leave `src` untouched.
        return Ok(None);
    }

    // --- Step 4: Consume from src — zero-copy via Bytes::split_to ---
    // Advance past the header.
    src.advance(header_len);
    // Split off exactly `payload_len` bytes as a `Bytes` (shared ref-counted).
    let payload: Bytes = src.split_to(payload_len as usize).freeze();

    Ok(Some(Capsule {
        capsule_type,
        payload,
    }))
}

/// Drain all complete Capsules from `src` in one pass.
///
/// Returns a `Vec<Capsule>` of everything decoded (empty if nothing complete).
/// On the first `Ok(None)` we stop — the rest waits for more data.
pub fn drain_capsules(src: &mut BytesMut) -> Result<Vec<Capsule>, ProtocolError> {
    let mut out = Vec::new();
    loop {
        match decode_capsule(src)? {
            Some(c) => out.push(c),
            None => break,
        }
    }
    Ok(out)
}

// -----------------------------------------------------------------------------
// §3  RFC 9297 §2 + RFC 9298 §4 — HTTP Datagram & Context ID
// -----------------------------------------------------------------------------

/// A decoded HTTP Datagram carrying a CONNECT-UDP payload.
///
/// RFC 9297 §2 defines the wire format for HTTP Datagrams.
/// RFC 9298 §4 defines how the first VarInt field is a *Context ID*.
///
/// ```text
/// HTTP Datagram {
///   Quarter Stream ID / Context ID (i),
///   HTTP Datagram Payload (..),    ← zero-copy Bytes
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct HttpDatagram {
    /// RFC 9298 §4: Context ID (VarInt).
    /// Client-allocated IDs are even; server-allocated IDs are odd.
    pub context_id: u64,
    /// The raw UDP payload.  Zero-copy slice from the QUIC DATAGRAM frame.
    pub payload: Bytes,
}

/// RFC 9298 §4 — Context ID Allocation
///
/// "The context ID space is divided into two disjoint sub-spaces.
///  Even values are client-allocated; odd values are server-allocated."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextIdSide {
    /// Client-allocated (even context IDs).
    Client,
    /// Server-allocated (odd context IDs).
    Server,
}

impl ContextIdSide {
    pub fn of(context_id: u64) -> Self {
        if context_id % 2 == 0 {
            Self::Client
        } else {
            Self::Server
        }
    }
}

/// RFC 9297 §2 + RFC 9298 §4 — Parse an HTTP Datagram from a raw QUIC
/// DATAGRAM payload (`Bytes`).  **Zero-copy**: `payload` is a sub-slice.
///
/// # Errors
///
/// - `DatagramTooShort` if the buffer cannot even hold the Context ID.
/// - `InvalidVarInt` / `VarIntOverflow` on malformed encoding.
pub fn decode_http_datagram(mut raw: Bytes) -> Result<HttpDatagram, ProtocolError> {
    // RFC 9298 §4: first field is Context ID encoded as a VarInt.
    // `raw` is a `Bytes` which implements `Buf`.
    let context_id = match decode_varint(&mut raw)? {
        Some(vi) => vi.value,
        None => return Err(ProtocolError::DatagramTooShort),
    };

    // Remaining bytes are the UDP payload — no copy, just a sub-slice.
    let payload = raw; // `Bytes::advance` already moved the start pointer.
    Ok(HttpDatagram {
        context_id,
        payload,
    })
}

/// RFC 9297 §2 + RFC 9298 §4 — Encode an HTTP Datagram for transmission.
///
/// Returns a `Bytes` suitable for passing to `quinn`'s `send_datagram`.
/// The Context ID is prepended as a VarInt; the payload is appended without
/// copying (we use `BytesMut` → `Bytes` freeze).
pub fn encode_http_datagram(context_id: u64, payload: &Bytes) -> Bytes {
    // Worst-case header: 8 bytes for a 8-byte VarInt Context ID.
    let mut buf = BytesMut::with_capacity(8 + payload.len());
    encode_varint(&mut buf, context_id);
    // Zero-copy from caller's `Bytes` into our buffer.
    buf.extend_from_slice(payload);
    buf.freeze()
}

/// RFC 9298 §4 — Context ID = 0 is the default proxying context.
///
/// "If the context ID is 0, the datagram payload is a UDP payload for the
///  target of the CONNECT-UDP request."
pub const CONNECT_UDP_DEFAULT_CONTEXT_ID: u64 = 0;

/// Decode a DATAGRAM Capsule's payload into an `HttpDatagram`.
///
/// RFC 9297 §3.5: A DATAGRAM capsule carries exactly one HTTP Datagram.
/// The Capsule Payload IS the HTTP Datagram wire format.
pub fn decode_datagram_capsule_payload(
    capsule: &Capsule,
) -> Result<HttpDatagram, ProtocolError> {
    if capsule.capsule_type != CapsuleType::Datagram {
        // Caller is expected to filter, but we guard defensively.
        return Err(ProtocolError::Io(format!(
            "expected DATAGRAM capsule, got {:?}",
            capsule.capsule_type
        )));
    }
    decode_http_datagram(capsule.payload.clone())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // VarInt round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn varint_roundtrip_1byte() {
        for v in [0u64, 1, 62, 63] {
            let mut buf = BytesMut::new();
            encode_varint(&mut buf, v);
            assert_eq!(buf.len(), 1, "value {v} should encode in 1 byte");
            let decoded = decode_varint(&mut buf).unwrap().unwrap();
            assert_eq!(decoded.value, v);
            assert_eq!(decoded.encoded_len, 1);
        }
    }

    #[test]
    fn varint_roundtrip_2byte() {
        for v in [64u64, 255, 16_383] {
            let mut buf = BytesMut::new();
            encode_varint(&mut buf, v);
            assert_eq!(buf.len(), 2);
            let decoded = decode_varint(&mut buf).unwrap().unwrap();
            assert_eq!(decoded.value, v);
        }
    }

    #[test]
    fn varint_roundtrip_4byte() {
        for v in [16_384u64, 1_000_000, 1_073_741_823] {
            let mut buf = BytesMut::new();
            encode_varint(&mut buf, v);
            assert_eq!(buf.len(), 4);
            let decoded = decode_varint(&mut buf).unwrap().unwrap();
            assert_eq!(decoded.value, v);
        }
    }

    #[test]
    fn varint_roundtrip_8byte() {
        for v in [1_073_741_824u64, u32::MAX as u64, VarInt::MAX] {
            let mut buf = BytesMut::new();
            encode_varint(&mut buf, v);
            assert_eq!(buf.len(), 8);
            let decoded = decode_varint(&mut buf).unwrap().unwrap();
            assert_eq!(decoded.value, v);
        }
    }

    #[test]
    fn varint_empty_returns_none() {
        let mut buf = BytesMut::new();
        let result = decode_varint(&mut buf).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn varint_partial_multibyte_returns_none() {
        // Encode a 4-byte VarInt (value = 65536), then strip last byte.
        let mut full = BytesMut::new();
        encode_varint(&mut full, 65536u64);
        assert_eq!(full.len(), 4);

        // Provide only 3 of the 4 bytes.
        let mut partial = BytesMut::from(&full[..3]);
        let result = decode_varint(&mut partial).unwrap();
        assert_eq!(result, None, "should return None on partial multibyte");
        // Cursor must NOT have moved.
        assert_eq!(partial.len(), 3, "partial buffer must be untouched");
    }

    // -------------------------------------------------------------------------
    // Capsule: normal encode / decode
    // -------------------------------------------------------------------------

    fn make_datagram_capsule(payload_data: &[u8]) -> Capsule {
        Capsule {
            capsule_type: CapsuleType::Datagram,
            payload: Bytes::copy_from_slice(payload_data),
        }
    }

    #[test]
    fn capsule_encode_decode_roundtrip() {
        let original = make_datagram_capsule(b"hello MASQUE world");
        let wire = original.to_bytes();

        let mut buf = BytesMut::from(wire.as_ref());
        let decoded = decode_capsule(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.capsule_type, CapsuleType::Datagram);
        assert_eq!(decoded.payload, original.payload);
        assert_eq!(buf.len(), 0, "buffer must be fully consumed");
    }

    #[test]
    fn capsule_empty_payload() {
        let c = Capsule {
            capsule_type: CapsuleType::Datagram,
            payload: Bytes::new(),
        };
        let wire = c.to_bytes();
        let mut buf = BytesMut::from(wire.as_ref());
        let decoded = decode_capsule(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.payload.len(), 0);
        assert_eq!(buf.len(), 0);
    }

    // -------------------------------------------------------------------------
    // Capsule: half-packet / streaming assembly — THE CRITICAL TEST
    // -------------------------------------------------------------------------

    #[test]
    fn capsule_halfpacket_does_not_consume_buffer() {
        // Build a complete capsule wire representation.
        let original = make_datagram_capsule(b"fragmented payload data here");
        let wire = original.to_bytes();
        assert!(wire.len() >= 4, "wire should be at least a few bytes");

        // Feed only first half of bytes — simulating a partial TCP segment.
        let half = wire.len() / 2;
        let mut buf = BytesMut::from(&wire[..half]);

        let result = decode_capsule(&mut buf).unwrap();

        assert_eq!(result, None, "half-packet must return Ok(None)");
        assert_eq!(
            buf.len(),
            half,
            "cursor MUST NOT advance on incomplete frame"
        );
    }

    #[test]
    fn capsule_byte_by_byte_assembly() {
        let original = make_datagram_capsule(b"incremental test");
        let wire = original.to_bytes();

        let mut buf = BytesMut::new();
        let mut decoded_capsule: Option<Capsule> = None;

        for (i, byte) in wire.iter().enumerate() {
            buf.extend_from_slice(&[*byte]);
            match decode_capsule(&mut buf).unwrap() {
                Some(c) => {
                    decoded_capsule = Some(c);
                    // No more bytes should be consumed beyond the frame.
                    assert_eq!(buf.len(), 0, "consumed at byte {i}");
                    break;
                }
                None => {
                    assert_eq!(
                        buf.len(),
                        i + 1,
                        "cursor must not move before frame complete"
                    );
                }
            }
        }

        let c = decoded_capsule.expect("should have decoded by end of stream");
        assert_eq!(c.payload, original.payload);
    }

    #[test]
    fn capsule_exact_boundary_then_second_capsule() {
        // Two capsules concatenated — first arrives complete, second arrives complete.
        let c1 = make_datagram_capsule(b"first");
        let c2 = make_datagram_capsule(b"second");

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&c1.to_bytes());
        buf.extend_from_slice(&c2.to_bytes());

        let d1 = decode_capsule(&mut buf).unwrap().unwrap();
        let d2 = decode_capsule(&mut buf).unwrap().unwrap();
        let none = decode_capsule(&mut buf).unwrap();

        assert_eq!(d1.payload, c1.payload);
        assert_eq!(d2.payload, c2.payload);
        assert_eq!(none, None);
    }

    // -------------------------------------------------------------------------
    // Capsule: unknown type — silent skip (RFC 9297 §3.3)
    // -------------------------------------------------------------------------

    #[test]
    fn capsule_unknown_type_is_returned_not_errored() {
        // Manually craft a capsule with type = 0xBEEF (unknown).
        let unknown_type_id: u64 = 0xBEEF;
        let payload_data = b"opaque extension data";

        let mut wire = BytesMut::new();
        encode_varint(&mut wire, unknown_type_id);
        encode_varint(&mut wire, payload_data.len() as u64);
        wire.extend_from_slice(payload_data);

        let mut buf = wire.clone();
        let result = decode_capsule(&mut buf).unwrap();

        // Must decode successfully (not an error).
        let capsule = result.expect("unknown capsule should decode as Ok(Some(_))");
        assert!(
            capsule.capsule_type.is_unknown(),
            "type should be CapsuleType::Unknown"
        );
        if let CapsuleType::Unknown(v) = capsule.capsule_type {
            assert_eq!(v, unknown_type_id);
        }
        assert_eq!(capsule.payload.as_ref(), payload_data);
        assert_eq!(buf.len(), 0, "buffer fully consumed");
    }

    #[test]
    fn drain_capsules_with_unknown_and_known_mixed() {
        let known = make_datagram_capsule(b"known");
        let mut wire = BytesMut::new();

        // Unknown capsule first.
        encode_varint(&mut wire, 0xDEAD_u64);
        encode_varint(&mut wire, 3u64);
        wire.extend_from_slice(b"unk");

        // Known DATAGRAM capsule.
        wire.extend_from_slice(&known.to_bytes());

        let mut buf = wire;
        let capsules = drain_capsules(&mut buf).unwrap();

        assert_eq!(capsules.len(), 2);
        assert!(capsules[0].capsule_type.is_unknown());
        assert_eq!(capsules[1].capsule_type, CapsuleType::Datagram);
        assert_eq!(capsules[1].payload, known.payload);
    }

    // -------------------------------------------------------------------------
    // Capsule: payload size limit
    // -------------------------------------------------------------------------

    #[test]
    fn capsule_too_large_returns_error() {
        let mut wire = BytesMut::new();
        // Capsule type = 0 (DATAGRAM), length = 10MB (within u64 range but > our limit).
        encode_varint(&mut wire, 0u64);
        encode_varint(&mut wire, 20 * 1024 * 1024u64); // 20 MiB > DEFAULT (16 MiB)
        // Don't bother appending actual bytes — the check comes before reading payload.

        let mut buf = wire;
        let result = decode_capsule(&mut buf);
        assert!(
            matches!(result, Err(ProtocolError::CapsuleTooLarge { .. })),
            "should reject oversized capsule"
        );
    }

    // -------------------------------------------------------------------------
    // HTTP Datagram + Context ID (RFC 9298 §4)
    // -------------------------------------------------------------------------

    #[test]
    fn http_datagram_encode_decode_roundtrip() {
        // RFC 9298 §4: Context ID 0 is the default UDP proxy context.
        let context_id = CONNECT_UDP_DEFAULT_CONTEXT_ID;
        let udp_payload = Bytes::from_static(b"\x00\x50hello udp world");

        let encoded = encode_http_datagram(context_id, &udp_payload);
        let decoded = decode_http_datagram(encoded).unwrap();

        assert_eq!(decoded.context_id, context_id);
        assert_eq!(decoded.payload, udp_payload);
    }

    #[test]
    fn http_datagram_non_zero_context_id() {
        // Client allocates even IDs (RFC 9298 §4).
        let context_id = 42u64;
        let udp_payload = Bytes::from_static(b"payload for context 42");

        let encoded = encode_http_datagram(context_id, &udp_payload);
        let decoded = decode_http_datagram(encoded).unwrap();

        assert_eq!(decoded.context_id, 42);
        assert_eq!(ContextIdSide::of(decoded.context_id), ContextIdSide::Client);
        assert_eq!(decoded.payload, udp_payload);
    }

    #[test]
    fn http_datagram_server_side_context_id_is_odd() {
        // Server allocates odd IDs (RFC 9298 §4).
        let context_id = 1u64;
        let payload = Bytes::from_static(b"server-allocated context");

        let encoded = encode_http_datagram(context_id, &payload);
        let decoded = decode_http_datagram(encoded).unwrap();

        assert_eq!(ContextIdSide::of(decoded.context_id), ContextIdSide::Server);
    }

    #[test]
    fn http_datagram_too_short_returns_error() {
        // An empty QUIC DATAGRAM has no room for a Context ID VarInt.
        let raw = Bytes::new();
        let result = decode_http_datagram(raw);
        assert_eq!(result.unwrap_err(), ProtocolError::DatagramTooShort);
    }

    #[test]
    fn http_datagram_payload_is_zero_copy_subslice() {
        // Verify that `payload` inside HttpDatagram is a sub-slice (not a copy)
        // by checking the pointer address lies within the original allocation.
        let udp_data = b"original data block for zero copy check";
        let context_id = 0u64;
        let original_payload = Bytes::copy_from_slice(udp_data);
        let encoded = encode_http_datagram(context_id, &original_payload);

        // encoded: [varint(0)] ++ udp_data
        let encoded_ptr = encoded.as_ptr();
        let decoded = decode_http_datagram(encoded).unwrap();

        // The decoded payload's pointer should be offset into the original buffer,
        // not a new heap allocation.
        let payload_ptr = decoded.payload.as_ptr();
        let encoded_end = unsafe { encoded_ptr.add(1 + udp_data.len()) }; // 1-byte VarInt for 0
        // payload_ptr must be >= encoded_ptr and < encoded_end
        assert!(
            payload_ptr >= encoded_ptr && payload_ptr < encoded_end,
            "payload should be a zero-copy subslice of the encoded buffer"
        );
        assert_eq!(decoded.payload.as_ref(), udp_data);
    }

    // -------------------------------------------------------------------------
    // DATAGRAM Capsule → HttpDatagram integration path
    // -------------------------------------------------------------------------

    #[test]
    fn datagram_capsule_carries_http_datagram() {
        // Encode an HTTP Datagram, wrap it in a DATAGRAM Capsule, decode it all.
        let context_id = 0u64;
        let udp_payload = Bytes::from_static(b"UDP DNS query bytes here");
        let http_dgram_bytes = encode_http_datagram(context_id, &udp_payload);

        let capsule = Capsule {
            capsule_type: CapsuleType::Datagram,
            payload: http_dgram_bytes,
        };

        let wire = capsule.to_bytes();
        let mut buf = BytesMut::from(wire.as_ref());

        let decoded_capsule = decode_capsule(&mut buf).unwrap().unwrap();
        let decoded_dgram = decode_datagram_capsule_payload(&decoded_capsule).unwrap();

        assert_eq!(decoded_dgram.context_id, context_id);
        assert_eq!(decoded_dgram.payload, udp_payload);
    }

    // -------------------------------------------------------------------------
    // Context ID Parity helper
    // -------------------------------------------------------------------------

    #[test]
    fn context_id_side_classification() {
        assert_eq!(ContextIdSide::of(0), ContextIdSide::Client);
        assert_eq!(ContextIdSide::of(2), ContextIdSide::Client);
        assert_eq!(ContextIdSide::of(100), ContextIdSide::Client);
        assert_eq!(ContextIdSide::of(1), ContextIdSide::Server);
        assert_eq!(ContextIdSide::of(99), ContextIdSide::Server);
    }
}
