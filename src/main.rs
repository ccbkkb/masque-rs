// src/main.rs
mod protocol;
mod session;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h3::server::RequestResolver;
use http::{Request, Response, StatusCode};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::session::{ConnectUdpSession, QuicMessage};

const LISTEN_ADDR: &str = "0.0.0.0:4433";
const DATAGRAM_RECV_WINDOW: u64 = 16 * 1024 * 1024; // 16 MiB
const SESSION_CHANNEL_CAP: usize = 256;

// =============================================================================
// § 1 — TLS & QUIC Server Config
// =============================================================================

fn generate_self_signed_cert() -> anyhow::Result<(
    rustls_pki_types::CertificateDer<'static>,
    rustls_pki_types::PrivateKeyDer<'static>,
)> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, "masque-proxy");
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ];

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_der = rustls_pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
        rustls_pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
    );

    Ok((cert_der, key_der))
}

fn make_server_config(
    cert_der: rustls_pki_types::CertificateDer<'static>,
    key_der: rustls_pki_types::PrivateKeyDer<'static>,
) -> anyhow::Result<quinn::ServerConfig> {
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;

    // 【关键修复：注册 HTTP/3 ALPN】
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls_config))?,
    ));

    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(100u32.into())
        .max_concurrent_uni_streams(10u32.into())
        .datagram_receive_buffer_size(Some(DATAGRAM_RECV_WINDOW as usize))
        .datagram_send_buffer_size(DATAGRAM_RECV_WINDOW as usize)
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .max_idle_timeout(Some(Duration::from_secs(30).try_into()?));

    server_cfg.transport_config(Arc::new(transport));
    Ok(server_cfg)
}

// =============================================================================
// § 2 — HTTP/3 Connection & Request Handling
// =============================================================================

async fn handle_connection(quic_conn: quinn::Connection) {
    let conn_id = quic_conn.stable_id();
    info!(conn_id, remote = %quic_conn.remote_address(), "New QUIC connection");

    let h3_quic = h3_quinn::Connection::new(quic_conn.clone());
    let mut h3_conn = match h3::server::Connection::new(h3_quic).await {
        Ok(c) => c,
        Err(e) => {
            warn!(conn_id, "H3 handshake failed: {e}");
            return;
        }
    };

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let quic_conn_clone = quic_conn.clone();
                tokio::spawn(async move {
                    handle_request(resolver, quic_conn_clone).await;
                });
            }
            Ok(None) => break, // Peer closed gracefully
            Err(e) => {
                warn!(conn_id, "H3 accept error: {e}");
                break;
            }
        }
    }
}

async fn handle_request(
    resolver: RequestResolver<h3_quinn::Connection, Bytes>,
    quic_conn: quinn::Connection,
) {
    let (req, mut stream) = match resolver.resolve_request().await {
        Ok(pair) => pair,
        Err(e) => {
            error!("Request resolution failed: {e}");
            return;
        }
    };

    let req = inject_protocol_header(req);

    // 1. Handshake Validation
    let (target_host, target_port) = match session::parse_connect_udp_target(&req) {
        Ok(pair) => pair,
        Err(e) => {
            warn!("CONNECT-UDP validation failed: {e}");
            let _ = send_response(&mut stream, StatusCode::BAD_REQUEST).await;
            return;
        }
    };

    info!("CONNECT-UDP tunnel accepted to {}:{}", target_host, target_port);

    // 2. Resolve Target & Bind UDP
    let target_addr: SocketAddr = match tokio::net::lookup_host(format!("{target_host}:{target_port}"))
        .await
        .ok()
        .and_then(|mut it| it.next())
    {
        Some(a) => a,
        None => {
            error!("DNS resolution failed for {target_host}:{target_port}");
            let _ = send_response(&mut stream, StatusCode::BAD_GATEWAY).await;
            return;
        }
    };

    let udp_sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            error!("UDP bind failed: {e}");
            let _ = send_response(&mut stream, StatusCode::INTERNAL_SERVER_ERROR).await;
            return;
        }
    };

    if let Err(e) = udp_sock.connect(target_addr).await {
        error!("UDP connect failed: {e}");
        let _ = send_response(&mut stream, StatusCode::BAD_GATEWAY).await;
        return;
    }

    // 3. Send 200 OK + Capsule Protocol Header
    if let Err(e) = send_connect_udp_ok(&mut stream).await {
        debug!("Failed to send 200 OK: {e}");
        return;
    }

    // 4. Setup Channels & Bridge Tasks
    let (h3_to_session_tx, h3_to_session_rx) = mpsc::channel::<QuicMessage>(SESSION_CHANNEL_CAP);
    let (session_to_h3_tx, mut session_to_h3_rx) = mpsc::channel::<Bytes>(SESSION_CHANNEL_CAP);

    // Task A: QUIC Datagram -> Session
    let datagram_tx = h3_to_session_tx.clone();
    let quic_rx_clone = quic_conn.clone();
    let dgram_recv_task = tokio::spawn(async move {
        while let Ok(dgram) = quic_rx_clone.read_datagram().await {
            if datagram_tx.send(QuicMessage::Datagram(dgram)).await.is_err() {
                break;
            }
        }
        let _ = datagram_tx.send(QuicMessage::Closed).await;
    });

    // Task B: H3 Stream (Capsules) -> Session
    let stream_tx = h3_to_session_tx;
    let stream_recv_task = tokio::spawn(async move {
        loop {
            match stream.recv_data().await {
                Ok(Some(data)) => {
                    use bytes::Buf;
                    let mut data = data;
                    let chunk = data.copy_to_bytes(data.remaining());
                    if stream_tx.send(QuicMessage::StreamChunk(chunk)).await.is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => {
                    let _ = stream_tx.send(QuicMessage::Closed).await;
                    break;
                }
            }
        }
    });

    // Task C: Session -> QUIC Datagram
    let dgram_send_task = tokio::spawn(async move {
        while let Some(payload) = session_to_h3_rx.recv().await {
            if quic_conn.send_datagram(payload).is_err() {
                break;
            }
        }
    });

    // 5. Run Session Engine
    let mut session = ConnectUdpSession::new(udp_sock, h3_to_session_rx, session_to_h3_tx);
    let _ = session.run().await;

    // Cleanup
    dgram_recv_task.abort();
    stream_recv_task.abort();
    dgram_send_task.abort();
    info!("Session to {}:{} closed cleanly", target_host, target_port);
}

// =============================================================================
// § 3 — Helpers
// =============================================================================

type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

async fn send_response(stream: &mut H3Stream, status: StatusCode) -> anyhow::Result<()> {
    let resp = Response::builder().status(status).body(())?;
    stream.send_response(resp).await?;
    Ok(())
}

async fn send_connect_udp_ok(stream: &mut H3Stream) -> anyhow::Result<()> {
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("capsule-protocol", "?1")
        .body(())?;
    stream.send_response(resp).await?;
    Ok(())
}

fn inject_protocol_header(mut req: Request<()>) -> Request<()> {
    if let Some(proto) = req.extensions().get::<h3::ext::Protocol>() {
        // Fix: h3 0.0.8 removed AsRef, but provides an explicit .as_str() method.
        if let Ok(val) = http::HeaderValue::from_str(proto.as_str()) {
            req.headers_mut().insert("x-protocol", val);
        }
    }
    req
}

// =============================================================================
// § 4 — Main Entry Point
// =============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter("info,masque_proxy=debug")
        .init();

    let (cert_der, key_der) = generate_self_signed_cert()?;
    info!("Generated self-signed TLS certificate");

    let server_cfg = make_server_config(cert_der, key_der)?;
    let listen: SocketAddr = LISTEN_ADDR.parse()?;
    let endpoint = quinn::Endpoint::server(server_cfg, listen)?;

    info!("MASQUE CONNECT-UDP proxy listening on {}", listen);

    while let Some(incoming) = endpoint.accept().await {
        match incoming.await {
            Ok(conn) => {
                tokio::spawn(handle_connection(conn));
            }
            Err(e) => warn!("Connection failed: {}", e),
        }
    }

    Ok(())
}
