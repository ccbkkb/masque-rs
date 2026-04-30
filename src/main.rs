// src/main.rs
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

mod protocol;
mod session;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use clap::Parser;
use dashmap::DashMap;
use h3::server::RequestResolver;
use http::{Request, Response, StatusCode};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::protocol::{decode_varint, encode_varint};
use crate::session::{ConnectUdpSession, QuicMessage};

const SESSION_CHANNEL_CAP: usize = 256;
const DATAGRAM_RECV_WINDOW: u64 = 16 * 1024 * 1024;

// =============================================================================
// § 0 — 命令行参数定义
// =============================================================================

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "MASQUE (CONNECT-UDP) Zero-Trust Proxy")]
pub struct AppConfig {
    #[arg(short, long, default_value = "0.0.0.0:4433")]
    pub listen: SocketAddr,
    #[arg(long, default_value_t = 3)]
    pub dns_timeout: u64,
    #[arg(long, default_value_t = false)]
    pub allow_local: bool,
    #[arg(long, default_value_t = 10000)]
    pub max_sessions: usize,
}

// =============================================================================
// § 1 — TLS & QUIC 初始化
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
// § 2 — HTTP/3 Connection & Datagram Demuxer
// =============================================================================

async fn handle_connection(quic_conn: quinn::Connection, config: Arc<AppConfig>) {
    let _conn_id = quic_conn.stable_id();
    let h3_quic = h3_quinn::Connection::new(quic_conn.clone());
    let mut h3_conn = match h3::server::Connection::new(h3_quic).await {
        Ok(c) => c,
        Err(_) => return,
    };

    let datagram_routers = Arc::new(DashMap::<u64, mpsc::Sender<QuicMessage>>::new());

    let demux_quic_rx = quic_conn.clone();
    let routers = datagram_routers.clone();
    let demux_task = tokio::spawn(async move {
        while let Ok(mut dgram) = demux_quic_rx.read_datagram().await {
            if let Ok(Some(q_stream_id)) = decode_varint(&mut dgram) {
                if let Some(sender) = routers.get(&q_stream_id.value) {
                    let _ = sender.value().send(QuicMessage::Datagram(dgram)).await;
                }
            }
        }
    });

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let quic_conn_clone = quic_conn.clone();
                let cfg_clone = config.clone();
                let routers_clone = datagram_routers.clone();
                tokio::spawn(async move {
                    handle_request(resolver, quic_conn_clone, cfg_clone, routers_clone).await;
                });
            }
            Ok(None) | Err(_) => break,
        }
    }

    demux_task.abort();
}

async fn handle_request(
    resolver: RequestResolver<h3_quinn::Connection, Bytes>,
    quic_conn: quinn::Connection,
    config: Arc<AppConfig>,
    datagram_routers: Arc<DashMap<u64, mpsc::Sender<QuicMessage>>>,
) {
    let (req, mut stream) = match resolver.resolve_request().await {
        Ok(pair) => pair,
        Err(_) => return,
    };
    let req = inject_protocol_header(req);

    let (target_host, target_port) = match session::parse_connect_udp_target(&req) {
        Ok(pair) => pair,
        Err(_) => {
            let _ = send_response(&mut stream, StatusCode::BAD_REQUEST).await;
            return;
        }
    };

    let resolve_future = tokio::net::lookup_host(format!("{target_host}:{target_port}"));
    let target_addr: SocketAddr = match tokio::time::timeout(Duration::from_secs(config.dns_timeout), resolve_future).await {
        Ok(Ok(mut it)) => {
            if let Some(a) = it.next() { a } else { return; }
        }
        Ok(Err(_)) | Err(_) => {
            let _ = send_response(&mut stream, StatusCode::BAD_GATEWAY).await;
            return;
        }
    };

    if !config.allow_local && is_private_or_loopback(target_addr.ip()) {
        let _ = send_response(&mut stream, StatusCode::FORBIDDEN).await;
        return;
    }

    info!("Tunnel accepted to {}:{}", target_host, target_port);

    let udp_sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return,
    };
    if udp_sock.connect(target_addr).await.is_err() {
        return;
    }

    if send_connect_udp_ok(&mut stream).await.is_err() { return; }

    let (h3_to_session_tx, h3_to_session_rx) = mpsc::channel::<QuicMessage>(SESSION_CHANNEL_CAP);
    let (session_to_h3_tx, mut session_to_h3_rx) = mpsc::channel::<Bytes>(SESSION_CHANNEL_CAP);

    // ==========================================
    // 鲁棒性计算 Quarter Stream ID
    // 采用字符串提取法，完美绕过底层的私有字段和版本类型差异！
    // ==========================================
    let stream_id_raw = format!("{:?}", stream.id());
    let stream_id: u64 = stream_id_raw
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0);
    let quarter_stream_id = stream_id / 4;
    datagram_routers.insert(quarter_stream_id, h3_to_session_tx.clone());

    // Task A: H3 Stream (Capsules) -> Session
    let stream_tx = h3_to_session_tx;
    let stream_recv_task = tokio::spawn(async move {
        loop {
            match stream.recv_data().await {
                Ok(Some(data)) => {
                    use bytes::Buf;
                    let mut data = data;
                    let chunk = data.copy_to_bytes(data.remaining());
                    if stream_tx.send(QuicMessage::StreamChunk(chunk)).await.is_err() { break; }
                }
                Ok(None) | Err(_) => {
                    let _ = stream_tx.send(QuicMessage::Closed).await;
                    break;
                }
            }
        }
    });

    // Task B: Session -> QUIC Datagram
    let dgram_send_task = tokio::spawn(async move {
        while let Some(payload) = session_to_h3_rx.recv().await {
            let mut out = bytes::BytesMut::with_capacity(8 + payload.len());
            encode_varint(&mut out, quarter_stream_id);
            out.extend_from_slice(&payload);
            
            if quic_conn.send_datagram(out.freeze()).is_err() { break; }
        }
    });

    let mut session = ConnectUdpSession::new(udp_sock, h3_to_session_rx, session_to_h3_tx);
    let _ = session.run().await;

    datagram_routers.remove(&quarter_stream_id);
    stream_recv_task.abort();
    dgram_send_task.abort();
}

fn is_private_or_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_loopback() || ipv4.is_private() || ipv4.is_link_local(),
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
    }
}

// =============================================================================
// § 3 & 4 — Helpers & Main
// =============================================================================

type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

async fn send_response(stream: &mut H3Stream, status: StatusCode) -> anyhow::Result<()> {
    stream.send_response(Response::builder().status(status).body(())?).await?;
    Ok(())
}

async fn send_connect_udp_ok(stream: &mut H3Stream) -> anyhow::Result<()> {
    stream.send_response(Response::builder().status(StatusCode::OK).header("capsule-protocol", "?1").body(())?).await?;
    Ok(())
}

fn inject_protocol_header(mut req: Request<()>) -> Request<()> {
    if let Some(proto) = req.extensions().get::<h3::ext::Protocol>() {
        if let Ok(val) = http::HeaderValue::from_str(proto.as_str()) {
            req.headers_mut().insert("x-protocol", val);
        }
    }
    req
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Arc::new(AppConfig::parse());

    if let Err(e) = rlimit::increase_nofile_limit(65535) {
        warn!("Failed to increase NOFILE limit: {}", e);
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt().with_env_filter("info,masque_proxy=debug").init();

    let (cert_der, key_der) = generate_self_signed_cert()?;
    info!("Generated self-signed TLS certificate");

    let server_cfg = make_server_config(cert_der, key_der)?;
    let endpoint = quinn::Endpoint::server(server_cfg, config.listen)?;
    info!("MASQUE CONNECT-UDP zero-trust proxy listening on {}", config.listen);

    let connection_limit = Arc::new(tokio::sync::Semaphore::new(config.max_sessions));

    while let Some(incoming) = endpoint.accept().await {
        let permit = connection_limit.clone().acquire_owned().await;
        let config_clone = config.clone();
        
        match incoming.await {
            Ok(conn) => {
                tokio::spawn(async move {
                    let _permit = permit; 
                    handle_connection(conn, config_clone).await;
                });
            }
            Err(e) => warn!("Connection failed: {}", e),
        }
    }

    Ok(())
}
