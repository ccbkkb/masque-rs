// src/main.rs
mod protocol;
mod session;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use clap::Parser; // 引入命令行解析
use h3::server::RequestResolver;
use http::{Request, Response, StatusCode};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::session::{ConnectUdpSession, QuicMessage};

const SESSION_CHANNEL_CAP: usize = 256;
const DATAGRAM_RECV_WINDOW: u64 = 16 * 1024 * 1024;

// =============================================================================
// § 0 — 命令行参数定义 (CLI Config)
// =============================================================================

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "MASQUE (CONNECT-UDP) High-Performance Proxy", long_about = None)]
pub struct AppConfig {
    /// 监听地址和端口
    #[arg(short, long, default_value = "0.0.0.0:4433")]
    pub listen: SocketAddr,

    /// DNS 解析超时时间 (秒)
    #[arg(long, default_value_t = 3)]
    pub dns_timeout: u64,

    /// 是否允许代理连接到本地/内网 IP (关闭 SSRF 防护)
    #[arg(long, default_value_t = false)]
    pub allow_local: bool,

    /// 最大全局并发会话数 (防止 OOM 和 CPU 耗尽)
    #[arg(long, default_value_t = 10000)]
    pub max_sessions: usize,
}

// ... 这里的 §1 (generate_self_signed_cert 和 make_server_config) 保持不变 ...
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
// § 2 — HTTP/3 Connection & Request Handling
// =============================================================================

async fn handle_connection(quic_conn: quinn::Connection, config: Arc<AppConfig>) {
    let conn_id = quic_conn.stable_id();
    let h3_quic = h3_quinn::Connection::new(quic_conn.clone());
    let mut h3_conn = match h3::server::Connection::new(h3_quic).await {
        Ok(c) => c,
        Err(_) => return,
    };

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let quic_conn_clone = quic_conn.clone();
                let cfg_clone = config.clone();
                tokio::spawn(async move {
                    handle_request(resolver, quic_conn_clone, cfg_clone).await;
                });
            }
            Ok(None) | Err(_) => break,
        }
    }
}

async fn handle_request(
    resolver: RequestResolver<h3_quinn::Connection, Bytes>,
    quic_conn: quinn::Connection,
    config: Arc<AppConfig>,
) {
    let (req, mut stream) = match resolver.resolve_request().await {
        Ok(pair) => pair,
        Err(_) => return,
    };
    let req = inject_protocol_header(req);

    // 1. Handshake Validation
    let (target_host, target_port) = match session::parse_connect_udp_target(&req) {
        Ok(pair) => pair,
        Err(_) => {
            let _ = send_response(&mut stream, StatusCode::BAD_REQUEST).await;
            return;
        }
    };

    // 2. DNS 解析 (加入防挂起 Timeout)
    let resolve_future = tokio::net::lookup_host(format!("{target_host}:{target_port}"));
    let target_addr: SocketAddr = match tokio::time::timeout(Duration::from_secs(config.dns_timeout), resolve_future).await {
        Ok(Ok(mut it)) => {
            if let Some(a) = it.next() { a } else { return; }
        }
        Ok(Err(_)) | Err(_) => {
            warn!("DNS resolution failed or timed out for {target_host}");
            let _ = send_response(&mut stream, StatusCode::BAD_GATEWAY).await;
            return;
        }
    };

    // 3. 防内网 SSRF (UDP 目标地址过滤)
    if !config.allow_local && is_private_or_loopback(target_addr.ip()) {
        warn!("SSRF Blocked: Attempt to connect to private IP {}", target_addr.ip());
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

    // Setup Channels & Bridge Tasks... (这部分不变)
    let (h3_to_session_tx, h3_to_session_rx) = mpsc::channel::<QuicMessage>(SESSION_CHANNEL_CAP);
    let (session_to_h3_tx, mut session_to_h3_rx) = mpsc::channel::<Bytes>(SESSION_CHANNEL_CAP);

    let datagram_tx = h3_to_session_tx.clone();
    let quic_rx_clone = quic_conn.clone();
    let dgram_recv_task = tokio::spawn(async move {
        while let Ok(dgram) = quic_rx_clone.read_datagram().await {
            if datagram_tx.send(QuicMessage::Datagram(dgram)).await.is_err() { break; }
        }
        let _ = datagram_tx.send(QuicMessage::Closed).await;
    });

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

    let dgram_send_task = tokio::spawn(async move {
        while let Some(payload) = session_to_h3_rx.recv().await {
            if quic_conn.send_datagram(payload).is_err() { break; }
        }
    });

    let mut session = ConnectUdpSession::new(udp_sock, h3_to_session_rx, session_to_h3_tx);
    let _ = session.run().await;

    dgram_recv_task.abort();
    stream_recv_task.abort();
    dgram_send_task.abort();
}

// ── 辅助函数：判断是否为私有地址或回环地址 (防 SSRF 核心) ──
fn is_private_or_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_loopback() || ipv4.is_private() || ipv4.is_link_local(),
        IpAddr::V6(ipv6) => ipv6.is_loopback(), // IPv6 的私有地址判断在某些 Rust 稳定版未完全稳定，仅做 loopback 防御
    }
}

// =============================================================================
// § 3 & 4 — Helpers & Main Entry Point
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
        if let Ok(val) = http::HeaderValue::from_str(proto.as_str()) {
            req.headers_mut().insert("x-protocol", val);
        }
    }
    req
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. 解析命令行参数
    let config = Arc::new(AppConfig::parse());

    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt().with_env_filter("info,masque_proxy=debug").init();

    let (cert_der, key_der) = generate_self_signed_cert()?;
    info!("Generated self-signed TLS certificate");

    let server_cfg = make_server_config(cert_der, key_der)?;
    
    // 使用 CLI 中传入的监听地址
    let endpoint = quinn::Endpoint::server(server_cfg, config.listen)?;
    info!("MASQUE CONNECT-UDP proxy listening on {}", config.listen);

    // 引入基于 Semaphore 的全局并发限制 (防 OOM 和 流量洪峰)
    let connection_limit = Arc::new(tokio::sync::Semaphore::new(config.max_sessions));

    while let Some(incoming) = endpoint.accept().await {
        let permit = connection_limit.clone().acquire_owned().await;
        let config_clone = config.clone();
        
        match incoming.await {
            Ok(conn) => {
                tokio::spawn(async move {
                    // 当这个闭包结束时，permit 自动释放 (Drop)，并发数 -1
                    let _permit = permit; 
                    handle_connection(conn, config_clone).await;
                });
            }
            Err(e) => warn!("Connection failed: {}", e),
        }
    }

    Ok(())
}
