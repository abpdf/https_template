use hyper::{Body, Request, Response, StatusCode};
use hyper::service::service_fn;
use rcgen::generate_simple_self_signed;
use rustls::{Certificate as RustlsCertificate, PrivateKey, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use url::form_urlencoded;

async fn handle_request(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let (status, content, content_type) = match req.uri().path() {
        "/html" => {
            // 解析查询参数，提取 name 的值
            let name = req.uri()
                .query()
                .and_then(|q| {
                    form_urlencoded::parse(q.as_bytes())
                        .find(|(key, _)| key == "name")
                        .map(|(_, value)| value.into_owned())
                })
                .unwrap_or_else(|| "World".to_string()); // 默认值

            let html = format!("<html><body><h1>Hello, {}!</h1></body></html>", name);
            (StatusCode::OK, html, "text/html")
        }
        "/json" => (StatusCode::OK, r#"{"message": "Hello, JSON!"}"#.to_string(), "application/json"),
        "/txt"  => (StatusCode::OK, "Hello, Text!".to_string(), "text/plain"),
        _       => (StatusCode::NOT_FOUND, "404".to_string(), "text/plain"),
    };
    Ok(Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .body(Body::from(content))
        .unwrap())
}

fn generate_self_signed_cert() -> (Vec<RustlsCertificate>, PrivateKey) {
    let subject_alt_names = vec!["localhost".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let key_der = cert.get_key_pair().serialize_der();
    (vec![RustlsCertificate(cert_der)], PrivateKey(key_der))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (certs, key) = generate_self_signed_cert();
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(config));

    let addr: SocketAddr = "0.0.0.0:8443".parse()?;
    let listener = TcpListener::bind(addr).await?;
    println!("HTTPS server running on https://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("TLS accept error: {}", e);
                    return;
                }
            };
            let service = service_fn(handle_request);
            if let Err(e) = hyper::server::conn::Http::new()
                .serve_connection(tls_stream, service)
                .await
            {
                eprintln!("HTTP serve error: {}", e);
            }
        });
    }
}