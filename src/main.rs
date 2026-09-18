use actix_web::{App, HttpServer, web};
use nearshare_rs::p2p;
use nearshare_rs::handlers::*;
use nearshare_rs::{AppState, clear_uploads_dir};
use actix_web::middleware::Logger;
use aes_gcm::{
    Aes256Gcm, aead::{KeyInit, OsRng}
};
use std::env;
use std::{sync::{Arc, Mutex}};
use std::collections::HashMap;
use mdns_sd::{ServiceDaemon, ServiceInfo};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    clear_uploads_dir().await?;
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);

    let hostname = env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "SecureFileShare".to_string());

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let cipher_arc = Arc::new(cipher.clone());
    let (p2p_node, p2p_handle) = p2p::P2PNode::new(hostname.clone(), cipher_arc).await
        .expect("Failed to create P2P node");
    tokio::spawn(p2p_node.run());

    let auth_tokens = Arc::new(Mutex::new(HashMap::new()));
    let state = web::Data::new(AppState {
        auth_tokens: auth_tokens.clone(),
        encryption_key: cipher,
        p2p: p2p_handle,
    });

    let hostname_mdns = format!("{}.local.", hostname);
    let mdns = ServiceDaemon::new().expect("Failed to create mDNS daemon");
    let service_info = ServiceInfo::new(
        "_fileshare._tcp.local.",
        "SecureFileShare",
        &hostname_mdns,
        "",
        port,
        None
    ).expect("Invalid Service Info");

    mdns.register(service_info).expect("failed to register mdns servifce");

    println!("NearShare-rs starting at port {}", port);
    println!("use username:admin password:password");

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(Logger::default())
            .route("/", web::get().to(index))
            .route("/api/auth", web::post().to(authenticate))
            .route("/api/session", web::get().to(session))
            .route("/api/logout", web::post().to(logout))
            .route("/api/upload", web::post().to(upload_file))
            .route("/api/files", web::get().to(list_files))
            .route("/api/download", web::get().to(download_file))
            .route("/api/download/incoming", web::get().to(download_incoming_file))
            .route("/api/peer_id", web::get().to(get_peer_id))
            .route("/api/peers", web::get().to(list_peers))
            .route("/api/send", web::post().to(send_file_to_peer))
            .route("/api/incoming", web::get().to(list_incoming))
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await
}
