use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use nearshare_rs::p2p;
use actix_multipart::Multipart;
use futures_util::{StreamExt, TryStreamExt};
use actix_web::middleware::Logger;
use serde::{Serialize,Deserialize};
use aes_gcm::{
    Aes256Gcm, Nonce, aead::{Aead, KeyInit,OsRng}
};
use std::env;
use rand::Rng;
use mdns_sd::{ServiceDaemon,ServiceInfo};
use tokio::{fs, io::AsyncWriteExt};
use std::{sync::{Arc, Mutex}};
use std::collections::HashMap;
use std::path::Path;


#[derive(Serialize,Deserialize)]
struct AuthRequest{
    username:String,    
    password:String
}
#[derive(Serialize,Deserialize)]
struct AuthResponse{
    token:String
}

#[derive(Serialize)]
struct SessionResponse {
    username: String,
}

#[derive(Serialize,Deserialize,Default)]
struct UploadMeta {
    git_repos: Vec<String>,
}

#[derive(Serialize)]
struct FileListResponse {
    files: Vec<String>,
    git_repos: Vec<String>,
}

struct AppState {
    auth_tokens: Arc<Mutex<HashMap<String,String>>>,
    encryption_key:Aes256Gcm,
    p2p: p2p::P2PHandle,
}

async fn index() -> impl Responder{
    match fs::read_to_string("frontend.html").await {
        Ok(html) => HttpResponse::Ok().content_type("text/html").body(html),
        Err(_) => HttpResponse::InternalServerError().body("Frontend file not found."),
    }
}


async fn authenticate(
    req: web::Json<AuthRequest>,
    state:web::Data<AppState>,
) -> impl Responder{
    if req.username == "admin" && req.password == "password"{
        // Start each authenticated use with a fresh upload set.
        if clear_uploads_dir().await.is_err() {
            return HttpResponse::InternalServerError().body("Failed to reset uploads");
        }

        let token = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(32)
                .map(|x|char::from(x))
                .collect::<String>();
        
        state.auth_tokens.lock().unwrap().insert(token.clone(), req.username.clone());
        
        HttpResponse::Ok().json(AuthResponse{token})
    }else {
        HttpResponse::Unauthorized().finish()
    }

}

fn authenticated_username(
    req: &actix_web::HttpRequest,
    state: &web::Data<AppState>,
) -> Option<String> {
    let auth_header = req.headers().get("Authorization")?;
    let auth_str = auth_header.to_str().ok()?;
    let token = auth_str.strip_prefix("Bearer ")?;
    state.auth_tokens.lock().unwrap().get(token).cloned()
}

fn authenticated_token(
    req: &actix_web::HttpRequest,
    state: &web::Data<AppState>,
) -> Option<String> {
    let auth_header = req.headers().get("Authorization")?;
    let auth_str = auth_header.to_str().ok()?;
    let token = auth_str.strip_prefix("Bearer ")?.to_string();
    if state.auth_tokens.lock().unwrap().contains_key(&token) {
        Some(token)
    } else {
        None
    }
}

async fn session(
    state: web::Data<AppState>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if let Some(username) = authenticated_username(&req, &state) {
        return HttpResponse::Ok().json(SessionResponse { username });
    }

    HttpResponse::Unauthorized().finish()
}

async fn logout(
    state: web::Data<AppState>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if let Some(token) = authenticated_token(&req, &state) {
        state.auth_tokens.lock().unwrap().remove(&token);
        if clear_uploads_dir().await.is_err() {
            return HttpResponse::InternalServerError().body("Failed to clear uploads");
        }
        return HttpResponse::Ok().finish();
    }

    HttpResponse::Unauthorized().finish()
}

async fn upload_file(
    mut payload: Multipart,
    state: web::Data<AppState>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if authenticated_username(&req, &state).is_none() {
        return HttpResponse::Unauthorized().finish();
    }

    let tmp_id = format!("tmp-{}", rand::thread_rng().r#gen::<u64>());
    let tmp_base = format!("uploads/.tmp/{}", tmp_id);

    // Phase 1: stream all uploaded files into temp directory preserving paths
    while let Ok(Some(mut field)) = payload.try_next().await {
        let rel_path = field
            .name()
            .and_then(|n| n.strip_prefix("files:"))
            .map(|s| s.to_string())
            .or_else(|| {
                field
                    .content_disposition()
                    .and_then(|cd| cd.get_filename())
                    .map(|f| f.to_string())
            })
            .unwrap_or_else(|| "unnamed".to_string());

        let mut data = Vec::new();
        while let Some(chunk) = field.next().await {
            let chunk = chunk.unwrap();
            data.extend_from_slice(&chunk);
        }

        let tmp_path = format!("{}/{}", tmp_base, rel_path);
        if let Some(parent) = Path::new(&tmp_path).parent() {
            fs::create_dir_all(parent).await.unwrap();
        }
        let mut file = fs::File::create(&tmp_path).await.unwrap();
        file.write_all(&data).await.unwrap();
    }

    // Detect git repos in the uploaded tree
    let mut git_repos = Vec::new();
    let tmp_path_obj = Path::new(&tmp_base);
    if tmp_path_obj.join(".git").is_dir() {
        git_repos.push(".".to_string());
    }
    if let Ok(entries) = std::fs::read_dir(tmp_path_obj) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.join(".git").is_dir() {
                git_repos.push(path.file_name().unwrap_or_default().to_string_lossy().to_string());
            }
        }
    }
    // Merge with existing metadata
    let meta_path = "uploads/.nearshare-meta.json";
    let mut meta: UploadMeta = if Path::new(meta_path).exists() {
        fs::read_to_string(meta_path).await
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        UploadMeta::default()
    };
    for repo in git_repos {
        if !meta.git_repos.contains(&repo) {
            meta.git_repos.push(repo);
        }
    }
    if let Ok(json) = serde_json::to_string(&meta) {
        let _ = fs::write(meta_path, json).await;
    }

    // Phase 2: walk temp directory respecting .gitignore, encrypt and move
    let mut files_saved = Vec::new();
    let walker = ignore::WalkBuilder::new(&tmp_base)
        .hidden(false)
        .git_ignore(true)
        .build();

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            continue;
        }
        if entry.path().components().any(|c| c.as_os_str() == ".git") {
            continue;
        }

        let rel_path = match entry.path().strip_prefix(&tmp_base) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let rel_str = rel_path.to_string_lossy().to_string();

        let data = match fs::read(entry.path()).await {
            Ok(d) => d,
            Err(_) => continue,
        };

        let nonce_bytes = rand::thread_rng().r#gen::<[u8; 12]>();
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = match state.encryption_key.encrypt(&nonce, data.as_ref()) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut encrypted_data = Vec::new();
        encrypted_data.extend_from_slice(&nonce_bytes);
        encrypted_data.extend_from_slice(&ciphertext);

        let final_path = format!("uploads/{}", rel_str);
        if let Some(parent) = Path::new(&final_path).parent() {
            fs::create_dir_all(parent).await.unwrap();
        }
        let mut file = fs::File::create(&final_path).await.unwrap();
        file.write_all(&encrypted_data).await.unwrap();
        files_saved.push(rel_str);
    }

    let _ = fs::remove_dir_all(&tmp_base).await;
    HttpResponse::Ok().json(files_saved)
}

async fn list_files(
    state: web::Data<AppState>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if authenticated_username(&req, &state).is_some() {
        let mut files = Vec::new();
        let walker = ignore::WalkBuilder::new("uploads")
            .hidden(false)
            .git_ignore(false)
            .build();
        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                continue;
            }
            let rel_path = match entry.path().strip_prefix("uploads") {
                Ok(p) => p,
                Err(_) => continue,
            };
            let rel_str = rel_path.to_string_lossy().to_string();
            if rel_str.starts_with("incoming") || rel_str.starts_with("/.tmp") || rel_str.starts_with(".tmp") || rel_str.starts_with(".nearshare-meta") {
                continue;
            }
            files.push(rel_str);
        }
        files.sort();
        let meta: UploadMeta = fs::read_to_string("uploads/.nearshare-meta.json")
            .await
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        return HttpResponse::Ok().json(FileListResponse {
            files,
            git_repos: meta.git_repos,
        });
    }
    HttpResponse::Unauthorized().finish()
}


async fn download_file(
    query: web::Query<HashMap<String, String>>,
    state: web::Data<AppState>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if authenticated_username(&req, &state).is_some() {
        let file_name = query.get("path").cloned().unwrap_or_default();
        if file_name.is_empty() {
            return HttpResponse::BadRequest().body("Missing path parameter");
        }
        let file_path = format!("uploads/{}", file_name);
        if Path::new(&file_path).exists() {
            let encrypted_data = fs::read(&file_path).await.unwrap();
            if encrypted_data.len() < 12 {
                return HttpResponse::InternalServerError().finish();
            }
            let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
            #[allow(deprecated)]
            let nonce = Nonce::from_slice(nonce_bytes);

            return match state.encryption_key.decrypt(nonce, ciphertext) {
                Ok(decrypted_data) => {
                    HttpResponse::Ok()
                        .content_type("application/octet-stream")
                        .append_header((
                            "Content-Disposition",
                            format!("attachment; filename=\"{}\"", Path::new(&file_name).file_name().unwrap_or_default().to_string_lossy()),
                        ))
                        .body(decrypted_data)
                }
                Err(_) => HttpResponse::InternalServerError().body("Decryption Failed"),
            };
        }
        return HttpResponse::NotFound().body("File Not Found");
    }
    HttpResponse::Unauthorized().finish()
}

async fn download_incoming_file(
    query: web::Query<HashMap<String, String>>,
    state: web::Data<AppState>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if authenticated_username(&req, &state).is_some() {
        let peer_id = query.get("peer_id").cloned().unwrap_or_default();
        let file_name = query.get("path").cloned().unwrap_or_default();
        if peer_id.is_empty() || file_name.is_empty() {
            return HttpResponse::BadRequest().body("Missing peer_id or path parameter");
        }
        let file_path = format!("uploads/incoming/{}/{}", peer_id, file_name);
        if Path::new(&file_path).exists() {
            let encrypted_data = fs::read(&file_path).await.unwrap();
            if encrypted_data.len() < 12 {
                return HttpResponse::InternalServerError().finish();
            }
            let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
            #[allow(deprecated)]
            let nonce = Nonce::from_slice(nonce_bytes);

            return match state.encryption_key.decrypt(nonce, ciphertext) {
                Ok(decrypted_data) => {
                    HttpResponse::Ok()
                        .content_type("application/octet-stream")
                        .append_header((
                            "Content-Disposition",
                            format!("attachment; filename=\"{}\"", Path::new(&file_name).file_name().unwrap_or_default().to_string_lossy()),
                        ))
                        .body(decrypted_data)
                }
                Err(_) => HttpResponse::InternalServerError().body("Decryption Failed"),
            };
        }
        return HttpResponse::NotFound().body("File Not Found");
    }
    HttpResponse::Unauthorized().finish()
}

#[derive(Serialize)]
struct PeerIdResponse {
    peer_id: String,
    name: String,
}

async fn get_peer_id(state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(PeerIdResponse {
        peer_id: state.p2p.local_peer_id.to_string(),
        name: state.p2p.name.clone(),
    })
}

async fn list_peers(state: web::Data<AppState>, req: actix_web::HttpRequest) -> impl Responder {
    if authenticated_username(&req, &state).is_none() {
        return HttpResponse::Unauthorized().finish();
    }
    let peers = state.p2p.list_peers().await;
    HttpResponse::Ok().json(peers)
}

#[derive(Serialize)]
struct SendResult {
    status: String,
}

async fn send_file_to_peer(
    query: web::Query<HashMap<String, String>>,
    state: web::Data<AppState>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if authenticated_username(&req, &state).is_none() {
        return HttpResponse::Unauthorized().finish();
    }
    let peer_id_str = query.get("peer_id").cloned().unwrap_or_default();
    let filename = query.get("path").cloned().unwrap_or_default();
    if peer_id_str.is_empty() || filename.is_empty() {
        return HttpResponse::BadRequest().body("Missing peer_id or path parameter");
    }
    let peer_id = match peer_id_str.parse::<libp2p::PeerId>() {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().body("Invalid peer ID"),
    };
    match state.p2p.send_file(peer_id, filename).await {
        Ok(()) => HttpResponse::Ok().json(SendResult {
            status: "sent".to_string(),
        }),
        Err(e) => HttpResponse::InternalServerError().body(format!("Send failed: {}", e)),
    }
}

async fn list_incoming(
    state: web::Data<AppState>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if authenticated_username(&req, &state).is_none() {
        return HttpResponse::Unauthorized().finish();
    }
    match state.p2p.get_incoming_files().await {
        Ok(files) => HttpResponse::Ok().json(files),
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed to list incoming: {}", e)),
    }
}

async fn clear_uploads_dir() -> std::io::Result<()> {
    fs::create_dir_all("uploads").await?;
    let mut entries = fs::read_dir("uploads").await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let file_name = entry.file_name();
        if file_name == "incoming" {
            continue;
        }
        let metadata = entry.metadata().await?;
        if metadata.is_file() {
            fs::remove_file(path).await?;
        } else if metadata.is_dir() {
            fs::remove_dir_all(path).await?;
        }
    }

    Ok(())
}

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
    let state = web::Data::new(AppState{
        auth_tokens :auth_tokens.clone(),
        encryption_key:cipher,
        p2p: p2p_handle,
    });

    let hostname_mdns = format!("{}.local.", hostname);
    let mdns = ServiceDaemon::new().expect("Failed to create mDNS daemon");
    let service_info = ServiceInfo::new(
    "_fileshare._tcp.local.",     // Service type
    "SecureFileShare",             // Instance name
    &hostname_mdns,                // Hostname
    "",                            // IP address (empty is fine)
    port,                          // Port
    None                           // TXT records
    ).expect("Invalid Service Info");

    mdns.register(service_info).expect("failed to register mdns servifce");

    println!("NearShare-rs starting at port {}", port);
    println!("use username:admin password:password");


    HttpServer::new(move||{
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
