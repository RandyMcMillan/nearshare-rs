use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub username: String,
}

#[derive(Serialize, Deserialize, Default)]
pub struct UploadMeta {
    pub git_repos: Vec<String>,
}

#[derive(Serialize)]
pub struct FileListResponse {
    pub files: Vec<String>,
    pub git_repos: Vec<String>,
}

#[derive(Serialize)]
pub struct PeerIdResponse {
    pub peer_id: String,
    pub name: String,
}

#[derive(Serialize)]
pub struct SendResult {
    pub status: String,
}
