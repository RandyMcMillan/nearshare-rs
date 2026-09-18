pub mod p2p;
pub mod models;
pub mod handlers;

use aes_gcm::Aes256Gcm;
use p2p::P2PHandle;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::fs;

pub struct AppState {
    pub auth_tokens: Arc<Mutex<HashMap<String, String>>>,
    pub encryption_key: Aes256Gcm,
    pub p2p: P2PHandle,
}

pub async fn clear_uploads_dir() -> std::io::Result<()> {
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
