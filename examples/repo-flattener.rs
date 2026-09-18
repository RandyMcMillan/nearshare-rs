use anyhow::{Context, Result};
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use walkdir::WalkDir;

use nearshare_rs::repo_flattener::{
    build_html, default_output_path, git_short_hash, is_binary, normalize_repo_url, FileInfo,
};

const MAX_DEFAULT_BYTES: u64 = 51200; // 50 KiB

#[derive(Parser, Debug)]
#[command(author, version, about = "Strictly-compliant Repo Flattener")]
struct Args {
    repo_url: String,
    #[arg(short, long)]
    out: Option<PathBuf>,
    #[arg(long, default_value_t = MAX_DEFAULT_BYTES)]
    max_bytes: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let repo_url = normalize_repo_url(&args.repo_url);

    let tmp_dir = tempfile::Builder::new().prefix("flatten_").tempdir()?;
    let repo_path = tmp_dir.path().join("repo");

    println!("Cloning repository...");
    let status = Command::new("git")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env(
            "GIT_SSH_COMMAND",
            "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new",
        )
        .args(["clone", "--depth", "1", &repo_url, "repo"])
        .current_dir(tmp_dir.path())
        .status()
        .context("Git command failed")?;

    if !status.success() {
        anyhow::bail!("Failed to clone repository.");
    }

    let short_hash = git_short_hash(&repo_path).unwrap_or_else(|_| "unknown".to_string());

    let mut files = Vec::new();
    for entry in WalkDir::new(&repo_path).sort_by_file_name() {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            let rel = path
                .strip_prefix(&repo_path)?
                .to_string_lossy()
                .replace('\\', "/");

            if rel.starts_with(".git/") {
                continue;
            }

            let size = entry.metadata()?.len();
            let mut content = None;

            if size <= args.max_bytes && !is_binary(path) {
                content = fs::read_to_string(path).ok();
            }

            files.push(FileInfo { rel, size, content });
        }
    }

    let html = build_html(&repo_url, files)?;
    let out = args
        .out
        .unwrap_or_else(|| default_output_path(&repo_url, &short_hash));
    fs::write(&out, html)?;

    println!("✓ Flattened HTML generated at: {:?}", out);
    Ok(())
}
