#[actix_web::main]
async fn main() -> std::io::Result<()> {
    nearshare_rs::run().await
}
