use std::net::SocketAddr;

use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;

use rrm::config::AppConfig;
use rrm::grpc::RrmService;
use rrm::pb::{
    admin_service_server::AdminServiceServer,
    authorization_service_server::AuthorizationServiceServer,
    entity_service_server::EntityServiceServer, policy_service_server::PolicyServiceServer,
};
use rrm::store::Store;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = AppConfig::load()?;
    let addr: SocketAddr = cfg.server.listen_addr.parse()?;

    info!(
        endpoint = %cfg.surrealdb.endpoint,
        namespace = %cfg.surrealdb.namespace,
        database = %cfg.surrealdb.database,
        "Connecting to SurrealDB"
    );
    let store = Store::connect(&cfg.surrealdb).await?;

    let service = RrmService::new(store, cfg.auth.admin_token);

    info!(%addr, "Starting RRM Cedar Policy & SurrealDB gRPC Server");

    Server::builder()
        .add_service(AdminServiceServer::new(service.clone()))
        .add_service(PolicyServiceServer::new(service.clone()))
        .add_service(EntityServiceServer::new(service.clone()))
        .add_service(AuthorizationServiceServer::new(service))
        .serve_with_shutdown(addr, async {
            let _ = tokio::signal::ctrl_c().await;
            info!("Shutdown signal received, stopping gRPC server");
        })
        .await?;

    Ok(())
}
