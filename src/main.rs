use std::net::SocketAddr;

use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;

use rrm::auth::OAuthValidator;
use rrm::authzen_grpc::AuthzenGrpcService;
use rrm::authzen_pb::authorization_service_server::AuthorizationServiceServer as AuthzenAuthorizationServiceServer;
use rrm::config::AppConfig;
use rrm::grpc::RrmService;
use rrm::http::{HttpAppState, create_http_router};
use rrm::pb::{
    admin_service_server::AdminServiceServer,
    authorization_service_server::AuthorizationServiceServer,
    entity_service_server::EntityServiceServer, policy_service_server::PolicyServiceServer,
};
use rrm::store::Store;

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => {
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("Shutdown signal received, stopping servers");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = AppConfig::load()?;
    let grpc_addr: SocketAddr = cfg.server.listen_addr.parse()?;
    let http_addr: SocketAddr = cfg.server.http_listen_addr.parse()?;

    info!(
        endpoint = %cfg.surrealdb.endpoint,
        namespace = %cfg.surrealdb.namespace,
        database = %cfg.surrealdb.database,
        "Connecting to SurrealDB"
    );
    let store = Store::connect(&cfg.surrealdb).await?;

    let service = RrmService::new(store.clone(), cfg.auth.admin_token.clone());
    let authzen_service = AuthzenGrpcService::new(store.clone(), cfg.auth.admin_token.clone());

    info!(%grpc_addr, "Starting RRM Cedar Policy & SurrealDB gRPC Server");
    info!(%http_addr, "Starting RRM AuthZEN HTTP REST Server");

    let grpc_server = Server::builder()
        .add_service(AdminServiceServer::new(service.clone()))
        .add_service(PolicyServiceServer::new(service.clone()))
        .add_service(EntityServiceServer::new(service.clone()))
        .add_service(AuthorizationServiceServer::new(service))
        .add_service(AuthzenAuthorizationServiceServer::new(authzen_service))
        .serve_with_shutdown(grpc_addr, shutdown_signal());

    let oauth_validator = OAuthValidator::new(cfg.auth.oauth);
    let http_app_state = HttpAppState {
        store,
        admin_token: cfg.auth.admin_token,
        oauth_validator,
        default_base_url: format!("http://{http_addr}"),
    };
    let http_router = create_http_router(http_app_state);

    let http_listener = tokio::net::TcpListener::bind(http_addr).await?;
    let http_server = axum::serve(http_listener, http_router)
        .with_graceful_shutdown(shutdown_signal());

    tokio::select! {
        res = grpc_server => {
            if let Err(e) = res {
                tracing::error!("gRPC server error: {e}");
            }
        }
        res = http_server => {
            if let Err(e) = res {
                tracing::error!("HTTP server error: {e}");
            }
        }
    }

    Ok(())
}

