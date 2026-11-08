pub mod auth;
pub mod authzen;
pub mod authzen_grpc;
pub mod cedar_engine;
pub mod config;
pub mod error;
pub mod grpc;
pub mod http;
pub mod models;
pub mod store;

/// Generated protobuf/gRPC types for the RRM management & authorization API.
#[allow(unused_qualifications, clippy::all, clippy::pedantic)]
pub mod pb {
    tonic::include_proto!("rrm.v1");
}

/// Generated protobuf/gRPC types for the `OpenID` `AuthZEN` authorization API.
#[allow(unused_qualifications, clippy::all, clippy::pedantic)]
pub mod authzen_pb {
    tonic::include_proto!("authzen.authorization.v1");
}
