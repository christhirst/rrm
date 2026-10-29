fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc_path = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: build.rs runs single-threaded before compilation of this crate.
    unsafe {
        std::env::set_var("PROTOC", protoc_path);
    }

    println!("cargo:rerun-if-changed=proto/rrm/v1/rrm.proto");
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/rrm/v1/rrm.proto"], &["proto"])?;

    Ok(())
}
