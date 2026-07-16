fn main() -> Result<(), Box<dyn std::error::Error>> {
    // protox compiles .proto in pure Rust — no system protoc dependency.
    let fds = protox::compile(["../../protocol/messages.proto"], ["../../protocol"])?;
    prost_build::Config::new().compile_fds(fds)?;
    println!("cargo:rerun-if-changed=../../protocol/messages.proto");
    Ok(())
}
