use protoc_grpcio;

fn main() {
    let proto_root = "protos/";
    println!("cargo:rerun-if-changed={}", proto_root);
    protoc_grpcio::compile_grpc_protos(&["aas.proto"], &[proto_root], &"src/", None)
        .expect("Failed to compile gRPC definitions!");
}
