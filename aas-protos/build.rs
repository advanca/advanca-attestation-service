fn main() {
    //let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = "src/";
    let modules = &[
        ("protos/aas", "aas"),
    ];
    for (dir, package) in modules {
        let out_dir = format!("{}/{}", out_dir, package);
        let files: Vec<_> = walkdir::WalkDir::new(format!("{}", dir))
            .into_iter()
            .filter_map(|p| {
                let dent = p.expect("Error happened when search protos");
                if !dent.file_type().is_file() {
                    return None;
                }
                // rust-protobuf is bad at dealing with path, keep it the same style.
                Some(format!("{}", dent.path().display()).replace('\\', "/"))
            })
            .collect();
        protobuf_build::Builder::new()
            .includes(&["protos".to_owned()])
            .files(&files)
            .out_dir(&out_dir)
            .generate();
    }
}
