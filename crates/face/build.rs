//! Compiles the C++ shim and links dlib through pkg-config.

fn main() {
    // The static shim must come before dlib on the linker command line.
    // Print the dlib flags after cxx-build prints the shim.
    let dlib = pkg_config::Config::new()
        .atleast_version("19.24")
        .cargo_metadata(false)
        .probe("dlib-1")
        .unwrap_or_else(|error| panic!("dlib is required: {error}"));

    cxx_build::bridge("src/lib.rs")
        .file("src/engine.cc")
        .includes(&dlib.include_paths)
        .std("c++17")
        // The dlib network is slow without optimization, also in test builds.
        .opt_level(2)
        .compile("pam-biometrics-face");

    for path in &dlib.link_paths {
        println!("cargo:rustc-link-search=native={}", path.display());
    }
    for library in &dlib.libs {
        println!("cargo:rustc-link-lib={library}");
    }
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/engine.cc");
    println!("cargo:rerun-if-changed=src/engine.h");
}
