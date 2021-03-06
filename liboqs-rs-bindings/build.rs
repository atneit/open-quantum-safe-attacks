extern crate bindgen;

use std::env;
use std::path::{Path, PathBuf};

fn main() {
    // Tell cargo to tell rustc to link the local oqs
    // shared library.
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let path_l = Path::new(&dir).join("liboqs/build/lib/");
    let path_i = Path::new(&dir).join("liboqs/build/include/");
    let path_i = path_i.display();
    let path_l = path_l.display();
    println!("cargo:rustc-link-search={}", path_l);
    println!("cargo:rustc-link-lib=static=oqs");
    println!("cargo:rustc-link-lib=crypto");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // extra include paths
        .clang_arg(format!("-I{}", path_i))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
