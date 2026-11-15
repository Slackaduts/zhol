fn main() {
    // On macOS a Python extension module (cdylib + pyo3 `extension-module`) must be
    // linked with `-undefined dynamic_lookup`: the `_Py*` symbols are resolved at
    // load time by the hosting interpreter, not at link time. Without this the link
    // fails with "undefined symbols _Py...". Scoped to the cdylib and the `python`
    // feature so normal lib/example/binary builds are unaffected. (Linux/Windows
    // need nothing here.)
    let is_macos = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos");
    let python_feature = std::env::var_os("CARGO_FEATURE_PYTHON").is_some();
    if is_macos && python_feature {
        println!("cargo:rustc-cdylib-link-arg=-undefined");
        println!("cargo:rustc-cdylib-link-arg=dynamic_lookup");
    }
}
