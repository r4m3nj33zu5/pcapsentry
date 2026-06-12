use std::process::Command;
use std::path::Path;

fn main() {
    let frontend_dir = Path::new("../frontend");
    if frontend_dir.exists() {
        // Watch every input that affects the built bundle so stale dist/
        // artifacts are never embedded into the binary.
        println!("cargo:rerun-if-changed=../frontend/src");
        println!("cargo:rerun-if-changed=../frontend/package.json");
        println!("cargo:rerun-if-changed=../frontend/package-lock.json");
        println!("cargo:rerun-if-changed=../frontend/vite.config.js");
        println!("cargo:rerun-if-changed=../frontend/index.html");

        let npm_install = Command::new("npm")
            .args(["install"])
            .current_dir(frontend_dir)
            .status();

        match npm_install {
            Ok(status) if status.success() => {}
            Ok(status) => panic!("npm install failed with status: {}", status),
            Err(e) => panic!("Failed to run npm install: {}", e),
        }

        let npm_build = Command::new("npm")
            .args(["run", "build"])
            .current_dir(frontend_dir)
            .status();

        match npm_build {
            Ok(status) if status.success() => {}
            Ok(status) => panic!("npm run build failed with status: {}", status),
            Err(e) => panic!("Failed to run npm run build: {}", e),
        }
    }
}
