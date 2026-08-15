//! Manual diagnostic: times each OS-keyring operation separately.
//! `cargo run --example keyring_probe`
use hearth_vault::hsm::{SecretBackend, os_keyring::OsKeyringBackend};
use std::time::Instant;

fn main() {
    let t = Instant::now();
    let avail = OsKeyringBackend::is_available();
    println!("is_available() = {avail} in {:?}", t.elapsed());
    if !avail {
        return;
    }
    let b = OsKeyringBackend::new();
    let t = Instant::now();
    match b.seal(b"probe-value", "hearth-probe") {
        Ok(blob) => {
            println!("seal ok in {:?}", t.elapsed());
            let t = Instant::now();
            println!(
                "unseal {:?} in {:?}",
                b.unseal(&blob, "hearth-probe").is_ok(),
                t.elapsed()
            );
        }
        Err(e) => println!("seal FAILED in {:?}: {e}", t.elapsed()),
    }
}
