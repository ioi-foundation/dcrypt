#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const CIPHERTEXT: [u8; 55] = [
    0x67, 0x2c, 0x3b, 0x97, 0xcd, 0x47, 0x79, 0xf4, 0x49, 0xbd, 0x39, 0xba, 0x13, 0xbf, 0x4d, 0x21,
    0x36, 0x22, 0x06, 0x74, 0x76, 0xb0, 0xcb, 0xfc, 0x0e, 0x05, 0x3d, 0x1d, 0x9f, 0xb9, 0xc7, 0x90,
    0xe6, 0x96, 0xfe, 0x06, 0x63, 0x67, 0xd0, 0x75, 0x37, 0x4e, 0x3b, 0xe5, 0x12, 0x0e, 0x61, 0x6b,
    0x50, 0x4e, 0xd6, 0x99, 0x8f, 0xaf, 0xa6,
];

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "dcrypt-legacy-xchacha-cli-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn invoke(directory: &Path, provenance: &str, ciphertext: &[u8]) -> (Output, PathBuf) {
    let key = directory.join("key.bin");
    let input = directory.join("ciphertext.bin");
    let output = directory.join("plaintext.bin");
    fs::write(&key, [0x42; 32]).unwrap();
    fs::write(&input, ciphertext).unwrap();

    let result = Command::new(env!(
        "CARGO_BIN_EXE_dcrypt-legacy-xchacha20poly1305-migration"
    ))
    .args([
        "--provenance",
        provenance,
        "--key-file",
        key.to_str().unwrap(),
        "--nonce-hex",
        "242424242424242424242424242424242424242424242424",
        "--ciphertext-file",
        input.to_str().unwrap(),
        "--output-file",
        output.to_str().unwrap(),
    ])
    .output()
    .unwrap();
    (result, output)
}

#[test]
fn authenticated_migration_creates_a_new_private_output() {
    let directory = TestDirectory::new();
    let (result, output) = invoke(
        &directory.0,
        "dcrypt-v1-custom-xchacha20poly1305",
        &CIPHERTEXT,
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(&output).unwrap(),
        b"Extended nonce allows for random nonces"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn provenance_authentication_and_no_clobber_fail_closed() {
    let directory = TestDirectory::new();
    let (wrong_provenance, output) = invoke(&directory.0, "standard-xchacha", &CIPHERTEXT);
    assert!(!wrong_provenance.status.success());
    assert!(!output.exists());

    let mut tampered = CIPHERTEXT;
    tampered[0] ^= 1;
    let (authentication_failure, output) = invoke(
        &directory.0,
        "dcrypt-v1-custom-xchacha20poly1305",
        &tampered,
    );
    assert!(!authentication_failure.status.success());
    assert!(!output.exists());

    fs::write(&output, b"do not overwrite").unwrap();
    let (existing_output, output) = invoke(
        &directory.0,
        "dcrypt-v1-custom-xchacha20poly1305",
        &CIPHERTEXT,
    );
    assert!(!existing_output.status.success());
    assert_eq!(fs::read(output).unwrap(), b"do not overwrite");
}

#[test]
fn help_is_successful_and_does_not_touch_files() {
    let output = Command::new(env!(
        "CARGO_BIN_EXE_dcrypt-legacy-xchacha20poly1305-migration"
    ))
    .arg("--help")
    .output()
    .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("--provenance"));
}
