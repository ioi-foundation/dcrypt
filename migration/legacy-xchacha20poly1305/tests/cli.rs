#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const ACKNOWLEDGEMENT: &str = "dcrypt-v0.5.0-through-v1.2.3-custom-xchacha20poly1305";
const NONCE_HEX: &str = "242424242424242424242424242424242424242424242424";
const NONCE_BASE64: &str = "JCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk";
const SERIALIZED_KEY_UPPERCASE: &str =
    "DCRYPT-CHACHA20POLY1305-KEY:QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=";
const SERIALIZED_KEY_LOWERCASE: &str =
    "dcrypt-CHACHA20POLY1305-KEY:QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=";
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

    fn staging_files(&self) -> Vec<PathBuf> {
        fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".dcrypt-xchacha-migration-"))
            })
            .collect()
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary() -> Command {
    Command::new(env!(
        "CARGO_BIN_EXE_dcrypt-legacy-xchacha20poly1305-migration"
    ))
}

fn raw_command(directory: &Path, acknowledgement: &str, ciphertext: &[u8]) -> (Command, PathBuf) {
    let key = directory.join("key.bin");
    let input = directory.join("ciphertext.bin");
    let output = directory.join("plaintext.bin");
    fs::write(&key, [0x42; 32]).unwrap();
    fs::write(&input, ciphertext).unwrap();

    let mut command = binary();
    command.args([
        "--acknowledge-format",
        acknowledgement,
        "--key-file",
        key.to_str().unwrap(),
        "--nonce-hex",
        NONCE_HEX,
        "--ciphertext-file",
        input.to_str().unwrap(),
        "--output-file",
        output.to_str().unwrap(),
    ]);
    (command, output)
}

fn invoke(directory: &Path, acknowledgement: &str, ciphertext: &[u8]) -> (Output, PathBuf) {
    let (mut command, output) = raw_command(directory, acknowledgement, ciphertext);
    (command.output().unwrap(), output)
}

#[test]
fn authenticated_migration_creates_a_new_private_output_without_residue() {
    let directory = TestDirectory::new();
    let (result, output) = invoke(&directory.0, ACKNOWLEDGEMENT, &CIPHERTEXT);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(&output).unwrap(),
        b"Extended nonce allows for random nonces"
    );
    assert!(directory.staging_files().is_empty());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(output).unwrap().permissions().mode() & 0o077,
            0
        );
    }
}

#[test]
fn serialized_key_and_base64_nonce_are_strictly_supported() {
    // Both exact forms appeared in released artifacts. In particular, the
    // published 1.0.0 archive still used uppercase even though tagged 1.0.0
    // source had already moved to lowercase.
    for serialized_key in [SERIALIZED_KEY_UPPERCASE, SERIALIZED_KEY_LOWERCASE] {
        let directory = TestDirectory::new();
        let key = directory.0.join("key.txt");
        let input = directory.0.join("ciphertext.bin");
        let output = directory.0.join("plaintext.bin");
        fs::write(&key, format!("{serialized_key}\r\n")).unwrap();
        fs::write(&input, CIPHERTEXT).unwrap();

        let result = binary()
            .args([
                "--acknowledge-format",
                ACKNOWLEDGEMENT,
                "--serialized-key-file",
                key.to_str().unwrap(),
                "--nonce-base64",
                NONCE_BASE64,
                "--ciphertext-file",
                input.to_str().unwrap(),
                "--output-file",
                output.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            fs::read(output).unwrap(),
            b"Extended nonce allows for random nonces"
        );
        assert!(directory.staging_files().is_empty());
    }
}

#[test]
fn malformed_legacy_serializations_are_rejected_before_output_creation() {
    let directory = TestDirectory::new();
    let key = directory.0.join("key.txt");
    let input = directory.0.join("ciphertext.bin");
    let output = directory.0.join("plaintext.bin");
    fs::write(
        &key,
        SERIALIZED_KEY_LOWERCASE.replacen("dcrypt", "Dcrypt", 1),
    )
    .unwrap();
    fs::write(&input, CIPHERTEXT).unwrap();

    let result = binary()
        .args([
            "--acknowledge-format",
            ACKNOWLEDGEMENT,
            "--serialized-key-file",
            key.to_str().unwrap(),
            "--nonce-base64",
            NONCE_BASE64,
            "--ciphertext-file",
            input.to_str().unwrap(),
            "--output-file",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());

    fs::write(&key, SERIALIZED_KEY_LOWERCASE).unwrap();
    let result = binary()
        .args([
            "--acknowledge-format",
            ACKNOWLEDGEMENT,
            "--serialized-key-file",
            key.to_str().unwrap(),
            "--nonce-base64",
            "not-base64",
            "--ciphertext-file",
            input.to_str().unwrap(),
            "--output-file",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());
}

#[test]
fn format_acknowledgement_ciphertext_authentication_and_no_clobber_fail_closed() {
    let directory = TestDirectory::new();
    let (wrong_format, output) = invoke(&directory.0, "standard-xchacha", &CIPHERTEXT);
    assert!(!wrong_format.status.success());
    assert!(!output.exists());

    let mut tampered = CIPHERTEXT;
    tampered[0] ^= 1;
    let (authentication_failure, output) = invoke(&directory.0, ACKNOWLEDGEMENT, &tampered);
    assert!(!authentication_failure.status.success());
    assert!(!output.exists());

    fs::write(&output, b"do not overwrite").unwrap();
    let (existing_output, output) = invoke(&directory.0, ACKNOWLEDGEMENT, &CIPHERTEXT);
    assert!(!existing_output.status.success());
    assert_eq!(fs::read(output).unwrap(), b"do not overwrite");
    assert!(directory.staging_files().is_empty());
}

#[test]
fn bounded_key_read_rejects_short_overlong_large_and_non_regular_inputs() {
    for (name, length) in [("short", 31), ("overlong", 33)] {
        let directory = TestDirectory::new();
        let (mut command, output) = raw_command(&directory.0, ACKNOWLEDGEMENT, &CIPHERTEXT);
        fs::write(directory.0.join("key.bin"), vec![0x42; length]).unwrap();
        let result = command.output().unwrap();
        assert!(!result.status.success(), "{name}");
        assert!(!output.exists(), "{name}");
    }

    let directory = TestDirectory::new();
    let (mut command, output) = raw_command(&directory.0, ACKNOWLEDGEMENT, &CIPHERTEXT);
    fs::File::create(directory.0.join("key.bin"))
        .unwrap()
        .set_len(16 * 1024 * 1024)
        .unwrap();
    let result = command.output().unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());

    let directory = TestDirectory::new();
    let (mut command, output) = raw_command(&directory.0, ACKNOWLEDGEMENT, &CIPHERTEXT);
    fs::remove_file(directory.0.join("key.bin")).unwrap();
    fs::create_dir(directory.0.join("key.bin")).unwrap();
    let result = command.output().unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());
}

#[test]
fn duplicate_and_mixed_format_options_are_rejected() {
    let directory = TestDirectory::new();
    let (mut duplicate, output) = raw_command(&directory.0, ACKNOWLEDGEMENT, &CIPHERTEXT);
    duplicate.args(["--output-file", output.to_str().unwrap()]);
    let result = duplicate.output().unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());

    let directory = TestDirectory::new();
    let serialized = directory.0.join("serialized-key.txt");
    fs::write(&serialized, SERIALIZED_KEY_LOWERCASE).unwrap();
    let (mut mixed_key, output) = raw_command(&directory.0, ACKNOWLEDGEMENT, &CIPHERTEXT);
    mixed_key.args(["--serialized-key-file", serialized.to_str().unwrap()]);
    let result = mixed_key.output().unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());

    let directory = TestDirectory::new();
    let (mut mixed_nonce, output) = raw_command(&directory.0, ACKNOWLEDGEMENT, &CIPHERTEXT);
    mixed_nonce.args(["--nonce-base64", NONCE_BASE64]);
    let result = mixed_nonce.output().unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());
}

#[test]
fn help_is_successful_only_when_standalone() {
    let output = binary().arg("--help").output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("--acknowledge-format"));

    let directory = TestDirectory::new();
    let (mut appended_help, plaintext) = raw_command(&directory.0, ACKNOWLEDGEMENT, &CIPHERTEXT);
    appended_help.arg("--help");
    let result = appended_help.output().unwrap();
    assert!(!result.status.success());
    assert!(!plaintext.exists());

    let output = binary().args(["--key-file", "--help"]).output().unwrap();
    assert!(!output.status.success());
}
