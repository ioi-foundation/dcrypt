//! Downstream compile and behavior fixtures for the v4 error API migration.

use dcrypt_algorithms::error::Error as PrimitiveError;
use dcrypt_api::error::{Error, Result};
use dcrypt_symmetric::error::{from_io_error, from_primitive_error};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DOWNSTREAM_CHECK_TIMEOUT: Duration = Duration::from_secs(120);

struct DownstreamFixture {
    root: PathBuf,
}

impl DownstreamFixture {
    fn create() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must follow the Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "dcrypt-error-api-v4-{}-{nonce}",
            std::process::id()
        ));
        assert!(!root.exists(), "temporary fixture path unexpectedly exists");
        fs::create_dir_all(root.join("src")).expect("create downstream fixture");
        Self { root }
    }

    fn write_manifest(&self, project_root: &Path) {
        let manifest = format!(
            r#"[package]
name = "dcrypt-error-api-v4-downstream"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
dcrypt-api = {{ path = "{}" }}
dcrypt-algorithms = {{ path = "{}" }}
dcrypt-symmetric = {{ path = "{}" }}
"#,
            toml_path(&project_root.join("crates/api")),
            toml_path(&project_root.join("crates/algorithms")),
            toml_path(&project_root.join("crates/symmetric")),
        );
        fs::write(self.root.join("Cargo.toml"), manifest).expect("write downstream manifest");
    }

    fn write_source(&self, source: &str) {
        fs::write(self.root.join("src/main.rs"), source).expect("write downstream source");
    }

    fn cargo_check(&self, label: &str, locked: bool) -> (bool, String) {
        let stdout_path = self.root.join(format!("{label}.stdout"));
        let stderr_path = self.root.join(format!("{label}.stderr"));
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
        let mut command = Command::new(cargo);
        command
            .arg("check")
            .arg("--offline")
            .arg("--quiet")
            .arg("--manifest-path")
            .arg(self.root.join("Cargo.toml"))
            .env("CARGO_NET_OFFLINE", "true")
            .env("CARGO_TARGET_DIR", self.root.join("target"))
            .env("CARGO_TERM_COLOR", "never")
            .stdout(Stdio::from(
                File::create(&stdout_path).expect("create cargo stdout log"),
            ))
            .stderr(Stdio::from(
                File::create(&stderr_path).expect("create cargo stderr log"),
            ));
        if locked {
            command.arg("--locked");
        }

        let mut child = command.spawn().expect("start bounded offline cargo check");
        let deadline = Instant::now() + DOWNSTREAM_CHECK_TIMEOUT;
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll cargo check") {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().expect("terminate timed-out cargo check");
                child.wait().expect("reap timed-out cargo check");
                panic!("offline downstream cargo check exceeded {DOWNSTREAM_CHECK_TIMEOUT:?}");
            }
            thread::sleep(Duration::from_millis(50));
        };
        let stderr = fs::read_to_string(stderr_path).expect("read cargo stderr log");
        (status.success(), stderr)
    }
}

impl Drop for DownstreamFixture {
    fn drop(&mut self) {
        let temp_root = std::env::temp_dir();
        let safe_name = self
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("dcrypt-error-api-v4-"));
        if self.root.parent() == Some(temp_root.as_path()) && safe_name {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn toml_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn other_error(context: &'static str) -> Error {
    Error::Other {
        context,
        message: String::new(),
    }
}

fn propagate(result: Result<u8>) -> Result<u8> {
    Ok(result?)
}

#[test]
fn standard_result_control_flow_replaces_compatibility_extensions() {
    let success: core::result::Result<u8, &'static str> = Ok(7);
    assert!(success.is_ok());
    assert!(!success.is_err());
    assert_eq!(success.map_or_else(|_| 0, |value| value + 1), 8);

    let failure: core::result::Result<u8, &'static str> = Err("source failure");
    assert!(failure.is_err());
    assert_eq!(failure.map_or_else(|_| 9, |value| value), 9);
}

#[test]
fn errors_are_propagated_or_recorded_in_caller_owned_state() {
    let propagated = propagate(Err(other_error("source"))).unwrap_err();
    assert!(matches!(
        propagated,
        Error::Other {
            context: "source",
            ..
        }
    ));

    let mut diagnostic = None;
    let failure: core::result::Result<u8, &'static str> = Err("local diagnostic");
    let fallback = failure.unwrap_or_else(|error| {
        diagnostic = Some(error);
        42
    });
    assert_eq!(fallback, 42);
    assert_eq!(diagnostic, Some("local diagnostic"));
}

#[test]
fn standard_error_mapping_preserves_v4_replacement_semantics() {
    let replaced: core::result::Result<(), Error> =
        Err::<(), _>("discarded source").map_err(|_| other_error("replacement"));
    assert!(matches!(
        replaced.unwrap_err(),
        Error::Other {
            context: "replacement",
            ..
        }
    ));

    let contextual: Result<()> =
        Err::<(), _>(other_error("source")).map_err(|error| error.with_context("operation"));
    assert!(matches!(
        contextual.unwrap_err(),
        Error::Other {
            context: "operation",
            ..
        }
    ));

    let messaged: Result<()> = Err::<(), _>(other_error("operation"))
        .map_err(|error| error.with_message("additional detail"));
    assert!(matches!(
        messaged.unwrap_err(),
        Error::Other { message, .. } if message == "additional detail"
    ));
}

#[test]
fn symmetric_converters_replace_result_extension_methods() {
    let primitive = Err::<(), _>(PrimitiveError::Authentication {
        algorithm: "migration fixture",
    })
    .map_err(from_primitive_error)
    .unwrap_err();
    assert!(matches!(
        primitive,
        Error::AuthenticationFailed {
            context: "migration fixture",
            ..
        }
    ));

    let io_error = Err::<(), _>(io::Error::other("migration fixture"))
        .map_err(from_io_error)
        .unwrap_err();
    assert!(matches!(
        io_error,
        Error::Other {
            context: "I/O operation",
            ..
        }
    ));
}

#[test]
fn downstream_replacements_compile_and_legacy_surface_fails_closed() {
    let project_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tests workspace must be below the project root");
    let fixture = DownstreamFixture::create();
    fixture.write_manifest(project_root);

    fixture.write_source(
        r#"
use dcrypt_algorithms::error::Error as PrimitiveError;
use dcrypt_api::error::{Error, Result};
use dcrypt_symmetric::error::{from_io_error, from_primitive_error};

fn other(context: &'static str) -> Error {
    Error::Other { context, message: String::new() }
}

fn propagate(result: Result<u8>) -> Result<u8> {
    Ok(result?)
}

fn main() -> Result<()> {
    let _ = propagate(Ok(7))?;
    let inspected = Ok::<u8, Error>(7);
    let _ = inspected.is_ok();
    let _ = inspected.is_err();
    let _ = inspected.map_or_else(|_| 0, |value| value);
    let _: Result<()> = Err::<(), _>(other("source"))
        .map_err(|error| error.with_context("operation"));
    let _: Result<()> = Err::<(), _>(other("operation"))
        .map_err(|error| error.with_message("detail"));
    let _ = Err::<(), _>(PrimitiveError::Authentication { algorithm: "fixture" })
        .map_err(from_primitive_error);
    let _ = Err::<(), _>(std::io::Error::other("fixture")).map_err(from_io_error);
    Ok(())
}
"#,
    );
    let (passed, pass_stderr) = fixture.cargo_check("replacement-pass", false);
    assert!(
        passed,
        "replacement-only downstream fixture failed:\n{pass_stderr}"
    );

    fixture.write_source(
        r#"
use dcrypt_api::error::registry::{ErrorRegistry, ERROR_REGISTRY};
use dcrypt_api::error::traits::{
    ConstantTimeResult, ErrorRegistryExt, ResultExt, SecureErrorHandling,
};
use dcrypt_symmetric::error::SymmetricResultExt;

fn main() {
    let _ = ErrorRegistry::new();
    let _ = &ERROR_REGISTRY;
    let _ = Ok::<u8, &'static str>(7).ct_is_ok();
    let _ = Err::<u8, &'static str>("error").ct_is_err();
    let _ = Ok::<u8, &'static str>(7).ct_map(|value| value, |_| 0);
    let _ = Err::<u8, &'static str>("error").wrap_err(|| ());
    let _ = Err::<u8, &'static str>("error").with_context("operation");
    let _ = Err::<u8, &'static str>("error").with_message("detail");
    let _ = Err::<u8, &'static str>("error")
        .unwrap_or_record_with(0, || "diagnostic");
    let _ = Err::<u8, &'static str>("error").secure_unwrap(0, || "diagnostic");
    let _ = Err::<(), _>(std::io::Error::other("fixture")).map_io_err();
    let _ = Err::<(), _>(dcrypt_algorithms::error::Error::Authentication {
        algorithm: "fixture",
    })
    .map_primitive_err();
}
"#,
    );
    let (passed, fail_stderr) = fixture.cargo_check("legacy-fail", true);
    assert!(
        !passed,
        "legacy downstream fixture unexpectedly compiled successfully"
    );
    for removed_import in [
        "ErrorRegistry",
        "ERROR_REGISTRY",
        "ConstantTimeResult",
        "ErrorRegistryExt",
        "ResultExt",
        "SecureErrorHandling",
        "SymmetricResultExt",
    ] {
        let diagnostic = format!("no `{removed_import}` in");
        assert!(
            fail_stderr.contains(&diagnostic),
            "legacy fixture stderr omitted import diagnostic {diagnostic}:\n{fail_stderr}"
        );
    }
    for removed_method in [
        "ct_is_ok",
        "ct_is_err",
        "ct_map",
        "wrap_err",
        "with_context",
        "with_message",
        "unwrap_or_record_with",
        "secure_unwrap",
        "map_io_err",
        "map_primitive_err",
    ] {
        let diagnostic = format!("no method named `{removed_method}`");
        assert!(
            fail_stderr.contains(&diagnostic),
            "legacy fixture stderr omitted method diagnostic {diagnostic}:\n{fail_stderr}"
        );
    }
}
