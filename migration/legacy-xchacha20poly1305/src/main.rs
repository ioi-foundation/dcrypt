#![forbid(unsafe_code)]

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use dcrypt_internal::zeroing::{Zeroize, Zeroizing};
use dcrypt_legacy_xchacha20poly1305_migration::{decrypt_legacy, REQUIRED_FORMAT_ACKNOWLEDGEMENT};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_STAGING_ATTEMPTS: u64 = 64;
const LEGACY_KEY_PREFIX: &[u8] = b"dcrypt-CHACHA20POLY1305-KEY:";
const LEGACY_KEY_BASE64_LENGTH: usize = 44;
const MAX_SERIALIZED_KEY_FILE_LENGTH: usize =
    LEGACY_KEY_PREFIX.len() + LEGACY_KEY_BASE64_LENGTH + 2;
static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

enum KeyInput {
    Raw(PathBuf),
    Serialized(PathBuf),
}

struct Arguments {
    key_input: KeyInput,
    nonce: [u8; 24],
    ciphertext_file: PathBuf,
    output_file: PathBuf,
    aad_file: Option<PathBuf>,
}

enum ParseOutcome {
    Run(Arguments),
    Help,
}

fn usage() -> &'static str {
    "usage: dcrypt-legacy-xchacha20poly1305-migration \
--acknowledge-format dcrypt-v0.7.0-pre-through-v1.2.3-custom-xchacha20poly1305 \
(--key-file RAW_KEY | --serialized-key-file LEGACY_KEY) \
(--nonce-hex 48_HEX_CHARS | --nonce-base64 LEGACY_NONCE) \
--ciphertext-file INPUT --output-file NEW_OUTPUT [--aad-file AAD]"
}

fn decode_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("nonce contains a non-hexadecimal character".into()),
    }
}

fn decode_nonce(value: &str) -> Result<[u8; 24], String> {
    let bytes = value.as_bytes();
    if bytes.len() != 48 {
        return Err("nonce must contain exactly 48 hexadecimal characters".into());
    }
    let mut nonce = [0u8; 24];
    for (index, output) in nonce.iter_mut().enumerate() {
        *output = (decode_nibble(bytes[2 * index])? << 4) | decode_nibble(bytes[2 * index + 1])?;
    }
    Ok(nonce)
}

fn decode_nonce_base64(value: &str) -> Result<[u8; 24], String> {
    let mut nonce = [0u8; 24];
    let decoded = BASE64_STANDARD
        .decode_slice(value.as_bytes(), &mut nonce)
        .map_err(|_| "legacy nonce must be valid standard base64".to_string())?;
    if decoded != nonce.len() {
        return Err("legacy nonce base64 must decode to exactly 24 bytes".into());
    }
    Ok(nonce)
}

fn next_value(arguments: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    arguments
        .next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn reject_duplicate<T>(slot: &Option<T>, flag: &str) -> Result<(), String> {
    if slot.is_some() {
        Err(format!("{flag} may be supplied only once"))
    } else {
        Ok(())
    }
}

fn parse_arguments(arguments: impl IntoIterator<Item = String>) -> Result<ParseOutcome, String> {
    let arguments: Vec<String> = arguments.into_iter().collect();
    if arguments.len() == 1 && matches!(arguments[0].as_str(), "-h" | "--help") {
        return Ok(ParseOutcome::Help);
    }

    let mut arguments = arguments.into_iter();
    let mut acknowledgement = None;
    let mut key_input = None;
    let mut nonce = None;
    let mut ciphertext_file = None;
    let mut output_file = None;
    let mut aad_file = None;

    while let Some(flag) = arguments.next() {
        match flag.as_str() {
            "--acknowledge-format" => {
                reject_duplicate(&acknowledgement, &flag)?;
                acknowledgement = Some(next_value(&mut arguments, &flag)?);
            }
            "--key-file" => {
                reject_duplicate(&key_input, "key input")?;
                key_input = Some(KeyInput::Raw(PathBuf::from(next_value(
                    &mut arguments,
                    &flag,
                )?)));
            }
            "--serialized-key-file" => {
                reject_duplicate(&key_input, "key input")?;
                key_input = Some(KeyInput::Serialized(PathBuf::from(next_value(
                    &mut arguments,
                    &flag,
                )?)));
            }
            "--nonce-hex" => {
                reject_duplicate(&nonce, "nonce input")?;
                let value = next_value(&mut arguments, &flag)?;
                nonce = Some(decode_nonce(&value)?);
            }
            "--nonce-base64" => {
                reject_duplicate(&nonce, "nonce input")?;
                let value = next_value(&mut arguments, &flag)?;
                nonce = Some(decode_nonce_base64(&value)?);
            }
            "--ciphertext-file" => {
                reject_duplicate(&ciphertext_file, &flag)?;
                ciphertext_file = Some(PathBuf::from(next_value(&mut arguments, &flag)?));
            }
            "--output-file" => {
                reject_duplicate(&output_file, &flag)?;
                output_file = Some(PathBuf::from(next_value(&mut arguments, &flag)?));
            }
            "--aad-file" => {
                reject_duplicate(&aad_file, &flag)?;
                aad_file = Some(PathBuf::from(next_value(&mut arguments, &flag)?));
            }
            "-h" | "--help" => return Err("--help must be used by itself".into()),
            _ => return Err(format!("unknown option: {flag}\n{}", usage())),
        }
    }

    if acknowledgement.as_deref() != Some(REQUIRED_FORMAT_ACKNOWLEDGEMENT) {
        return Err(format!(
            "refusing migration without --acknowledge-format {REQUIRED_FORMAT_ACKNOWLEDGEMENT}"
        ));
    }
    Ok(ParseOutcome::Run(Arguments {
        key_input: key_input.ok_or_else(|| {
            "exactly one of --key-file or --serialized-key-file is required".to_string()
        })?,
        nonce: nonce.ok_or_else(|| {
            "exactly one of --nonce-hex or --nonce-base64 is required".to_string()
        })?,
        ciphertext_file: ciphertext_file
            .ok_or_else(|| "--ciphertext-file is required".to_string())?,
        output_file: output_file.ok_or_else(|| "--output-file is required".to_string())?,
        aad_file,
    }))
}

fn open_regular_file(path: &Path, label: &str) -> Result<File, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("unable to inspect {label} file: {error}"))?;
    if !metadata.is_file() {
        return Err(format!("{label} path must identify a regular file"));
    }

    let file = File::open(path).map_err(|error| format!("unable to open {label} file: {error}"))?;
    if !file
        .metadata()
        .map_err(|error| format!("unable to inspect opened {label} file: {error}"))?
        .is_file()
    {
        return Err(format!("{label} path must identify a regular file"));
    }
    Ok(file)
}

fn read_raw_key(path: &Path) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut file = open_regular_file(path, "key")?;
    let mut key = Zeroizing::new([0u8; 32]);
    file.read_exact(key.as_mut())
        .map_err(|_| "key file must contain exactly 32 raw bytes".to_string())?;

    let mut trailing = Zeroizing::new([0u8; 1]);
    loop {
        match file.read(trailing.as_mut()) {
            Ok(0) => return Ok(key),
            Ok(_) => return Err("key file must contain exactly 32 raw bytes".into()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("unable to finish reading key file: {error}")),
        }
    }
}

fn read_serialized_key(path: &Path) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut file = open_regular_file(path, "serialized key")?;
    let mut serialized = Zeroizing::new([0u8; MAX_SERIALIZED_KEY_FILE_LENGTH]);
    let mut length = 0;
    while length < serialized.len() {
        match file.read(&mut serialized[length..]) {
            Ok(0) => break,
            Ok(count) => length += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("unable to read serialized key file: {error}")),
        }
    }
    if length == serialized.len() {
        let mut trailing = Zeroizing::new([0u8; 1]);
        loop {
            match file.read(trailing.as_mut()) {
                Ok(0) => break,
                Ok(_) => return Err("serialized key file is too long".into()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(format!(
                        "unable to finish reading serialized key file: {error}"
                    ));
                }
            }
        }
    }

    let mut bytes = &serialized[..length];
    if let Some(without_newline) = bytes.strip_suffix(b"\r\n") {
        bytes = without_newline;
    } else if let Some(without_newline) = bytes.strip_suffix(b"\n") {
        bytes = without_newline;
    }
    let encoded = bytes
        .strip_prefix(LEGACY_KEY_PREFIX)
        .ok_or_else(|| "serialized key file has the wrong legacy prefix".to_string())?;
    if encoded.len() != LEGACY_KEY_BASE64_LENGTH {
        return Err("serialized key must contain exactly one legacy 32-byte key".into());
    }

    let mut key = Zeroizing::new([0u8; 32]);
    let decoded = BASE64_STANDARD
        .decode_slice(encoded, key.as_mut())
        .map_err(|_| "serialized key contains invalid standard base64".to_string())?;
    if decoded != key.len() {
        return Err("serialized key base64 must decode to exactly 32 bytes".into());
    }
    Ok(key)
}

fn read_key(input: &KeyInput) -> Result<Zeroizing<[u8; 32]>, String> {
    match input {
        KeyInput::Raw(path) => read_raw_key(path),
        KeyInput::Serialized(path) => read_serialized_key(path),
    }
}

trait OutputBackend {
    type Writer: Write;

    fn create_private(&self, path: &Path) -> io::Result<Self::Writer>;
    fn sync_file(&self, writer: &Self::Writer) -> io::Result<()>;
    fn publish_without_clobber(&self, staging: &Path, output: &Path) -> io::Result<()>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    fn sync_directory(&self, path: &Path) -> io::Result<()>;
}

struct StdOutputBackend;

impl OutputBackend for StdOutputBackend {
    type Writer = File;

    fn create_private(&self, path: &Path) -> io::Result<Self::Writer> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)
    }

    fn sync_file(&self, writer: &Self::Writer) -> io::Result<()> {
        writer.sync_all()
    }

    fn publish_without_clobber(&self, staging: &Path, output: &Path) -> io::Result<()> {
        fs::hard_link(staging, output)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }

    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            File::open(path)?.sync_all()
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Ok(())
        }
    }
}

fn output_parent(output: &Path) -> &Path {
    output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn staging_path(output: &Path, sequence: u64) -> PathBuf {
    output_parent(output).join(format!(
        ".dcrypt-xchacha-migration-{}-{sequence}.tmp",
        std::process::id()
    ))
}

fn create_staging_file<B: OutputBackend>(
    backend: &B,
    output: &Path,
) -> Result<(PathBuf, B::Writer), String> {
    for _ in 0..MAX_STAGING_ATTEMPTS {
        let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let staging = staging_path(output, sequence);
        match backend.create_private(&staging) {
            Ok(writer) => return Ok((staging, writer)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "unable to create private staging file {}: {error}",
                    staging.display()
                ));
            }
        }
    }
    Err(format!(
        "unable to allocate a private staging file beside {} after {MAX_STAGING_ATTEMPTS} attempts",
        output.display()
    ))
}

fn cleanup_after_failure<B: OutputBackend>(backend: &B, staging: &Path, failure: String) -> String {
    match backend.remove_file(staging) {
        Ok(()) => failure,
        Err(error) if error.kind() == io::ErrorKind::NotFound => failure,
        Err(error) => format!(
            "{failure}; cleanup also failed: plaintext may remain at staging path {}: {error}",
            staging.display()
        ),
    }
}

fn write_private_output_with<B: OutputBackend>(
    backend: &B,
    output: &Path,
    plaintext: &[u8],
) -> Result<(), String> {
    if output.file_name().is_none() {
        return Err("output path must identify a file".into());
    }

    let (staging, mut writer) = create_staging_file(backend, output)?;
    if let Err(error) = writer
        .write_all(plaintext)
        .and_then(|()| backend.sync_file(&writer))
    {
        drop(writer);
        return Err(cleanup_after_failure(
            backend,
            &staging,
            format!("unable to write and synchronize plaintext staging file: {error}"),
        ));
    }
    drop(writer);

    if let Err(error) = backend.publish_without_clobber(&staging, output) {
        let publication_failure = if error.kind() == io::ErrorKind::Unsupported {
            format!(
                "the destination filesystem does not support the required atomic no-clobber hard-link publication for {}; no copy fallback is permitted: {error}",
                output.display()
            )
        } else {
            format!(
                "unable to create new plaintext output {} without clobbering; no copy fallback is permitted: {error}",
                output.display()
            )
        };
        return Err(cleanup_after_failure(
            backend,
            &staging,
            publication_failure,
        ));
    }

    if let Err(error) = backend.remove_file(&staging) {
        return Err(format!(
            "plaintext output was created at {}, but staging cleanup failed; duplicate plaintext may remain at {}: {error}; preserve the original ciphertext and inspect both paths",
            output.display(),
            staging.display()
        ));
    }

    if let Err(error) = backend.sync_directory(output_parent(output)) {
        return Err(format!(
            "plaintext output was created at {}, but its parent directory could not be synchronized: {error}; preserve the original ciphertext and verify the output before continuing",
            output.display()
        ));
    }

    Ok(())
}

fn run(arguments: Arguments) -> Result<(), String> {
    let key = read_key(&arguments.key_input)?;
    let ciphertext = fs::read(&arguments.ciphertext_file)
        .map_err(|error| format!("unable to read ciphertext file: {error}"))?;
    let aad = arguments
        .aad_file
        .as_ref()
        .map(fs::read)
        .transpose()
        .map_err(|error| format!("unable to read AAD file: {error}"))?;
    let mut plaintext = decrypt_legacy(&key, &arguments.nonce, &ciphertext, aad.as_deref())
        .map_err(|_| {
            "authentication failed; input is not verified legacy ciphertext".to_string()
        })?;

    let result = write_private_output_with(&StdOutputBackend, &arguments.output_file, &plaintext);
    plaintext.zeroize();
    result
}

fn environment_arguments() -> Result<Vec<String>, String> {
    env::args_os()
        .skip(1)
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| "all option names and paths must be valid UTF-8".to_string())
        })
        .collect()
}

fn main() {
    match environment_arguments().and_then(parse_arguments) {
        Ok(ParseOutcome::Help) => println!("{}", usage()),
        Ok(ParseOutcome::Run(arguments)) => {
            if let Err(error) = run(arguments) {
                eprintln!("error: {error}");
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_arguments, write_private_output_with, OutputBackend, ParseOutcome};
    use std::cell::{Cell, RefCell};
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};

    #[derive(Default)]
    struct Faults {
        write: bool,
        sync: bool,
        publish: bool,
        unsupported_publish: bool,
        remove: bool,
        directory_sync: bool,
    }

    struct FaultWriter {
        fail: bool,
        returned_partial_write: bool,
    }

    impl Write for FaultWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail && self.returned_partial_write {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "injected write failure",
                ));
            }
            if self.fail {
                self.returned_partial_write = true;
                return Ok(bytes.len().min(3));
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FaultBackend {
        faults: Faults,
        staging: RefCell<Option<PathBuf>>,
        published: Cell<bool>,
        remove_calls: Cell<usize>,
    }

    impl FaultBackend {
        fn new(faults: Faults) -> Self {
            Self {
                faults,
                staging: RefCell::new(None),
                published: Cell::new(false),
                remove_calls: Cell::new(0),
            }
        }
    }

    impl OutputBackend for FaultBackend {
        type Writer = FaultWriter;

        fn create_private(&self, path: &Path) -> io::Result<Self::Writer> {
            self.staging.replace(Some(path.to_path_buf()));
            Ok(FaultWriter {
                fail: self.faults.write,
                returned_partial_write: false,
            })
        }

        fn sync_file(&self, _writer: &Self::Writer) -> io::Result<()> {
            if self.faults.sync {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "injected sync failure",
                ))
            } else {
                Ok(())
            }
        }

        fn publish_without_clobber(&self, _staging: &Path, _output: &Path) -> io::Result<()> {
            if self.faults.unsupported_publish {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "injected unsupported hard link",
                ))
            } else if self.faults.publish {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "injected publish failure",
                ))
            } else {
                self.published.set(true);
                Ok(())
            }
        }

        fn remove_file(&self, _path: &Path) -> io::Result<()> {
            self.remove_calls.set(self.remove_calls.get() + 1);
            if self.faults.remove {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected cleanup failure",
                ))
            } else {
                Ok(())
            }
        }

        fn sync_directory(&self, _path: &Path) -> io::Result<()> {
            if self.faults.directory_sync {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "injected directory sync failure",
                ))
            } else {
                Ok(())
            }
        }
    }

    fn valid_arguments() -> Vec<String> {
        [
            "--acknowledge-format",
            "dcrypt-v0.7.0-pre-through-v1.2.3-custom-xchacha20poly1305",
            "--key-file",
            "key",
            "--nonce-hex",
            "242424242424242424242424242424242424242424242424",
            "--ciphertext-file",
            "ciphertext",
            "--output-file",
            "output",
            "--aad-file",
            "aad",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    #[test]
    fn help_is_only_a_standalone_success_action() {
        assert!(matches!(
            parse_arguments([String::from("--help")]).unwrap(),
            ParseOutcome::Help
        ));

        let mut arguments = valid_arguments();
        arguments.push(String::from("--help"));
        assert_eq!(
            parse_arguments(arguments).err().unwrap(),
            "--help must be used by itself"
        );
    }

    #[test]
    fn every_option_rejects_duplicates() {
        for (flag, value) in [
            ("--acknowledge-format", "anything"),
            ("--key-file", "another-key"),
            ("--serialized-key-file", "serialized-key"),
            (
                "--nonce-hex",
                "000000000000000000000000000000000000000000000000",
            ),
            ("--nonce-base64", "JCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk"),
            ("--ciphertext-file", "another-input"),
            ("--output-file", "another-output"),
            ("--aad-file", "another-aad"),
        ] {
            let mut arguments = valid_arguments();
            arguments.extend([String::from(flag), String::from(value)]);
            let error = parse_arguments(arguments).err().unwrap();
            assert!(
                error.contains("may be supplied only once"),
                "{flag}: {error}"
            );
        }
    }

    #[test]
    fn partial_write_and_cleanup_failures_surface_plaintext_residue() {
        let backend = FaultBackend::new(Faults {
            write: true,
            remove: true,
            ..Faults::default()
        });
        let error =
            write_private_output_with(&backend, Path::new("plaintext"), b"secret").unwrap_err();
        let staging = backend.staging.borrow().clone().unwrap();
        assert!(error.contains("injected write failure"));
        assert!(error.contains("cleanup also failed"));
        assert!(error.contains(&staging.display().to_string()));
        assert!(error.contains("plaintext may remain"));
        assert!(!backend.published.get());
    }

    #[test]
    fn sync_failure_removes_the_unpublished_staging_file() {
        let backend = FaultBackend::new(Faults {
            sync: true,
            ..Faults::default()
        });
        let error =
            write_private_output_with(&backend, Path::new("plaintext"), b"secret").unwrap_err();
        assert!(error.contains("injected sync failure"));
        assert_eq!(backend.remove_calls.get(), 1);
        assert!(!backend.published.get());
        assert!(!error.contains("plaintext may remain"));
    }

    #[test]
    fn publish_failure_and_cleanup_failure_surface_the_staging_path() {
        let backend = FaultBackend::new(Faults {
            publish: true,
            remove: true,
            ..Faults::default()
        });
        let error =
            write_private_output_with(&backend, Path::new("plaintext"), b"secret").unwrap_err();
        let staging = backend.staging.borrow().clone().unwrap();
        assert!(error.contains("without clobbering"));
        assert!(error.contains(&staging.display().to_string()));
        assert!(error.contains("plaintext may remain"));
        assert!(!backend.published.get());
    }

    #[test]
    fn unsupported_hard_link_has_no_copy_fallback() {
        let backend = FaultBackend::new(Faults {
            unsupported_publish: true,
            ..Faults::default()
        });
        let error =
            write_private_output_with(&backend, Path::new("plaintext"), b"secret").unwrap_err();
        assert!(error.contains("does not support the required atomic no-clobber hard-link"));
        assert!(error.contains("no copy fallback is permitted"));
        assert_eq!(backend.remove_calls.get(), 1);
        assert!(!backend.published.get());
    }

    #[test]
    fn post_publish_cleanup_and_durability_failures_name_the_created_output() {
        let cleanup_backend = FaultBackend::new(Faults {
            remove: true,
            ..Faults::default()
        });
        let cleanup_error =
            write_private_output_with(&cleanup_backend, Path::new("plaintext"), b"secret")
                .unwrap_err();
        assert!(cleanup_backend.published.get());
        assert!(cleanup_error.contains("plaintext output was created at plaintext"));
        assert!(cleanup_error.contains("duplicate plaintext may remain"));

        let sync_backend = FaultBackend::new(Faults {
            directory_sync: true,
            ..Faults::default()
        });
        let sync_error =
            write_private_output_with(&sync_backend, Path::new("plaintext"), b"secret")
                .unwrap_err();
        assert!(sync_backend.published.get());
        assert!(sync_error.contains("plaintext output was created at plaintext"));
        assert!(sync_error.contains("parent directory could not be synchronized"));
    }
}
