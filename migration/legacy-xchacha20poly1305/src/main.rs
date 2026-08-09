#![forbid(unsafe_code)]

use dcrypt_internal::zeroing::{Zeroize, Zeroizing};
use dcrypt_legacy_xchacha20poly1305_migration::{decrypt_legacy_v1, REQUIRED_PROVENANCE};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

struct Arguments {
    key_file: PathBuf,
    nonce: [u8; 24],
    ciphertext_file: PathBuf,
    output_file: PathBuf,
    aad_file: Option<PathBuf>,
}

fn usage() -> &'static str {
    "usage: dcrypt-legacy-xchacha20poly1305-migration \
--provenance dcrypt-v1-custom-xchacha20poly1305 \
--key-file KEY --nonce-hex 48_HEX_CHARS \
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

fn next_value(arguments: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    arguments
        .next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut arguments = env::args().skip(1);
    let mut provenance = None;
    let mut key_file = None;
    let mut nonce = None;
    let mut ciphertext_file = None;
    let mut output_file = None;
    let mut aad_file = None;

    while let Some(flag) = arguments.next() {
        match flag.as_str() {
            "--provenance" => provenance = Some(next_value(&mut arguments, &flag)?),
            "--key-file" => key_file = Some(PathBuf::from(next_value(&mut arguments, &flag)?)),
            "--nonce-hex" => nonce = Some(decode_nonce(&next_value(&mut arguments, &flag)?)?),
            "--ciphertext-file" => {
                ciphertext_file = Some(PathBuf::from(next_value(&mut arguments, &flag)?));
            }
            "--output-file" => {
                output_file = Some(PathBuf::from(next_value(&mut arguments, &flag)?));
            }
            "--aad-file" => aad_file = Some(PathBuf::from(next_value(&mut arguments, &flag)?)),
            "-h" | "--help" => return Err(usage().into()),
            _ => return Err(format!("unknown option: {flag}\n{}", usage())),
        }
    }

    if provenance.as_deref() != Some(REQUIRED_PROVENANCE) {
        return Err(format!(
            "refusing migration without --provenance {REQUIRED_PROVENANCE}"
        ));
    }
    Ok(Arguments {
        key_file: key_file.ok_or_else(|| "--key-file is required".to_string())?,
        nonce: nonce.ok_or_else(|| "--nonce-hex is required".to_string())?,
        ciphertext_file: ciphertext_file
            .ok_or_else(|| "--ciphertext-file is required".to_string())?,
        output_file: output_file.ok_or_else(|| "--output-file is required".to_string())?,
        aad_file,
    })
}

fn read_key(path: &Path) -> Result<Zeroizing<[u8; 32]>, String> {
    let bytes = Zeroizing::new(
        fs::read(path)
            .map_err(|error| format!("unable to read key file: {error}"))?
            .into_boxed_slice(),
    );
    if bytes.len() != 32 {
        return Err("key file must contain exactly 32 raw bytes".into());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn create_output(path: &Path) -> Result<std::fs::File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| format!("unable to create a new output file: {error}"))
}

fn run() -> Result<(), String> {
    let arguments = parse_arguments()?;
    let key = read_key(&arguments.key_file)?;
    let ciphertext = fs::read(&arguments.ciphertext_file)
        .map_err(|error| format!("unable to read ciphertext file: {error}"))?;
    let aad = arguments
        .aad_file
        .as_ref()
        .map(fs::read)
        .transpose()
        .map_err(|error| format!("unable to read AAD file: {error}"))?;
    let mut plaintext = decrypt_legacy_v1(&key, &arguments.nonce, &ciphertext, aad.as_deref())
        .map_err(|_| {
            "authentication failed; input is not verified legacy ciphertext".to_string()
        })?;

    let mut output = create_output(&arguments.output_file)?;
    if let Err(error) = output
        .write_all(&plaintext)
        .and_then(|()| output.sync_all())
    {
        plaintext.zeroize();
        drop(output);
        let _ = fs::remove_file(&arguments.output_file);
        return Err(format!("unable to write plaintext output: {error}"));
    }
    plaintext.zeroize();
    Ok(())
}

fn main() {
    if env::args()
        .skip(1)
        .any(|argument| argument == "-h" || argument == "--help")
    {
        println!("{}", usage());
        return;
    }
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
