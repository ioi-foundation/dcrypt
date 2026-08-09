use clap::Parser;
use regex::Regex;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;
use walkdir::WalkDir;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to BENCHMARKS.md
    #[arg(short, long, default_value = "BENCHMARKS.md")]
    target: PathBuf,

    /// Path to target/criterion directory
    #[arg(long, default_value = "target/criterion")]
    criterion_dir: PathBuf,
}

#[derive(Deserialize, Debug)]
struct Estimates {
    mean: Estimate,
}

#[derive(Deserialize, Debug)]
struct Estimate {
    point_estimate: f64, // Time in nanoseconds
}

#[derive(Hash, Eq, PartialEq, Ord, PartialOrd)]
enum Category {
    Kem,
    Sign,
    Symmetric,
    Hash,
    Kdf,
    Primitives,
    Other,
}

impl Category {
    fn as_str(&self) -> &'static str {
        match self {
            Category::Kem => "Key Encapsulation (KEM)",
            Category::Sign => "Digital Signatures",
            Category::Symmetric => "Symmetric Encryption",
            Category::Hash => "Hash Functions",
            Category::Kdf => "Key Derivation (KDF)",
            Category::Primitives => "Low-Level Primitives",
            Category::Other => "Other / Benchmarks",
        }
    }
}

fn categorize(id: &str) -> Category {
    // Convert to lowercase to ensure case-insensitive matching
    let id_lower = id.to_lowercase();

    // 1. Key Encapsulation
    if id_lower.contains("kyber")
        || id_lower.contains("ecdh")
        || id_lower.contains("mceliece")
        || id_lower.contains("saber")
        || id_lower.contains("encaps")
        || id_lower.contains("decaps")
        || id_lower.contains("kem")
    {
        return Category::Kem;
    }

    // 2. Signatures
    if id_lower.contains("dilithium")
        || id_lower.contains("falcon")
        || id_lower.contains("sphincs")
        || id_lower.contains("ed25519")
        || id_lower.contains("rainbow")
        || id_lower.contains("ecdsa")
        || id_lower.contains("rsa")
        || id_lower.contains("sign")
        || id_lower.contains("verify")
    {
        return Category::Sign;
    }

    // 3. Symmetric / AEAD
    if id_lower.contains("aes")
        || id_lower.contains("chacha")
        || id_lower.contains("gcm")
        || id_lower.contains("poly1305")
        || id_lower.contains("salsa")
        || id_lower.contains("aead")
        || id_lower.contains("cipher")
        || id_lower.contains("block")
    {
        return Category::Symmetric;
    }

    // 4. KDFs (Check before Hash because some KDFs use Hash names like HKDF-SHA256)
    if id_lower.contains("argon2")
        || id_lower.contains("hkdf")
        || id_lower.contains("pbkdf")
        || id_lower.contains("scrypt")
        || id_lower.contains("derive_key")
        || id_lower.contains("kdf")
    {
        return Category::Kdf;
    }

    // 5. Hashing
    if id_lower.contains("sha")
        || id_lower.contains("blake")
        || id_lower.contains("shake")
        || id_lower.contains("md5")
        || id_lower.contains("keccak")
        || id_lower.contains("digest")
        || id_lower.contains("hash")
    {
        return Category::Hash;
    }

    // 6. Low Level Primitives
    if id_lower.contains("field")
        || id_lower.contains("scalar")
        || id_lower.contains("point")
        || id_lower.contains("ntt")
        || id_lower.contains("invert")
        || id_lower.contains("sqrt")
        || id_lower.contains("montgomery")
        || id_lower.contains("bigint")
        || id_lower.contains("primitive")
        || id_lower.contains("base")
        || id_lower.contains("add")
        || id_lower.contains("sub")
        || id_lower.contains("mul")
        || id_lower.contains("div")
    {
        return Category::Primitives;
    }

    Category::Other
}

fn format_time(ns: f64) -> String {
    if ns < 1_000.0 {
        return format!("{:.2} ns", ns);
    }
    if ns < 1_000_000.0 {
        return format!("{:.2} µs", ns / 1_000.0);
    }
    if ns < 1_000_000_000.0 {
        return format!("{:.2} ms", ns / 1_000_000.0);
    }
    format!("{:.2} s", ns / 1_000_000_000.0)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut results: HashMap<Category, BTreeMap<String, String>> = HashMap::new();

    eprintln!(
        "Scanning {} for benchmark results...",
        cli.criterion_dir.display()
    );

    if !cli.criterion_dir.exists() {
        eprintln!("Warning: Criterion directory not found.");
        return Ok(());
    }

    for entry in WalkDir::new(&cli.criterion_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_name() == "estimates.json" {
            let path = entry.path();

            // Path structure: .../criterion/<Group>/<Function>/new/estimates.json
            if let Some(new_dir) = path.parent() {
                if new_dir.file_name().unwrap() == "new" {
                    if let Some(func_dir) = new_dir.parent() {
                        let func_name = func_dir.file_name().unwrap().to_string_lossy();

                        let content = fs::read_to_string(path)?;
                        if let Ok(estimates) = serde_json::from_str::<Estimates>(&content) {
                            let cat = categorize(&func_name);
                            let time_str = format_time(estimates.mean.point_estimate);

                            results
                                .entry(cat)
                                .or_default()
                                .insert(func_name.to_string(), time_str);
                        }
                    }
                }
            }
        }
    }

    if results.is_empty() {
        eprintln!("No benchmark results found.");
        return Ok(());
    }

    // Read BENCHMARKS.md or create default
    let content = fs::read_to_string(&cli.target).unwrap_or_else(|_| {
        String::from("# dcrypt Benchmarks\n\n<!-- START: Key Encapsulation (KEM) -->\n<!-- END: Key Encapsulation (KEM) -->\n")
    });

    let mut new_content = content;

    // Process categories in a deterministic order
    let mut categories: Vec<_> = results.keys().collect();
    categories.sort();

    for cat in categories {
        let benches = &results[cat];
        let cat_str = cat.as_str();
        let start_marker = format!("<!-- START: {} -->", cat_str);
        let end_marker = format!("<!-- END: {} -->", cat_str);

        let mut table = String::new();
        table.push_str(&start_marker);
        table.push('\n');
        table.push_str("| Algorithm / Operation | Average Execution Time |\n");
        table.push_str("|:----------------------|-----------------------:|\n");

        for (name, time) in benches {
            table.push_str(&format!("| `{}` | {} |\n", name, time));
        }
        table.push_str(&end_marker);

        let pattern = format!(
            r"(?s){}.*?{}",
            regex::escape(&start_marker),
            regex::escape(&end_marker)
        );
        let re = Regex::new(&pattern)?;

        if re.is_match(&new_content) {
            new_content = re.replace(&new_content, table.as_str()).to_string();
        } else {
            // If marker not found, append to end
            new_content.push_str(&format!("\n\n## {}\n{}", cat_str, table));
        }
    }

    fs::write(&cli.target, new_content)?;
    eprintln!("Updated {}", cli.target.display());

    Ok(())
}
