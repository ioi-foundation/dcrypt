// tests/src/suites/constant_time/profile.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AlgoProfile {
    pub name: String,
    pub baseline_mad_ns: f64,
    pub last_updated_ts: u64,
    pub samples_seen: usize,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ProfileStore {
    profiles: HashMap<String, AlgoProfile>,
}

static STORE_LOCK: Mutex<()> = Mutex::new(());

impl ProfileStore {
    pub fn load_or_create(path: &Path) -> Result<Self, String> {
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(format!("open noise profile {}: {error}", path.display())),
        };

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|error| format!("read noise profile {}: {error}", path.display()))?;

        serde_json::from_str(&contents)
            .map_err(|error| format!("parse noise profile {}: {error}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        // Simple file lock simulation via Mutex for within-process safety.
        // Cross-process safety isn't guaranteed here but acceptable for test suites.
        let _guard = STORE_LOCK
            .lock()
            .map_err(|_| "noise profile store lock poisoned".to_string())?;

        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "create noise profile directory {}: {error}",
                    parent.display()
                )
            })?;
        }

        let json = serde_json::to_string_pretty(self)
            .map_err(|error| format!("serialize noise profile {}: {error}", path.display()))?;
        fs::write(path, json)
            .map_err(|error| format!("write noise profile {}: {error}", path.display()))
    }

    /// Updates the profile using an Exponential Moving Average (EMA)
    pub fn update(&mut self, name: &str, current_mad: f64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let entry = self
            .profiles
            .entry(name.to_string())
            .or_insert(AlgoProfile {
                name: name.to_string(),
                baseline_mad_ns: current_mad,
                last_updated_ts: now,
                samples_seen: 0,
            });

        // Update logic: Slow EMA to adapt to long-term hardware changes,
        // ignoring sudden spikes (which are likely temporary noise).
        // If current is BETTER (lower) than baseline, adapt faster.
        let alpha = if current_mad < entry.baseline_mad_ns {
            0.2
        } else {
            0.05
        };

        entry.baseline_mad_ns = (1.0 - alpha) * entry.baseline_mad_ns + alpha * current_mad;
        entry.last_updated_ts = now;
        entry.samples_seen += 1;
    }

    pub fn get_baseline(&self, name: &str) -> Option<f64> {
        self.profiles.get(name).map(|p| p.baseline_mad_ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dcrypt-timing-profile-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn paired_profile_path_does_not_consume_legacy_keys() {
        let directory = temporary_directory("namespace");
        fs::create_dir(&directory).unwrap();
        let legacy_path = directory.join("ct_noise_profile.json");
        let paired_path = directory.join("ct_noise_profile_paired_v1.json");

        let mut legacy = ProfileStore::default();
        legacy.update("legacy-case", 7.0);
        legacy.save(&legacy_path).unwrap();
        let legacy_baseline = ProfileStore::load_or_create(&legacy_path)
            .unwrap()
            .get_baseline("legacy-case")
            .unwrap();
        assert!((legacy_baseline - 7.0).abs() < 1.0e-12);
        assert_eq!(
            ProfileStore::load_or_create(&paired_path)
                .unwrap()
                .get_baseline("legacy-case"),
            None
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn save_creates_missing_parent_and_round_trips() {
        let directory = temporary_directory("round-trip");
        let path = directory.join("missing/parents/profile.json");
        let mut store = ProfileStore::default();
        store.update("round-trip", 11.0);

        store.save(&path).unwrap();
        assert!(path.is_file());
        assert_eq!(
            ProfileStore::load_or_create(&path)
                .unwrap()
                .get_baseline("round-trip"),
            Some(11.0)
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn malformed_profile_and_unwritable_parent_fail_closed() {
        let directory = temporary_directory("negative-io");
        fs::create_dir(&directory).unwrap();

        let malformed = directory.join("malformed.json");
        fs::write(&malformed, b"{").unwrap();
        assert!(ProfileStore::load_or_create(&malformed)
            .unwrap_err()
            .contains("parse noise profile"));

        let non_directory = directory.join("not-a-directory");
        fs::write(&non_directory, b"block parent creation").unwrap();
        let path = non_directory.join("profile.json");
        assert!(ProfileStore::default()
            .save(&path)
            .unwrap_err()
            .contains("create noise profile directory"));

        fs::remove_dir_all(directory).unwrap();
    }
}
