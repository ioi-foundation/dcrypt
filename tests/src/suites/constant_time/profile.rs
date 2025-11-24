// tests/src/suites/constant_time/profile.rs

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};
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
    pub fn load_or_create(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }

        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return Self::default(),
        };

        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_err() {
            return Self::default();
        }

        serde_json::from_str(&contents).unwrap_or_default()
    }

    pub fn save(&self, path: &Path) {
        // Simple file lock simulation via Mutex for within-process safety.
        // Cross-process safety isn't guaranteed here but acceptable for test suites.
        let _guard = STORE_LOCK.lock().unwrap();
        
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, json);
        }
    }

    /// Updates the profile using an Exponential Moving Average (EMA)
    pub fn update(&mut self, name: &str, current_mad: f64) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let entry = self.profiles.entry(name.to_string()).or_insert(AlgoProfile {
            name: name.to_string(),
            baseline_mad_ns: current_mad,
            last_updated_ts: now,
            samples_seen: 0,
        });

        // Update logic: Slow EMA to adapt to long-term hardware changes,
        // ignoring sudden spikes (which are likely temporary noise).
        // If current is BETTER (lower) than baseline, adapt faster.
        let alpha = if current_mad < entry.baseline_mad_ns { 0.2 } else { 0.05 };
        
        entry.baseline_mad_ns = (1.0 - alpha) * entry.baseline_mad_ns + alpha * current_mad;
        entry.last_updated_ts = now;
        entry.samples_seen += 1;
    }

    pub fn get_baseline(&self, name: &str) -> Option<f64> {
        self.profiles.get(name).map(|p| p.baseline_mad_ns)
    }
}