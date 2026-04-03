//! ACVP handlers for ML-KEM (Kyber) encapsulation / decapsulation
//! Follows §7 of FIPS-203 and mirrors the logic already in
//! `kem::kyber::ind_cca`, but is *deterministic* when ACVP supplies the
//! message seed `m`.

use crate::suites::acvp::dispatcher::{insert, DispatchKey, HandlerFn};
use crate::suites::acvp::error::{EngineError, Result};
use crate::suites::acvp::model::{TestCase, TestGroup};

use dcrypt_api::Kem; // Use the Kem trait from api crate
use dcrypt_kem::kyber::{
    Kyber1024, Kyber512, Kyber768, KyberCiphertext, KyberPublicKey, KyberSecretKey,
};
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

// Define the constant here since we can't access the private params module
const KYBER_SYMKEY_SEED_BYTES: usize = 32;

/// --- tiny deterministic RNG -------------------------------------------------
struct FixedRng {
    buf: Vec<u8>,
    ofs: usize,
}

impl FixedRng {
    fn new(seed: &[u8]) -> Self {
        Self {
            buf: seed.to_vec(),
            ofs: 0,
        }
    }
}

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            if self.ofs >= self.buf.len() {
                self.ofs = 0; // wrap around
            }
            *b = self.buf[self.ofs];
            self.ofs += 1;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixedRng {}

/// Key Generation ("keyGen", "AFT")
fn ml_kem_keygen(group: &TestGroup, case: &TestCase) -> Result<()> {
    let param_set = group
        .defaults
        .get("parameterSet")
        .ok_or(EngineError::MissingField("parameterSet"))?
        .as_string();

    // Get the two 32-byte seeds
    let z_hex = case
        .inputs
        .get("z")
        .ok_or(EngineError::MissingField("z"))?
        .as_string();
    let d_hex = case
        .inputs
        .get("d")
        .ok_or(EngineError::MissingField("d"))?
        .as_string();

    let z_bytes = hex::decode(&z_hex)?;
    let d_bytes = hex::decode(&d_hex)?;

    if z_bytes.len() != 32 || d_bytes.len() != 32 {
        return Err(EngineError::InvalidData(
            "z and d must be 32 bytes each".into(),
        ));
    }

    // Combine z and d to create a 64-byte seed for the RNG
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(&z_bytes);
    seed.extend_from_slice(&d_bytes);

    let mut rng = FixedRng::new(&seed);

    // Generate keypair based on parameter set
    let result = match param_set.as_str() {
        "ML-KEM-512" => Kyber512::keypair(&mut rng),
        "ML-KEM-768" => Kyber768::keypair(&mut rng),
        "ML-KEM-1024" => Kyber1024::keypair(&mut rng),
        other => {
            return Err(EngineError::InvalidData(format!(
                "Unknown parameterSet: {}",
                other
            )))
        }
    };

    let (pk, sk) = result.map_err(|e| EngineError::Crypto(format!("{:?}", e)))?;

    // Verify or store the public key (ek)
    if let Some(exp_ek) = case.inputs.get("ek").map(|v| v.as_string()) {
        if hex::decode(&exp_ek)?.ct_eq(pk.as_bytes()).unwrap_u8() != 1 {
            return Err(EngineError::Mismatch {
                expected: exp_ek,
                actual: hex::encode(pk.as_bytes()),
            });
        }
    } else {
        case.outputs
            .borrow_mut()
            .insert("ek".into(), hex::encode(pk.as_bytes()));
    }

    // Verify or store the secret key (dk)
    if let Some(exp_dk) = case.inputs.get("dk").map(|v| v.as_string()) {
        if hex::decode(&exp_dk)?.ct_eq(&sk.to_vec()).unwrap_u8() != 1 {
            return Err(EngineError::Mismatch {
                expected: exp_dk,
                actual: hex::encode(sk.to_vec()),
            });
        }
    } else {
        case.outputs
            .borrow_mut()
            .insert("dk".into(), hex::encode(sk.to_vec()));
    }

    Ok(())
}

/// Encapsulation ("encapsulation", "AFT")
fn ml_kem_encap(group: &TestGroup, case: &TestCase) -> Result<()> {
    let param_set = group
        .defaults
        .get("parameterSet")
        .ok_or(EngineError::MissingField("parameterSet"))?
        .as_string();

    let ek_hex = case
        .inputs
        .get("ek")
        .ok_or(EngineError::MissingField("ek"))?
        .as_string();
    let m_hex = case
        .inputs
        .get("m")
        .ok_or(EngineError::MissingField("m"))?
        .as_string();

    let pk_bytes = hex::decode(&ek_hex)?;
    let m_vec = hex::decode(&m_hex)?;
    if m_vec.len() != KYBER_SYMKEY_SEED_BYTES {
        return Err(EngineError::InvalidData("m must be 32 bytes".into()));
    }

    let pk = KyberPublicKey::new(pk_bytes.clone());
    let mut rng = FixedRng::new(&m_vec);

    // Use match to handle different parameter sets
    let result = match param_set.as_str() {
        "ML-KEM-512" => Kyber512::encapsulate(&mut rng, &pk),
        "ML-KEM-768" => Kyber768::encapsulate(&mut rng, &pk),
        "ML-KEM-1024" => Kyber1024::encapsulate(&mut rng, &pk),
        other => {
            return Err(EngineError::InvalidData(format!(
                "Unknown parameterSet: {}",
                other
            )))
        }
    };

    let (ct, ss) = result.map_err(|e| EngineError::Crypto(format!("{:?}", e)))?;

    // verify if expected values present
    if let Some(exp_c) = case.inputs.get("c").map(|v| v.as_string()) {
        if hex::decode(&exp_c)?.ct_eq(ct.as_bytes()).unwrap_u8() != 1 {
            return Err(EngineError::Mismatch {
                expected: exp_c,
                actual: hex::encode(ct.as_bytes()),
            });
        }
    } else {
        case.outputs
            .borrow_mut()
            .insert("c".into(), hex::encode(ct.as_bytes()));
    }

    if let Some(exp_k) = case.inputs.get("k").map(|v| v.as_string()) {
        if hex::decode(&exp_k)?
            .ct_eq(&*ss.to_bytes_zeroizing())
            .unwrap_u8()
            != 1
        {
            return Err(EngineError::Mismatch {
                expected: exp_k,
                actual: hex::encode(&*ss.to_bytes_zeroizing()),
            });
        }
    } else {
        case.outputs
            .borrow_mut()
            .insert("k".into(), hex::encode(&*ss.to_bytes_zeroizing()));
    }

    Ok(())
}

/// Decapsulation ("decapsulation", "VAL" | "AFT")
fn ml_kem_decap(group: &TestGroup, case: &TestCase) -> Result<()> {
    let param_set = group
        .defaults
        .get("parameterSet")
        .ok_or(EngineError::MissingField("parameterSet"))?
        .as_string();

    let dk_hex = case
        .inputs
        .get("dk")
        .ok_or(EngineError::MissingField("dk"))?
        .as_string();
    let c_hex = case
        .inputs
        .get("c")
        .ok_or(EngineError::MissingField("c"))?
        .as_string();

    let sk_bytes = hex::decode(&dk_hex)?;
    let ct_bytes = hex::decode(&c_hex)?;

    let sk = KyberSecretKey::new(sk_bytes.clone());
    let ct = KyberCiphertext::new(ct_bytes.clone());

    // Use match to handle different parameter sets
    let result = match param_set.as_str() {
        "ML-KEM-512" => Kyber512::decapsulate(&sk, &ct),
        "ML-KEM-768" => Kyber768::decapsulate(&sk, &ct),
        "ML-KEM-1024" => Kyber1024::decapsulate(&sk, &ct),
        other => {
            return Err(EngineError::InvalidData(format!(
                "Unknown parameterSet: {}",
                other
            )))
        }
    };

    let ss = result.map_err(|e| EngineError::Crypto(format!("{:?}", e)))?;

    if let Some(exp_k) = case.inputs.get("k").map(|v| v.as_string()) {
        if hex::decode(&exp_k)?
            .ct_eq(&*ss.to_bytes_zeroizing())
            .unwrap_u8()
            != 1
        {
            return Err(EngineError::Mismatch {
                expected: exp_k,
                actual: hex::encode(&*ss.to_bytes_zeroizing()),
            });
        }
    } else {
        case.outputs
            .borrow_mut()
            .insert("k".into(), hex::encode(&*ss.to_bytes_zeroizing()));
    }

    Ok(())
}

/// Encapsulation Key Check ("encapsulationKeyCheck", "VAL")
fn ml_kem_encap_keycheck(group: &TestGroup, case: &TestCase) -> Result<()> {
    let param_set = group
        .defaults
        .get("parameterSet")
        .ok_or(EngineError::MissingField("parameterSet"))?
        .as_string();

    let ek_hex = case
        .inputs
        .get("ek")
        .ok_or(EngineError::MissingField("ek"))?
        .as_string();

    let pk_bytes = hex::decode(&ek_hex)?;

    // Check if the key has the correct size for the parameter set
    let expected_size = match param_set.as_str() {
        "ML-KEM-512" => 800,   // Kyber512 public key size
        "ML-KEM-768" => 1184,  // Kyber768 public key size
        "ML-KEM-1024" => 1568, // Kyber1024 public key size
        other => {
            return Err(EngineError::InvalidData(format!(
                "Unknown parameterSet: {}",
                other
            )))
        }
    };

    let is_valid = pk_bytes.len() == expected_size;

    // If we need more thorough validation, we could try to parse the key
    // For now, just check the size
    case.outputs
        .borrow_mut()
        .insert("testPassed".into(), is_valid.to_string());

    Ok(())
}

/// Decapsulation Key Check ("decapsulationKeyCheck", "VAL")
fn ml_kem_decap_keycheck(group: &TestGroup, case: &TestCase) -> Result<()> {
    let param_set = group
        .defaults
        .get("parameterSet")
        .ok_or(EngineError::MissingField("parameterSet"))?
        .as_string();

    let dk_hex = case
        .inputs
        .get("dk")
        .ok_or(EngineError::MissingField("dk"))?
        .as_string();

    let sk_bytes = hex::decode(&dk_hex)?;

    // Check if the key has the correct size for the parameter set
    let expected_size = match param_set.as_str() {
        "ML-KEM-512" => 1632,  // Kyber512 secret key size
        "ML-KEM-768" => 2400,  // Kyber768 secret key size
        "ML-KEM-1024" => 3168, // Kyber1024 secret key size
        other => {
            return Err(EngineError::InvalidData(format!(
                "Unknown parameterSet: {}",
                other
            )))
        }
    };

    let is_valid = sk_bytes.len() == expected_size;

    // If we need more thorough validation, we could try to parse the key
    // For now, just check the size
    case.outputs
        .borrow_mut()
        .insert("testPassed".into(), is_valid.to_string());

    Ok(())
}

/// Public entry – called from the global algorithm registry
pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    // Key generation - note the algorithm name includes the mode
    insert(map, "ML-KEM-keyGen", "AFT", "AFT", ml_kem_keygen);

    // Encapsulation/Decapsulation
    insert(
        map,
        "ML-KEM-encapDecap",
        "encapsulation",
        "AFT",
        ml_kem_encap,
    );
    insert(
        map,
        "ML-KEM-encapDecap",
        "decapsulation",
        "VAL",
        ml_kem_decap,
    );
    insert(
        map,
        "ML-KEM-encapDecap",
        "decapsulation",
        "AFT",
        ml_kem_decap,
    );

    // Key validation checks
    insert(
        map,
        "ML-KEM-encapDecap",
        "encapsulationKeyCheck",
        "VAL",
        ml_kem_encap_keycheck,
    );
    insert(
        map,
        "ML-KEM-encapDecap",
        "decapsulationKeyCheck",
        "VAL",
        ml_kem_decap_keycheck,
    );
}
