//! ACVP handlers for final FIPS 204 ML-DSA operations.
//!
//! ACVP seed and `rnd` values are replayed directly. Expanded private keys are
//! accepted and emitted only in the exact Algorithm 24 encoding containing a
//! 64-byte `tr`; the removed 32-byte-`tr` dcrypt format is not adapted. The
//! handler covers the external pure, external pre-hash, internal `M'`, and
//! externally supplied `mu` interfaces in the official FIPS 204 vector set.

use super::super::dispatcher::{insert, DispatchKey, HandlerFn};
use crate::suites::acvp::error::{EngineError, Result};
use crate::suites::acvp::model::{TestCase, TestGroup};
use dcrypt_algorithms::hash::{
    sha2::{Sha512_224, Sha512_256},
    HashFunction, Sha224, Sha256, Sha384, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Sha512,
};
use dcrypt_algorithms::xof::{ExtendableOutputFunction, ShakeXof128, ShakeXof256};
use dcrypt_api::Signature;
use dcrypt_internal::random::{CryptoRng, Error as RngError, RngCore};
use dcrypt_sign::mldsa::{
    MlDsa44, MlDsa65, MlDsa87, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
};
use once_cell::sync::Lazy;
use std::{collections::HashMap, fs, path::Path};

#[derive(Clone, Copy)]
enum ParameterSet {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl ParameterSet {
    fn name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    fn secret_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2560,
            Self::MlDsa65 => 4032,
            Self::MlDsa87 => 4896,
        }
    }

    fn signature_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }
}

fn get_parameter_set(group: &TestGroup) -> Result<ParameterSet> {
    let value = group
        .defaults
        .get("parameterSet")
        .map(|value| value.as_string())
        .or_else(|| {
            group
                .params
                .as_ref()
                .and_then(|params| params.as_object())
                .and_then(|params| params.get("parameterSet"))
                .and_then(|value| value.as_str().map(String::from))
        })
        .ok_or(EngineError::MissingField("parameterSet"))?;

    match value.as_str() {
        "ML-DSA-44" => Ok(ParameterSet::MlDsa44),
        "ML-DSA-65" => Ok(ParameterSet::MlDsa65),
        "ML-DSA-87" => Ok(ParameterSet::MlDsa87),
        other => Err(EngineError::InvalidData(format!(
            "unknown ML-DSA parameter set: {other}"
        ))),
    }
}

struct ReplayRng {
    bytes: Vec<u8>,
    position: usize,
}

impl ReplayRng {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, destination: &mut [u8]) {
        let end = self.position + destination.len();
        destination.copy_from_slice(
            self.bytes
                .get(self.position..end)
                .expect("ACVP replay RNG exhausted"),
        );
        self.position = end;
    }
}

impl RngCore for ReplayRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.take(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.take(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        self.take(destination);
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> core::result::Result<(), RngError> {
        self.take(destination);
        Ok(())
    }
}

impl CryptoRng for ReplayRng {}

type ExpectedMap = HashMap<(u64, u64), serde_json::Map<String, serde_json::Value>>;
type ExpectedLoad = core::result::Result<ExpectedMap, String>;

fn load_expected_results(suite: &str) -> ExpectedLoad {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("vectors")
        .join("acvp_json")
        .join(suite)
        .join("expectedResults.json");
    let contents = fs::read_to_string(&path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let root: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|error| format!("failed to parse {}: {error}", path.display()))?;
    let groups = root
        .get("testGroups")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("{} has no testGroups array", path.display()))?;

    let mut results = HashMap::new();
    for group in groups {
        let group_id = group
            .get("tgId")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("{} contains a group without tgId", path.display()))?;
        let tests = group
            .get("tests")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("group {group_id} in {} has no tests", path.display()))?;
        for test in tests {
            let test_id = test
                .get("tcId")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    format!(
                        "group {group_id} in {} has a test without tcId",
                        path.display()
                    )
                })?;
            let object = test
                .as_object()
                .cloned()
                .ok_or_else(|| format!("test {test_id} in {} is not an object", path.display()))?;
            results.insert((group_id, test_id), object);
        }
    }
    Ok(results)
}

static KEYGEN_EXPECTED: Lazy<ExpectedLoad> =
    Lazy::new(|| load_expected_results("ML-DSA-keyGen-FIPS204"));
static SIGGEN_EXPECTED: Lazy<ExpectedLoad> =
    Lazy::new(|| load_expected_results("ML-DSA-sigGen-FIPS204"));
static SIGVER_EXPECTED: Lazy<ExpectedLoad> =
    Lazy::new(|| load_expected_results("ML-DSA-sigVer-FIPS204"));

fn expected_case<'a>(
    expected: &'a Lazy<ExpectedLoad>,
    group: &TestGroup,
    case: &TestCase,
) -> Result<Option<&'a serde_json::Map<String, serde_json::Value>>> {
    match expected.as_ref() {
        Ok(results) => Ok(results.get(&(group.group_name, case.test_id))),
        Err(error) => Err(EngineError::InvalidData(error.clone())),
    }
}

fn check_expected_hex(
    expected: &Lazy<ExpectedLoad>,
    group: &TestGroup,
    case: &TestCase,
    field: &'static str,
    actual: &[u8],
) -> Result<()> {
    let Some(result) = expected_case(expected, group, case)? else {
        return Ok(());
    };
    let encoded = result
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or(EngineError::MissingField(field))?;
    let wanted = hex::decode(encoded)?;
    if wanted != actual {
        return Err(EngineError::Mismatch {
            expected: hex::encode(wanted),
            actual: hex::encode(actual),
        });
    }
    Ok(())
}

fn check_expected_bool(
    expected: &Lazy<ExpectedLoad>,
    group: &TestGroup,
    case: &TestCase,
    field: &'static str,
    actual: bool,
) -> Result<()> {
    let Some(result) = expected_case(expected, group, case)? else {
        return Ok(());
    };
    let wanted = result
        .get(field)
        .and_then(serde_json::Value::as_bool)
        .ok_or(EngineError::MissingField(field))?;
    if wanted != actual {
        return Err(EngineError::Mismatch {
            expected: wanted.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(())
}

fn keypair<R: CryptoRng + RngCore>(
    parameter_set: ParameterSet,
    rng: &mut R,
) -> Result<(MlDsaPublicKey, MlDsaSecretKey)> {
    match parameter_set {
        ParameterSet::MlDsa44 => MlDsa44::keypair(rng),
        ParameterSet::MlDsa65 => MlDsa65::keypair(rng),
        ParameterSet::MlDsa87 => MlDsa87::keypair(rng),
    }
    .map_err(|error| {
        EngineError::Crypto(format!(
            "{} key generation failed: {error:?}",
            parameter_set.name()
        ))
    })
}

fn required_bytes(case: &TestCase, field: &'static str) -> Result<Vec<u8>> {
    case.inputs
        .get(field)
        .ok_or(EngineError::MissingField(field))
        .and_then(|value| hex::decode(value.as_string()).map_err(EngineError::from))
}

fn message(case: &TestCase) -> Result<Vec<u8>> {
    if let Some(value) = case
        .inputs
        .get("message")
        .or_else(|| case.inputs.get("msg"))
    {
        hex::decode(value.as_string()).map_err(EngineError::from)
    } else {
        Err(EngineError::MissingField("message"))
    }
}

fn optional_bytes(case: &TestCase, field: &'static str) -> Result<Vec<u8>> {
    case.inputs
        .get(field)
        .map(|value| hex::decode(value.as_string()).map_err(EngineError::from))
        .transpose()
        .map(|bytes| bytes.unwrap_or_default())
}

fn group_string(group: &TestGroup, field: &'static str) -> Option<String> {
    group
        .defaults
        .get(field)
        .map(|value| value.as_string())
        .or_else(|| {
            group
                .params
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .and_then(|params| params.get(field))
                .map(|value| match value {
                    serde_json::Value::String(string) => string.clone(),
                    other => other.to_string(),
                })
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignatureInterface {
    ExternalPure,
    ExternalPreHash,
    InternalMessage,
    InternalMu,
}

fn signature_interface(group: &TestGroup) -> Result<SignatureInterface> {
    match group_string(group, "signatureInterface").as_deref() {
        Some("external") => match group_string(group, "preHash").as_deref() {
            Some("pure") => Ok(SignatureInterface::ExternalPure),
            Some("preHash") => Ok(SignatureInterface::ExternalPreHash),
            other => Err(EngineError::InvalidData(format!(
                "unsupported external ML-DSA preHash mode: {other:?}"
            ))),
        },
        Some("internal") => match group_string(group, "externalMu").as_deref() {
            Some("true") => Ok(SignatureInterface::InternalMu),
            Some("false") | None => Ok(SignatureInterface::InternalMessage),
            other => Err(EngineError::InvalidData(format!(
                "invalid ML-DSA externalMu value: {other:?}"
            ))),
        },
        other => Err(EngineError::InvalidData(format!(
            "unsupported ML-DSA signatureInterface: {other:?}"
        ))),
    }
}

const NIST_HASH_OID_PREFIX: [u8; 10] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02];

fn fixed_hash<H: HashFunction>(message: &[u8]) -> Result<Vec<u8>> {
    Ok(H::digest(message)?.as_ref().to_vec())
}

/// Return the DER-encoded NIST hash OID and PH(M) required by FIPS 204
/// Algorithms 4 and 5. SHAKE-128 and SHAKE-256 use 32- and 64-byte outputs,
/// respectively, as required by the ACVP profile.
fn pre_hash(message: &[u8], algorithm: &str) -> Result<([u8; 11], Vec<u8>)> {
    let (oid_suffix, digest) = match algorithm {
        "SHA2-224" => (0x04, fixed_hash::<Sha224>(message)?),
        "SHA2-256" => (0x01, fixed_hash::<Sha256>(message)?),
        "SHA2-384" => (0x02, fixed_hash::<Sha384>(message)?),
        "SHA2-512" => (0x03, fixed_hash::<Sha512>(message)?),
        "SHA2-512/224" => (0x05, fixed_hash::<Sha512_224>(message)?),
        "SHA2-512/256" => (0x06, fixed_hash::<Sha512_256>(message)?),
        "SHA3-224" => (0x07, fixed_hash::<Sha3_224>(message)?),
        "SHA3-256" => (0x08, fixed_hash::<Sha3_256>(message)?),
        "SHA3-384" => (0x09, fixed_hash::<Sha3_384>(message)?),
        "SHA3-512" => (0x0A, fixed_hash::<Sha3_512>(message)?),
        // ACVP response assembly is a public test-only serialization boundary.
        "SHAKE-128" => (0x0B, ShakeXof128::generate(message, 32)?.to_vec()),
        "SHAKE-256" => (0x0C, ShakeXof256::generate(message, 64)?.to_vec()),
        other => {
            return Err(EngineError::InvalidData(format!(
                "unsupported HashML-DSA pre-hash algorithm: {other}"
            )))
        }
    };
    let mut oid = [0u8; 11];
    oid[..10].copy_from_slice(&NIST_HASH_OID_PREFIX);
    oid[10] = oid_suffix;
    Ok((oid, digest))
}

fn hash_ml_dsa_message(message: &[u8], context: &[u8], algorithm: &str) -> Result<Vec<u8>> {
    if context.len() > u8::MAX as usize {
        return Err(EngineError::InvalidData(format!(
            "HashML-DSA context is {} bytes; maximum is 255",
            context.len()
        )));
    }
    let (oid, digest) = pre_hash(message, algorithm)?;
    let mut formatted = Vec::with_capacity(2 + context.len() + oid.len() + digest.len());
    formatted.push(1);
    formatted.push(context.len() as u8);
    formatted.extend_from_slice(context);
    formatted.extend_from_slice(&oid);
    formatted.extend_from_slice(&digest);
    Ok(formatted)
}

fn decode_secret_key(parameter_set: ParameterSet, bytes: &[u8]) -> Result<MlDsaSecretKey> {
    if bytes.len() != parameter_set.secret_key_len() {
        return Err(EngineError::InvalidData(format!(
            "{} expanded private key must be {} bytes, got {}",
            parameter_set.name(),
            parameter_set.secret_key_len(),
            bytes.len()
        )));
    }
    MlDsaSecretKey::from_bytes(bytes).map_err(|error| {
        EngineError::Crypto(format!(
            "{} expanded private key validation failed: {error:?}",
            parameter_set.name()
        ))
    })
}

fn sign_external(
    parameter_set: ParameterSet,
    message: &[u8],
    context: &[u8],
    secret_key: &MlDsaSecretKey,
    randomizer: [u8; 32],
) -> Result<Vec<u8>> {
    let mut rng = ReplayRng::new(randomizer.to_vec());
    let result = match parameter_set {
        ParameterSet::MlDsa44 => {
            MlDsa44::sign_with_context_rng(message, context, secret_key, &mut rng)
        }
        ParameterSet::MlDsa65 => {
            MlDsa65::sign_with_context_rng(message, context, secret_key, &mut rng)
        }
        ParameterSet::MlDsa87 => {
            MlDsa87::sign_with_context_rng(message, context, secret_key, &mut rng)
        }
    };
    result
        .map(|signature| signature.as_ref().to_vec())
        .map_err(|error| {
            EngineError::Crypto(format!(
                "{} signature generation failed: {error:?}",
                parameter_set.name()
            ))
        })
}

fn sign_internal_message(
    parameter_set: ParameterSet,
    formatted_message: &[u8],
    secret_key: &MlDsaSecretKey,
    randomizer: &[u8; 32],
) -> Result<Vec<u8>> {
    let result = match parameter_set {
        ParameterSet::MlDsa44 => {
            MlDsa44::sign_internal_with_randomizer(formatted_message, secret_key, randomizer)
        }
        ParameterSet::MlDsa65 => {
            MlDsa65::sign_internal_with_randomizer(formatted_message, secret_key, randomizer)
        }
        ParameterSet::MlDsa87 => {
            MlDsa87::sign_internal_with_randomizer(formatted_message, secret_key, randomizer)
        }
    };
    result
        .map(|signature| signature.as_ref().to_vec())
        .map_err(|error| {
            EngineError::Crypto(format!(
                "{} internal signature generation failed: {error:?}",
                parameter_set.name()
            ))
        })
}

fn sign_mu(
    parameter_set: ParameterSet,
    mu: &[u8],
    secret_key: &MlDsaSecretKey,
    randomizer: &[u8; 32],
) -> Result<Vec<u8>> {
    let mu: &[u8; 64] = mu.try_into().map_err(|_| {
        EngineError::InvalidData(format!(
            "ML-DSA externally supplied mu must be 64 bytes, got {}",
            mu.len()
        ))
    })?;
    let result = match parameter_set {
        ParameterSet::MlDsa44 => MlDsa44::sign_mu_with_randomizer(mu, secret_key, randomizer),
        ParameterSet::MlDsa65 => MlDsa65::sign_mu_with_randomizer(mu, secret_key, randomizer),
        ParameterSet::MlDsa87 => MlDsa87::sign_mu_with_randomizer(mu, secret_key, randomizer),
    };
    result
        .map(|signature| signature.as_ref().to_vec())
        .map_err(|error| {
            EngineError::Crypto(format!(
                "{} supplied-mu signature generation failed: {error:?}",
                parameter_set.name()
            ))
        })
}

fn verify_external(
    parameter_set: ParameterSet,
    message: &[u8],
    context: &[u8],
    signature: &MlDsaSignature,
    public_key: &MlDsaPublicKey,
) -> bool {
    match parameter_set {
        ParameterSet::MlDsa44 => {
            MlDsa44::verify_with_context(message, context, signature, public_key)
        }
        ParameterSet::MlDsa65 => {
            MlDsa65::verify_with_context(message, context, signature, public_key)
        }
        ParameterSet::MlDsa87 => {
            MlDsa87::verify_with_context(message, context, signature, public_key)
        }
    }
    .is_ok()
}

fn verify_internal_message(
    parameter_set: ParameterSet,
    formatted_message: &[u8],
    signature: &MlDsaSignature,
    public_key: &MlDsaPublicKey,
) -> bool {
    match parameter_set {
        ParameterSet::MlDsa44 => {
            MlDsa44::verify_internal_message(formatted_message, signature, public_key)
        }
        ParameterSet::MlDsa65 => {
            MlDsa65::verify_internal_message(formatted_message, signature, public_key)
        }
        ParameterSet::MlDsa87 => {
            MlDsa87::verify_internal_message(formatted_message, signature, public_key)
        }
    }
    .is_ok()
}

fn verify_mu(
    parameter_set: ParameterSet,
    mu: &[u8],
    signature: &MlDsaSignature,
    public_key: &MlDsaPublicKey,
) -> bool {
    let Ok(mu) = <&[u8; 64]>::try_from(mu) else {
        return false;
    };
    match parameter_set {
        ParameterSet::MlDsa44 => MlDsa44::verify_mu(mu, signature, public_key),
        ParameterSet::MlDsa65 => MlDsa65::verify_mu(mu, signature, public_key),
        ParameterSet::MlDsa87 => MlDsa87::verify_mu(mu, signature, public_key),
    }
    .is_ok()
}

/// ML-DSA key generation using the ACVP seed as the direct 32-byte `xi` input.
pub(crate) fn ml_dsa_keygen(group: &TestGroup, case: &TestCase) -> Result<()> {
    let parameter_set = get_parameter_set(group)?;

    let seed = required_bytes(case, "seed")?;
    if seed.len() != 32 {
        return Err(EngineError::InvalidData(format!(
            "{} key-generation seed must be 32 bytes, got {}",
            parameter_set.name(),
            seed.len()
        )));
    }
    let (public_key, secret_key) = keypair(parameter_set, &mut ReplayRng::new(seed))?;

    check_expected_hex(&KEYGEN_EXPECTED, group, case, "pk", public_key.to_bytes())?;
    check_expected_hex(&KEYGEN_EXPECTED, group, case, "sk", secret_key.to_bytes())?;

    case.outputs
        .borrow_mut()
        .insert("pk".into(), hex::encode(public_key.to_bytes()));
    case.outputs
        .borrow_mut()
        .insert("sk".into(), hex::encode(secret_key.to_bytes()));
    Ok(())
}

/// ML-DSA signature generation using the ACVP `rnd` value directly.
///
/// The expanded private key is sufficient for signing; ACVP sigGen prompts do
/// not provide the public key. All four FIPS 204 interfaces exercise dcrypt's
/// owned implementation; external implementations live only in `verification/`.
pub(crate) fn ml_dsa_siggen(group: &TestGroup, case: &TestCase) -> Result<()> {
    let parameter_set = get_parameter_set(group)?;
    let secret_key_bytes = required_bytes(case, "sk")?;
    let secret_key = decode_secret_key(parameter_set, &secret_key_bytes)?;

    // Missing `rnd` denotes the optional deterministic FIPS 204 variant.
    let randomizer = case
        .inputs
        .get("rnd")
        .map(|value| hex::decode(value.as_string()))
        .transpose()?
        .unwrap_or_else(|| vec![0u8; 32]);
    if randomizer.len() != 32 {
        return Err(EngineError::InvalidData(format!(
            "{} signing randomizer must be 32 bytes, got {}",
            parameter_set.name(),
            randomizer.len()
        )));
    }
    let randomizer: [u8; 32] = randomizer
        .try_into()
        .map_err(|_| EngineError::InvalidData("invalid signing randomizer".into()))?;

    let interface = signature_interface(group)?;
    let signature = match interface {
        SignatureInterface::ExternalPure => {
            let message = message(case)?;
            let context = optional_bytes(case, "context")?;
            sign_external(parameter_set, &message, &context, &secret_key, randomizer)?
        }
        SignatureInterface::ExternalPreHash => {
            let message = message(case)?;
            let context = optional_bytes(case, "context")?;
            let hash_algorithm = case
                .inputs
                .get("hashAlg")
                .ok_or(EngineError::MissingField("hashAlg"))?
                .as_string();
            let formatted = hash_ml_dsa_message(&message, &context, &hash_algorithm)?;
            sign_internal_message(parameter_set, &formatted, &secret_key, &randomizer)?
        }
        SignatureInterface::InternalMessage => {
            let formatted = message(case)?;
            sign_internal_message(parameter_set, &formatted, &secret_key, &randomizer)?
        }
        SignatureInterface::InternalMu => {
            let mu = required_bytes(case, "mu")?;
            sign_mu(parameter_set, &mu, &secret_key, &randomizer)?
        }
    };

    if signature.len() != parameter_set.signature_len() {
        return Err(EngineError::InvalidData(format!(
            "{} produced a {}-byte signature; expected {}",
            parameter_set.name(),
            signature.len(),
            parameter_set.signature_len()
        )));
    }
    check_expected_hex(&SIGGEN_EXPECTED, group, case, "signature", &signature)?;
    case.outputs
        .borrow_mut()
        .insert("signature".into(), hex::encode(signature));
    Ok(())
}

/// ML-DSA signature verification with strict canonical signature decoding.
pub(crate) fn ml_dsa_sigver(group: &TestGroup, case: &TestCase) -> Result<()> {
    let parameter_set = get_parameter_set(group)?;
    let public_key_bytes = required_bytes(case, "pk")?;
    let signature_bytes = required_bytes(case, "signature")?;

    // Exercise dcrypt's strict key/signature decoders before entering either
    // verification backend. Noncanonical hint encodings are negative vectors.
    let decoded_public = MlDsaPublicKey::from_bytes(&public_key_bytes);
    let decoded_signature = MlDsaSignature::from_bytes(&signature_bytes);
    let test_passed = if let (Ok(public_key), Ok(signature)) = (decoded_public, decoded_signature) {
        match signature_interface(group)? {
            SignatureInterface::ExternalPure => {
                let message = message(case)?;
                let context = optional_bytes(case, "context")?;
                verify_external(parameter_set, &message, &context, &signature, &public_key)
            }
            SignatureInterface::ExternalPreHash => {
                let message = message(case)?;
                let context = optional_bytes(case, "context")?;
                let hash_algorithm = case
                    .inputs
                    .get("hashAlg")
                    .ok_or(EngineError::MissingField("hashAlg"))?
                    .as_string();
                let formatted = hash_ml_dsa_message(&message, &context, &hash_algorithm)?;
                verify_internal_message(parameter_set, &formatted, &signature, &public_key)
            }
            SignatureInterface::InternalMessage => {
                let formatted = message(case)?;
                verify_internal_message(parameter_set, &formatted, &signature, &public_key)
            }
            SignatureInterface::InternalMu => {
                let mu = required_bytes(case, "mu")?;
                verify_mu(parameter_set, &mu, &signature, &public_key)
            }
        }
    } else {
        false
    };
    check_expected_bool(&SIGVER_EXPECTED, group, case, "testPassed", test_passed)?;
    case.outputs
        .borrow_mut()
        .insert("testPassed".into(), test_passed.to_string());
    Ok(())
}

/// Register ML-DSA handlers.
pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    insert(map, "ML-DSA-keyGen", "AFT", "AFT", ml_dsa_keygen);
    insert(map, "ML-DSA-sigGen", "AFT", "AFT", ml_dsa_siggen);
    insert(map, "ML-DSA-sigVer", "AFT", "AFT", ml_dsa_sigver);
}
