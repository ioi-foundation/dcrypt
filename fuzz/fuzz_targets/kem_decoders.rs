#![no_main]

use dcrypt_kem::ecdh::{
    EcdhK256Ciphertext, EcdhK256PublicKey, EcdhK256SecretKey, EcdhP224Ciphertext,
    EcdhP224PublicKey, EcdhP224SecretKey, EcdhP256Ciphertext, EcdhP256PublicKey, EcdhP256SecretKey,
    EcdhP384Ciphertext, EcdhP384PublicKey, EcdhP384SecretKey, EcdhP521Ciphertext,
    EcdhP521PublicKey, EcdhP521SecretKey,
};
use dcrypt_kem::ml_kem::{
    MlKem1024Ciphertext, MlKem1024DecapsulationKey, MlKem1024EncapsulationKey, MlKem512Ciphertext,
    MlKem512DecapsulationKey, MlKem512EncapsulationKey, MlKem768Ciphertext,
    MlKem768DecapsulationKey, MlKem768EncapsulationKey,
};
use libfuzzer_sys::fuzz_target;

const INPUT_MAX: usize = 16 * 1024;

fn expanded(data: &[u8], offset: usize, length: usize) -> Vec<u8> {
    let mut output = vec![0u8; length];
    if data.is_empty() {
        return output;
    }
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = data[(offset + index) % data.len()];
    }
    output
}

macro_rules! exercise_ml_kem {
    ($input:expr, $offset:expr, $ek:ty, $dk:ty, $ct:ty, $ek_len:expr, $dk_len:expr, $ct_len:expr) => {{
        let _ = <$ek>::from_bytes($input);
        let _ = <$dk>::from_bytes($input);
        let _ = <$ct>::from_bytes($input);
        let _ = <$ek>::from_bytes(&expanded($input, $offset, $ek_len));
        let _ = <$dk>::from_bytes(&expanded($input, $offset + 17, $dk_len));
        let _ = <$ct>::from_bytes(&expanded($input, $offset + 31, $ct_len));
    }};
}

macro_rules! exercise_ecdh {
    ($input:expr, $offset:expr, $pk:ty, $sk:ty, $ct:ty, $pk_len:expr, $sk_len:expr) => {{
        let _ = <$pk>::from_bytes($input);
        let _ = <$sk>::from_bytes($input);
        let _ = <$ct>::from_bytes($input);
        let _ = <$pk>::from_bytes(&expanded($input, $offset, $pk_len));
        let _ = <$sk>::from_bytes(&expanded($input, $offset + 7, $sk_len));
        let _ = <$ct>::from_bytes(&expanded($input, $offset + 13, $pk_len));
    }};
}

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(INPUT_MAX)];

    exercise_ml_kem!(
        input,
        1,
        MlKem512EncapsulationKey,
        MlKem512DecapsulationKey,
        MlKem512Ciphertext,
        800,
        1_632,
        768
    );
    exercise_ml_kem!(
        input,
        3,
        MlKem768EncapsulationKey,
        MlKem768DecapsulationKey,
        MlKem768Ciphertext,
        1_184,
        2_400,
        1_088
    );
    exercise_ml_kem!(
        input,
        5,
        MlKem1024EncapsulationKey,
        MlKem1024DecapsulationKey,
        MlKem1024Ciphertext,
        1_568,
        3_168,
        1_568
    );

    exercise_ecdh!(
        input,
        2,
        EcdhP224PublicKey,
        EcdhP224SecretKey,
        EcdhP224Ciphertext,
        29,
        28
    );
    exercise_ecdh!(
        input,
        4,
        EcdhP256PublicKey,
        EcdhP256SecretKey,
        EcdhP256Ciphertext,
        33,
        32
    );
    exercise_ecdh!(
        input,
        6,
        EcdhP384PublicKey,
        EcdhP384SecretKey,
        EcdhP384Ciphertext,
        49,
        48
    );
    exercise_ecdh!(
        input,
        8,
        EcdhP521PublicKey,
        EcdhP521SecretKey,
        EcdhP521Ciphertext,
        67,
        66
    );
    exercise_ecdh!(
        input,
        10,
        EcdhK256PublicKey,
        EcdhK256SecretKey,
        EcdhK256Ciphertext,
        33,
        32
    );
});
