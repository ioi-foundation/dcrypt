use super::*;
use crate::hash::HashFunction;
use hex;

// Helper function to convert a digest to hex string
fn to_hex(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn test_blake2b_empty_string() {
    let mut hasher = Blake2b::new();
    hasher.update(b"").unwrap();
    let digest = hasher.finalize().unwrap();
    let hex = to_hex(digest.as_ref());

    // RFC 7693 Appendix A test vector for empty string
    let expected = "786a02f742015903c6c6fd852552d272912f4740e1584761\
                    8a86e217f71f5419d25e1031afee585313896444934eb04b\
                    903a685b1448b755d56f701afe9be2ce";

    assert_eq!(hex, expected);
    // Also verify first 4 bytes specifically
    assert_eq!(&hex[0..8], "786a02f7");
}

#[test]
fn test_blake2b_abc() {
    let mut hasher = Blake2b::new();
    hasher.update(b"abc").unwrap();
    let digest = hasher.finalize().unwrap();
    let hex = to_hex(digest.as_ref());

    // RFC 7693 Appendix A test vector for "abc"
    let expected = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b7\
                    4b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc95\
                    18d38aa8dbf1925ab92386edd4009923";

    assert_eq!(hex, expected);
    // Also verify first 4 bytes specifically
    assert_eq!(&hex[0..8], "ba80a53f");
}

#[test]
fn test_blake2b_1million_zeros() {
    // RFC 7693 A.3 – 1_000_000 zero-bytes
    let data = vec![0u8; 1_000_000];

    let mut hasher = Blake2b::new();
    hasher.update(&data).unwrap();
    let digest = hasher.finalize().unwrap();
    let hex = hex::encode(digest);

    let expected = "\
        9ef8b51be521c6e33abb22d6a6936390\
        2b6d7eb67ca1364ebc87a64d5a36ec5e\
        749e5c9e7029a85b0008e46cff24281e\
        87500886818dbe79dc8e094f119bbeb8";

    assert_eq!(hex, expected);
}

#[test]
fn test_f1_flag_never_set_sequential_tree() {
    // Create a Blake2b instance
    let mut hasher = Blake2b::new();

    // Check that f[1] is initially zero
    assert_eq!(hasher.f[1], 0);

    // Small input to trigger compression
    hasher
        .update(b"test data that will cause compression")
        .unwrap();

    // Check f[1] is still zero after an update
    assert_eq!(hasher.f[1], 0);

    // Finalize to trigger the last block with the 'last' flag
    hasher.finalize().unwrap();

    // Check f[1] is still zero after finalization
    // This ensures LAST_NODE bit is not set in sequential tree mode
    assert_eq!(hasher.f[1], 0);
}

#[test]
fn test_blake2b_empty() {
    // Vector from RFC 7693, Appendix A
    let expected = "\
        786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
        d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce";
    let mut h = Blake2b::new();
    h.update(&[]).unwrap();
    let res = h.finalize().unwrap();
    assert_eq!(hex::encode(&res), expected);
}

#[test]
fn test_blake2s_empty() {
    // Vector from RFC 7693, Appendix A
    let expected = "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9";
    let mut h = Blake2s::new();
    h.update(&[]).unwrap();
    let res = h.finalize().unwrap();
    assert_eq!(hex::encode(&res), expected);
}

#[test]
fn test_blake2s_abc() {
    // Common test vector for cryptographic hash functions
    let expected = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982";
    let mut h = Blake2s::new();
    h.update(b"abc").unwrap();
    let res = h.finalize().unwrap();
    assert_eq!(hex::encode(&res), expected);
}

#[test]
fn keyed_blake2_matches_independent_known_answers() {
    let mut blake2b = Blake2b::with_key(b"key", 64).unwrap();
    blake2b.update(b"abc").unwrap();
    assert_eq!(
        hex::encode(blake2b.finalize().unwrap()),
        "5c6a9a4ae911c02fb7e71a991eb9aea371ae993d4842d206e6020d46f5e41358\
         c6d5c277c110ef86c959ed63e6ecaaaceaaff38019a43264ae06acf73b9550b1"
    );

    let mut blake2s = Blake2s::with_key(b"key", 32).unwrap();
    blake2s.update(b"abc").unwrap();
    assert_eq!(
        hex::encode(blake2s.finalize().unwrap()),
        "3f9723437b033bf0c1f4df43cafd0776068cb0a95912de13f3b2952a3aba764d"
    );
}

#[test]
fn keyed_blake2_rejects_invalid_output_lengths_before_key_staging() {
    assert!(Blake2b::with_key(b"key", 0).is_err());
    assert!(Blake2b::with_key(b"key", 65).is_err());
    assert!(Blake2s::with_key(b"key", 0).is_err());
    assert!(Blake2s::with_key(b"key", 33).is_err());
}

#[test]
fn test_blake2b_multiblock() {
    let message = vec![b'a'; 200];
    let expected = "\
        932355851d75f09c18646a9da87c25e055bc57f113121ad1ec63d45e7a1d62ab\
        9133f8b7d1d7de9e0afa784eb6a8a11d78683013d0a672611f17668d9577d209";
    let mut h = Blake2b::new();
    h.update(&message).unwrap();
    let res = h.finalize().unwrap();
    assert_eq!(hex::encode(&res), expected);
}

#[test]
fn test_blake2s_multiblock() {
    let message = vec![b'a'; 100];
    let expected = "214f24fe1118eb854450238e11bebe22d2e3937ed85c7c96c6c010106b752ad3";
    let mut h = Blake2s::new();
    h.update(&message).unwrap();
    let res = h.finalize().unwrap();
    assert_eq!(hex::encode(&res), expected);
}

#[test]
fn test_blake2b_custom_length() {
    let message = b"BLAKE2 supports custom output sizes";
    // 32-byte output
    let expected_32 = "4266cdaabc5169700801c549cab5dd84737ea19aadc6f96febb8b62856ebd5de";
    let mut h_32 = Blake2b::with_output_size(32);
    h_32.update(message).unwrap();
    let res_32 = h_32.finalize().unwrap();
    assert_eq!(res_32.len(), 32);
    assert_eq!(hex::encode(&res_32), expected_32);
    // 16-byte output
    let expected_16 = "21ec55723d5d4dd17568550d35d20be5";
    let mut h_16 = Blake2b::with_output_size(16);
    h_16.update(message).unwrap();
    let res_16 = h_16.finalize().unwrap();
    assert_eq!(res_16.len(), 16);
    assert_eq!(hex::encode(&res_16), expected_16);
}

#[test]
fn test_blake2s_custom_length() {
    let message = b"BLAKE2 supports custom output sizes";
    // 16-byte output
    let expected_16 = "c3934711085c446a98089fb8779baf6d";
    let mut h_16 = Blake2s::with_output_size(16);
    h_16.update(message).unwrap();
    let res_16 = h_16.finalize().unwrap();
    assert_eq!(res_16.len(), 16);
    assert_eq!(hex::encode(&res_16), expected_16);
    // 8-byte output
    let expected_8 = "58ed9f2e1c7110ec";
    let mut h_8 = Blake2s::with_output_size(8);
    h_8.update(message).unwrap();
    let res_8 = h_8.finalize().unwrap();
    assert_eq!(res_8.len(), 8);
    assert_eq!(hex::encode(&res_8), expected_8);
}

#[test]
fn test_blake2b_incremental() {
    let message = b"This message will be hashed in multiple updates";
    let mut h1 = Blake2b::new();
    h1.update(message).unwrap();
    let res1 = h1.finalize().unwrap();
    let mut h2 = Blake2b::new();
    h2.update(&message[0..10]).unwrap();
    h2.update(&message[10..20]).unwrap();
    h2.update(&message[20..]).unwrap();
    let res2 = h2.finalize().unwrap();
    assert_eq!(res1, res2);
}

#[test]
fn test_blake2s_incremental() {
    let message = b"This message will be hashed in multiple updates";
    let mut h1 = Blake2s::new();
    h1.update(message).unwrap();
    let res1 = h1.finalize().unwrap();
    let mut h2 = Blake2s::new();
    h2.update(&message[0..10]).unwrap();
    h2.update(&message[10..20]).unwrap();
    h2.update(&message[20..]).unwrap();
    let res2 = h2.finalize().unwrap();
    assert_eq!(res1, res2);
}

#[test]
fn test_blake2b_boundary_sizes() {
    let test_sizes = [127, 128, 129];
    for &size in &test_sizes {
        let message = vec![b'x'; size];
        let mut h1 = Blake2b::new();
        h1.update(&message).unwrap();
        let r1 = h1.finalize().unwrap();
        let mut h2 = Blake2b::new();
        let split = size / 2;
        h2.update(&message[..split]).unwrap();
        h2.update(&message[split..]).unwrap();
        let r2 = h2.finalize().unwrap();
        assert_eq!(r1, r2, "Failed for size {}", size);
    }
}

#[test]
fn test_blake2s_boundary_sizes() {
    let test_sizes = [63, 64, 65];
    for &size in &test_sizes {
        let message = vec![b'x'; size];
        let mut h1 = Blake2s::new();
        h1.update(&message).unwrap();
        let r1 = h1.finalize().unwrap();
        let mut h2 = Blake2s::new();
        let split = size / 2;
        h2.update(&message[..split]).unwrap();
        h2.update(&message[split..]).unwrap();
        let r2 = h2.finalize().unwrap();
        assert_eq!(r1, r2, "Failed for size {}", size);
    }
}

#[test]
fn test_blake2b_vectors() {
    let test_vectors = [
        (
            b"".as_ref(),
            "\
            786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
            d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
        ),
        (
            b"The quick brown fox jumps over the lazy dog".as_ref(),
            "\
            a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673\
            f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918",
        ),
        (
            b"The quick brown fox jumps over the lazy dof".as_ref(),
            "\
            ab6b007747d8068c02e25a6008db8a77c218d94f3b40d2291a7dc8a62090a744c\
            082ea27af01521a102e42f480a31e9844053f456b4b41e8aa78bbe5c12957bb",
        ),
    ];
    for (i, &(msg, exp)) in test_vectors.iter().enumerate() {
        let mut h = Blake2b::new();
        h.update(msg).unwrap();
        let out = h.finalize().unwrap();
        assert_eq!(hex::encode(&out), exp, "Failed test vector {}", i);
    }
}

#[test]
fn test_blake2s_vectors() {
    let test_vectors = [
        (
            b"".as_ref(),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
        ),
        (
            b"The quick brown fox jumps over the lazy dog".as_ref(),
            "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812",
        ),
        (
            b"The quick brown fox jumps over the lazy dof".as_ref(),
            "ae8ce27c652988829d43a30e38a710e59c5adacab9076d8289d0f44976a567e8",
        ),
    ];
    for (i, &(msg, exp)) in test_vectors.iter().enumerate() {
        let mut h = Blake2s::new();
        h.update(msg).unwrap();
        let out = h.finalize().unwrap();
        assert_eq!(hex::encode(&out), exp, "Failed test vector {}", i);
    }
}
