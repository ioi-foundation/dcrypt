use super::*;
use crate::types::Tag;
use dcrypt_internal::random::{ChaCha20Rng, RngCore};
use hex;

fn rfc_key() -> [u8; 32] {
    hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn test_poly1305_rfc8439_vector() {
    let key = rfc_key();
    let mut p = Poly1305::new(&key).unwrap();
    let msg = b"Cryptographic Forum Research Group";
    p.update(msg).unwrap();
    assert_eq!(
        p.finalize(),
        Tag::<16>::from_slice(&hex::decode("a8061dc1305136c6c22b8baf0c0127a9").unwrap()).unwrap()
    );
}

#[test]
fn test_empty_message() {
    let key = rfc_key();
    let tag = Poly1305::new(&key).unwrap().finalize();
    let mut expected = [0u8; 16];
    expected.copy_from_slice(&key[16..32]);
    assert_eq!(tag, Tag::<16>::new(expected));
}

#[test]
fn test_chunked_vs_single_update() {
    let key = rfc_key();
    let msg: Vec<u8> = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".to_vec();
    let mut p1 = Poly1305::new(&key).unwrap();
    p1.update(&msg).unwrap();
    let mut p2 = Poly1305::new(&key).unwrap();
    for b in &msg {
        p2.update(&[*b]).unwrap();
    }
    assert_eq!(p1.finalize(), p2.finalize());
}

#[test]
fn test_hello_message() {
    let key = rfc_key();
    let mut p = Poly1305::new(&key).unwrap();
    p.update(b"Hello").unwrap();
    assert_eq!(
        p.finalize(),
        Tag::<16>::from_slice(&hex::decode("f74f694dcdf0d5131ed59f4b4e760495").unwrap()).unwrap()
    );
}

#[test]
fn test_single_block_message() {
    let key = rfc_key();
    let mut p = Poly1305::new(&key).unwrap();
    p.update(b"0123456789ABCDEF").unwrap();
    assert_eq!(
        p.finalize(),
        Tag::<16>::from_slice(&hex::decode("e70d564ce526627cb2f56c7657604601").unwrap()).unwrap()
    );
}

#[test]
fn test_multi_block_message() {
    let key = rfc_key();
    let msg = b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    let mut p = Poly1305::new(&key).unwrap();
    p.update(msg).unwrap();
    assert_eq!(
        p.finalize(),
        Tag::<16>::from_slice(&hex::decode("8253fca07713cc36043e7aed25d35085").unwrap()).unwrap()
    );
}

#[test]
fn test_poly1305_rfc8439_vector2() {
    let mut key = [0u8; 32];
    key[16..32].copy_from_slice(&hex::decode("36e5f6b5c5e06070f0efca96227a863e").unwrap());
    let mut p = Poly1305::new(&key).unwrap();
    let text = b"Any submission to the IETF intended by the Contributor for \
publication as all or part of an IETF Internet-Draft or RFC";
    p.update(text).unwrap();
    assert_eq!(
        p.finalize(),
        Tag::<16>::from_slice(&hex::decode("36e5f6b5c5e06070f0efca96227a863e").unwrap()).unwrap()
    );
}

#[test]
fn test_poly1305_rfc8439_vector5() {
    let mut key = [0u8; 32];
    key[0] = 0x02;
    let mut p = Poly1305::new(&key).unwrap();
    p.update(&[0xFFu8; 16]).unwrap();
    assert_eq!(
        p.finalize(),
        Tag::<16>::from_slice(&hex::decode("03000000000000000000000000000000").unwrap()).unwrap()
    );
}

#[test]
fn test_poly1305_rfc8439_vector6() {
    let mut key = [0u8; 32];
    key[0] = 0x02;
    for b in &mut key[16..32] {
        *b = 0xFF;
    }
    let mut p = Poly1305::new(&key).unwrap();
    let mut block = [0u8; 16];
    block[0] = 0x02;
    p.update(&block).unwrap();
    assert_eq!(
        p.finalize(),
        Tag::<16>::from_slice(&hex::decode("03000000000000000000000000000000").unwrap()).unwrap()
    );
}

#[test]
fn test_poly1305_rfc8439_vector7() {
    let mut key = [0u8; 32];
    key[0] = 0x01;
    let mut p = Poly1305::new(&key).unwrap();
    p.update(&[0xFFu8; 16]).unwrap();
    let mut b2 = [0xFFu8; 16];
    b2[0] = 0xF0;
    p.update(&b2).unwrap();
    let mut b3 = [0u8; 16];
    b3[0] = 0x11;
    p.update(&b3).unwrap();
    assert_eq!(
        p.finalize(),
        Tag::<16>::from_slice(&hex::decode("05000000000000000000000000000000").unwrap()).unwrap()
    );
}

#[test]
fn test_poly1305_rfc8439_vector8() {
    let mut key = [0u8; 32];
    key[0] = 0x01;
    let mut p = Poly1305::new(&key).unwrap();
    p.update(&[0xFFu8; 16]).unwrap();
    let mut b2 = [0xFEu8; 16];
    b2[0] = 0xFB;
    p.update(&b2).unwrap();
    p.update(&[0x01u8; 16]).unwrap();
    assert_eq!(
        p.finalize(),
        Tag::<16>::from_slice(&hex::decode("00000000000000000000000000000000").unwrap()).unwrap()
    );
}

#[test]
fn test_poly1305_rfc8439_vector10() {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&hex::decode("01000000000000000400000000000000").unwrap());
    let data = hex::decode(
        "e33594d7505e43b90000000000000000\
         3394d7505e4379cd0100000000000000\
         00000000000000000000000000000000\
         01000000000000000000000000000000",
    )
    .unwrap();
    let mut p = Poly1305::new(&key).unwrap();
    p.update(&data).unwrap();
    assert_eq!(
        p.finalize(),
        Tag::<16>::from_slice(&hex::decode("14000000000000005500000000000000").unwrap()).unwrap()
    );
}

#[test]
fn test_poly1305_rfc8439_vector11() {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&hex::decode("01000000000000000400000000000000").unwrap());
    let data = hex::decode(
        "e33594d7505e43b90000000000000000\
         3394d7505e4379cd0100000000000000\
         00000000000000000000000000000000",
    )
    .unwrap();
    let mut p = Poly1305::new(&key).unwrap();
    p.update(&data).unwrap();
    assert_eq!(
        p.finalize(),
        Tag::<16>::from_slice(&hex::decode("13000000000000000000000000000000").unwrap()).unwrap()
    );
}

#[test]
fn random_vs_chunked_update() {
    let mut rng = ChaCha20Rng::from_seed([0x12; 32]);
    for _ in 0..1_000 {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let msg_len = (rng.next_u32() % 256) as usize;
        let mut msg = vec![0u8; msg_len];
        rng.fill_bytes(&mut msg);
        let mut p1 = Poly1305::new(&key).unwrap();
        p1.update(&msg).unwrap();
        let mut p2 = Poly1305::new(&key).unwrap();
        let mut off = 0;
        while off < msg_len {
            let c = ((rng.next_u32() % 16) + 1) as usize;
            let end = usize::min(off + c, msg_len);
            p2.update(&msg[off..end]).unwrap();
            off = end;
        }
        assert_eq!(p1.finalize(), p2.finalize());
    }
}

#[test]
fn random_empty_update() {
    let mut rng = ChaCha20Rng::from_seed([0x0f; 32]);
    for _ in 0..100 {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let mut p = Poly1305::new(&key).unwrap();
        p.update(&[]).unwrap();
        p.update(&[]).unwrap();
        let mut expected = [0u8; 16];
        expected.copy_from_slice(&key[16..32]);
        assert_eq!(p.finalize(), Tag::<16>::new(expected));
    }
}
