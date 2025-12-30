//! Cryptographic operation benchmarks.
//!
//! Measures performance of core cryptographic primitives to ensure
//! they meet the latency budget constraint (<15% overhead).

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use scf::crypto::{Aead, AeadKey, EphemeralSecret, Hkdf, Nonce, PublicKey, SessionKeys, StaticSecret};

fn bench_x25519_keygen(c: &mut Criterion) {
    c.bench_function("x25519_keygen", |b| {
        b.iter(|| {
            let secret = EphemeralSecret::random();
            black_box(PublicKey::from(&secret))
        })
    });
}

fn bench_x25519_dh(c: &mut Criterion) {
    let alice_secret = StaticSecret::random();
    let bob_secret = StaticSecret::random();
    let bob_public = PublicKey::from(&bob_secret);

    c.bench_function("x25519_dh", |b| {
        b.iter(|| {
            black_box(alice_secret.diffie_hellman(&bob_public))
        })
    });
}

fn bench_chacha20_encrypt(c: &mut Criterion) {
    let key = AeadKey::from_bytes([0x42u8; 32]);
    let aead = Aead::new(&key);
    let nonce = Nonce::new(0);
    let plaintext = vec![0u8; 1200]; // Typical packet size
    let aad = b"";

    let mut group = c.benchmark_group("chacha20_encrypt");
    group.throughput(Throughput::Bytes(1200));

    group.bench_function("1200_bytes", |b| {
        b.iter(|| {
            black_box(aead.encrypt(&nonce, &plaintext, aad).unwrap())
        })
    });

    group.finish();
}

fn bench_chacha20_decrypt(c: &mut Criterion) {
    let key = AeadKey::from_bytes([0x42u8; 32]);
    let aead = Aead::new(&key);
    let nonce = Nonce::new(0);
    let plaintext = vec![0u8; 1200];
    let aad = b"";
    let ciphertext = aead.encrypt(&nonce, &plaintext, aad).unwrap();

    let mut group = c.benchmark_group("chacha20_decrypt");
    group.throughput(Throughput::Bytes(1200));

    group.bench_function("1200_bytes", |b| {
        b.iter(|| {
            black_box(aead.decrypt(&nonce, &ciphertext, aad).unwrap())
        })
    });

    group.finish();
}

fn bench_hkdf_derive(c: &mut Criterion) {
    let ikm = [0x42u8; 32];
    let salt = [0x00u8; 32];
    let info = b"test_context";

    c.bench_function("hkdf_derive_64_bytes", |b| {
        b.iter(|| {
            let hkdf = Hkdf::new(Some(&salt), &ikm);
            black_box(hkdf.expand(info, 64).unwrap())
        })
    });
}

fn bench_session_keys_derive(c: &mut Criterion) {
    let server_static = StaticSecret::random();
    let server_public = PublicKey::from(&server_static);
    let client_ephemeral = EphemeralSecret::random();
    let shared = client_ephemeral.diffie_hellman(&server_public);

    c.bench_function("session_keys_derive", |b| {
        b.iter(|| {
            black_box(SessionKeys::derive(&shared, b"test_context"))
        })
    });
}

fn bench_full_handshake_crypto(c: &mut Criterion) {
    // Simulate full handshake cryptographic operations
    c.bench_function("full_handshake_crypto", |b| {
        b.iter(|| {
            // Server static key (pre-existing)
            let server_static = StaticSecret::random();
            let server_public = PublicKey::from(&server_static);

            // Client generates ephemeral
            let client_ephemeral = EphemeralSecret::random();
            let client_public = PublicKey::from(&client_ephemeral);

            // Client computes shared secret
            let client_shared = client_ephemeral.diffie_hellman(&server_public);

            // Server computes shared secret
            let server_shared = server_static.diffie_hellman(&client_public);

            // Derive session keys
            let _client_keys = SessionKeys::derive(&client_shared, b"handshake");
            let _server_keys = SessionKeys::derive(&server_shared, b"handshake");

            black_box(())
        })
    });
}

criterion_group!(
    benches,
    bench_x25519_keygen,
    bench_x25519_dh,
    bench_chacha20_encrypt,
    bench_chacha20_decrypt,
    bench_hkdf_derive,
    bench_session_keys_derive,
    bench_full_handshake_crypto,
);

criterion_main!(benches);
