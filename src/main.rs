use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use std::env;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <target>", args[0]);
        std::process::exit(1);
    }

    let target = args[1].to_lowercase();
    let patterns = [
        format!("+{}+", target),
        format!("+{}/", target),
        format!("/{}+", target),
        format!("/{}/", target),
    ];
    let found = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));

    println!(
        "Starting vanity search on {} threads",
        rayon::current_num_threads()
    );
    println!("Target: \"{}\"", target);
    println!("Match rule: [+|/]TARGET[+|/]");

    (0..rayon::current_num_threads())
        .into_par_iter()
        .for_each(|_| {
            let mut rng = ChaCha20Rng::from_entropy();
            let mut local_count: u64 = 0;
            const BATCH_SIZE: u64 = 256;

            while !found.load(Ordering::Relaxed) {
                let key = SigningKey::generate(&mut rng);
                let pub_der = key
                    .verifying_key()
                    .to_public_key_der()
                    .unwrap();

                let pub_b64 = general_purpose::STANDARD.encode(pub_der.as_bytes());
                let pub_lower = pub_b64.to_lowercase();

                local_count += 1;
                if local_count % BATCH_SIZE == 0 {
                    let count = attempts.fetch_add(BATCH_SIZE, Ordering::Relaxed);
                    if count % 50_000 < BATCH_SIZE {
                        print!("\rAttempts: {}", count);
                    }
                }

                if patterns.iter().any(|p| pub_lower.contains(p)) {
                    found.store(true, Ordering::Relaxed);
                    let final_count = attempts.fetch_add(local_count % BATCH_SIZE, Ordering::Relaxed);

                    let priv_der = key.to_pkcs8_der().unwrap();
                    let priv_b64 =
                        general_purpose::STANDARD.encode(priv_der.as_bytes());

                    println!("\n\nMATCH FOUND");
                    println!("Attempts: ~{}", final_count + (local_count % BATCH_SIZE));
                    println!("\nPublic Key (Base64 DER):\n{}", pub_b64);
                    println!("\nPrivate Key (Base64 DER):\n{}", priv_b64);
                    break;
                }
            }
        });
}
