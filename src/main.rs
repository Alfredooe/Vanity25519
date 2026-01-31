use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use std::env;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

// SSH wire-format header for Ed25519 public keys (19 bytes).
// The 32-byte compressed public key is appended immediately after.
const SSH_PUBKEY_HEADER: [u8; 19] = [
    0x00, 0x00, 0x00, 0x0b,                                             // key-type length: 11
    b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', // "ssh-ed25519"
    0x00, 0x00, 0x00, 0x20,                                             // key length: 32
];

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
            let mut blob = [0u8; 51];
            blob[..19].copy_from_slice(&SSH_PUBKEY_HEADER);

            while !found.load(Ordering::Relaxed) {
                let key = SigningKey::generate(&mut rng);
                blob[19..].copy_from_slice(key.verifying_key().as_bytes());

                let ssh_b64 = general_purpose::STANDARD.encode(&blob);
                let ssh_lower = ssh_b64.to_lowercase();

                local_count += 1;
                if local_count % BATCH_SIZE == 0 {
                    let count = attempts.fetch_add(BATCH_SIZE, Ordering::Relaxed);
                    if count % 50_000 < BATCH_SIZE {
                        print!("\rAttempts: {}", count);
                    }
                }

                if patterns.iter().any(|p| ssh_lower.contains(p)) {
                    found.store(true, Ordering::Relaxed);
                    let final_count =
                        attempts.fetch_add(local_count % BATCH_SIZE, Ordering::Relaxed);

                    let priv_der = key.to_pkcs8_der().unwrap();
                    let priv_b64 =
                        general_purpose::STANDARD.encode(priv_der.as_bytes());
                    let pem_body: String = priv_b64
                        .as_bytes()
                        .chunks(64)
                        .map(|c| std::str::from_utf8(c).unwrap())
                        .collect::<Vec<_>>()
                        .join("\n");

                    println!("\n\nMATCH FOUND");
                    println!(
                        "Attempts: ~{}",
                        final_count + (local_count % BATCH_SIZE)
                    );
                    println!("\nSSH Public Key (authorized_keys):");
                    println!("ssh-ed25519 {}", ssh_b64);
                    println!("\nPrivate Key (PEM):");
                    println!("-----BEGIN PRIVATE KEY-----");
                    println!("{}", pem_body);
                    println!("-----END PRIVATE KEY-----");
                    break;
                }
            }
        });
}
