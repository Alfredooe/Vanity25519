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
        eprintln!("Usage: {} <target> [--threads N]", args[0]);
        std::process::exit(1);
    }

    let mut target = String::new();
    let mut threads: Option<usize> = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--threads" && i + 1 < args.len() {
            threads = args[i + 1].parse().ok();
            i += 2;
        } else if target.is_empty() {
            target = args[i].to_lowercase();
            i += 1;
        } else {
            i += 1;
        }
    }
    if target.is_empty() {
        eprintln!("Usage: {} <target> [--threads N]", args[0]);
        std::process::exit(1);
    }
    if let Some(n) = threads {
        rayon::ThreadPoolBuilder::new().num_threads(n).build_global().ok();
    }
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

    let start = std::time::Instant::now();
    let result = (0..rayon::current_num_threads())
        .into_par_iter()
        .map(|_| {
            let mut rng = ChaCha20Rng::from_entropy();
            let mut local_count: u64 = 0;
            const BATCH_SIZE: u64 = 256;
            let mut blob = [0u8; 51];
            blob[..19].copy_from_slice(&SSH_PUBKEY_HEADER);
            let mut found_key = None;

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

                    found_key = Some((final_count + (local_count % BATCH_SIZE), ssh_b64, pem_body));
                    break;
                }
            }
            (local_count, found_key)
        })
        .reduce(|| (0u64, None), |mut acc, x| {
            acc.0 += x.0;
            if acc.1.is_none() && x.1.is_some() {
                acc.1 = x.1;
            }
            acc
        });

    let elapsed = start.elapsed().as_secs_f64();
    let total_attempts = attempts.load(Ordering::Relaxed);
    let avg_rate = if elapsed > 0.0 { total_attempts as f64 / elapsed } else { 0.0 };

    if let Some((final_count, ssh_b64, pem_body)) = result.1 {
        println!("\n\nMATCH FOUND");
        println!("Attempts: ~{}", final_count);
        println!("\nSSH Public Key (authorized_keys):");
        println!("ssh-ed25519 {}", ssh_b64);
        println!("\nPrivate Key (PEM):");
        println!("-----BEGIN PRIVATE KEY-----");
        println!("{}", pem_body);
        println!("-----END PRIVATE KEY-----");
    }
    println!("\nElapsed: {:.2}s", elapsed);
    println!("Average rate: {:.2} keys/sec", avg_rate);
}
