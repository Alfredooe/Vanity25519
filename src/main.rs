use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use std::env;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// SSH wire-format header for Ed25519 public keys (19 bytes).
// The 32-byte compressed public key is appended immediately after.
const SSH_PUBKEY_HEADER: [u8; 19] = [
    0x00, 0x00, 0x00, 0x0b,                                             // key-type length: 11
    b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', // "ssh-ed25519"
    0x00, 0x00, 0x00, 0x20,                                             // key length: 32
];

struct FoundResult {
    target: String,
    ssh_b64: String,
    pem_body: String,
}

fn parse_input_file(path: &str) -> Result<Vec<String>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read input file '{}': {}", path, e))?;
    let targets: Vec<String> = content.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_lowercase())
        .collect();
    if targets.is_empty() {
        return Err(format!("Input file '{}' contains no targets", path));
    }
    Ok(targets)
}

fn write_result_block(file: &mut impl std::io::Write, target: &str, ssh_b64: &str, pem_body: &str) {
    writeln!(file, "================================================================================").unwrap();
    writeln!(file, "Target: {}", target).unwrap();
    writeln!(file, "SSH Public Key: ssh-ed25519 {}", ssh_b64).unwrap();
    writeln!(file, "Private Key (PEM):").unwrap();
    writeln!(file, "-----BEGIN PRIVATE KEY-----").unwrap();
    writeln!(file, "{}", pem_body).unwrap();
    writeln!(file, "-----END PRIVATE KEY-----").unwrap();
    writeln!(file, "================================================================================").unwrap();
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut positional_target: Option<String> = None;
    let mut threads: Option<usize> = None;
    let mut input_file: Option<String> = None;
    let mut output_file: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--threads" && i + 1 < args.len() {
            threads = args[i + 1].parse().ok();
            i += 2;
        } else if args[i] == "--input" && i + 1 < args.len() {
            input_file = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--output" && i + 1 < args.len() {
            output_file = Some(args[i + 1].clone());
            i += 2;
        } else if positional_target.is_none() && !args[i].starts_with('-') {
            positional_target = Some(args[i].to_lowercase());
            i += 1;
        } else {
            eprintln!("Unknown argument: {}", args[i]);
            eprintln!("Usage: {} [<target>] [--input <file>] [--output <file>] [--threads N]", args[0]);
            std::process::exit(1);
        }
    }

    // Collect targets: positional + input file, deduplicated
    let mut targets: Vec<String> = Vec::new();
    if let Some(ref t) = positional_target {
        targets.push(t.clone());
    }
    if let Some(ref path) = input_file {
        match parse_input_file(path) {
            Ok(file_targets) => {
                for t in file_targets {
                    if !targets.contains(&t) {
                        targets.push(t);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }
    if targets.is_empty() {
        eprintln!("Usage: {} [<target>] [--input <file>] [--output <file>] [--threads N]", args[0]);
        eprintln!("Error: at least one target is required (positional or via --input)");
        std::process::exit(1);
    }

    if let Some(n) = threads {
        rayon::ThreadPoolBuilder::new().num_threads(n).build_global().ok();
    }

    // Precompute patterns for all targets: each target gets 4 patterns + its index
    let all_patterns: Vec<([String; 4], usize)> = targets.iter().enumerate().map(|(idx, target)| {
        ([
            format!("+{}+", target),
            format!("+{}/", target),
            format!("/{}+", target),
            format!("/{}/", target),
        ], idx)
    }).collect();

    let target_count = targets.len();
    let remaining = Arc::new(AtomicUsize::new(target_count));
    let target_found: Arc<Vec<AtomicBool>> = Arc::new(
        (0..target_count).map(|_| AtomicBool::new(false)).collect()
    );
    let results: Arc<Mutex<Vec<FoundResult>>> = Arc::new(Mutex::new(Vec::new()));
    let attempts = Arc::new(AtomicU64::new(0));

    // Banner
    println!(
        "Starting vanity search on {} threads",
        rayon::current_num_threads()
    );
    println!("Targets ({}):", target_count);
    for t in &targets {
        println!("  \"{}\"", t);
    }
    println!("Match rule: [+|/]TARGET[+|/]");
    if let Some(ref path) = output_file {
        println!("Output file: {}", path);
    }

    let start = std::time::Instant::now();

    (0..rayon::current_num_threads())
        .into_par_iter()
        .for_each(|_| {
            let mut rng = ChaCha20Rng::from_entropy();
            let mut local_count: u64 = 0;
            const BATCH_SIZE: u64 = 256;
            let mut blob = [0u8; 51];
            blob[..19].copy_from_slice(&SSH_PUBKEY_HEADER);
            let mut local_skip: u64 = 0; // bitmask for up to 64 targets

            while remaining.load(Ordering::Relaxed) > 0 {
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

                // Check against all targets
                for &(ref patterns, idx) in &all_patterns {
                    // Skip already-found targets (local bitmask, up to 64)
                    if idx < 64 && (local_skip >> idx) & 1 == 1 {
                        continue;
                    }
                    // Check shared flag
                    if target_found[idx].load(Ordering::Relaxed) {
                        if idx < 64 {
                            local_skip |= 1u64 << idx;
                        }
                        continue;
                    }
                    // Check if any of the 4 patterns match
                    if patterns.iter().any(|p| ssh_lower.contains(p.as_str())) {
                        // Try to claim this target
                        if target_found[idx].compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed).is_ok() {
                            // We won the race — build PEM and record result
                            let priv_der = key.to_pkcs8_der().unwrap();
                            let priv_b64 = general_purpose::STANDARD.encode(priv_der.as_bytes());
                            let pem_body: String = priv_b64
                                .as_bytes()
                                .chunks(64)
                                .map(|c| std::str::from_utf8(c).unwrap())
                                .collect::<Vec<_>>()
                                .join("\n");

                            let prev_remaining = remaining.fetch_sub(1, Ordering::Relaxed);
                            let found_so_far = target_count - prev_remaining + 1;
                            println!("\n[+] Found {}/{}: \"{}\"", found_so_far, target_count, targets[idx]);

                            results.lock().unwrap().push(FoundResult {
                                target: targets[idx].clone(),
                                ssh_b64: ssh_b64.clone(),
                                pem_body,
                            });
                        }
                        // Whether we won or lost, set local skip and stop checking other targets for this key
                        if idx < 64 {
                            local_skip |= 1u64 << idx;
                        }
                        break;
                    }
                }
            }

            // Flush remaining local count to the shared counter
            let remainder = local_count % BATCH_SIZE;
            if remainder > 0 {
                attempts.fetch_add(remainder, Ordering::Relaxed);
            }
        });

    let elapsed = start.elapsed().as_secs_f64();
    let total_attempts = attempts.load(Ordering::Relaxed);
    let avg_rate = if elapsed > 0.0 { total_attempts as f64 / elapsed } else { 0.0 };

    // Print all results to stdout
    let final_results = results.lock().unwrap();
    for result in final_results.iter() {
        println!("\n--- {} ---", result.target);
        println!("SSH Public Key (authorized_keys):");
        println!("ssh-ed25519 {}", result.ssh_b64);
        println!("\nPrivate Key (PEM):");
        println!("-----BEGIN PRIVATE KEY-----");
        println!("{}", result.pem_body);
        println!("-----END PRIVATE KEY-----");
    }

    // Write to output file if specified (append mode)
    if let Some(ref path) = output_file {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap_or_else(|e| {
                eprintln!("Error: failed to open output file '{}': {}", path, e);
                std::process::exit(1);
            });
        for result in final_results.iter() {
            write_result_block(&mut file, &result.target, &result.ssh_b64, &result.pem_body);
        }
    }

    println!("\nElapsed: {:.2}s", elapsed);
    println!("Average rate: {:.2} keys/sec", avg_rate);
}
