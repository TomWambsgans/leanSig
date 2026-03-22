//! Generates a test vector for the standalone verifier.
//! Uses SchemeAbortingTargetSumLifetime32Dim64Base8.
//!
//! Run with: cargo run --release --example export_test_vector

use leansig::signature::SignatureScheme;
use leansig::signature::generalized_xmss::instantiations_aborting::lifetime_2_to_the_32::SchemeAbortingTargetSumLifetime32Dim64Base8;
use rand::RngExt;
use ssz::Encode;
use std::io::Write;

type Sig = SchemeAbortingTargetSumLifetime32Dim64Base8;

fn main() {
    let mut rng = rand::rng();

    let activation_epoch = 1000;
    let num_active_epochs = 64;
    let epoch: u32 = activation_epoch + 5;

    eprintln!("Generating keys (LOG_LIFETIME=32, activation={activation_epoch}, {num_active_epochs} active epochs)...");
    let (pk, sk) = Sig::key_gen(&mut rng, activation_epoch as usize, num_active_epochs);

    let message: [u8; 32] = rng.random();

    eprintln!("Signing at epoch {epoch}...");
    let sig = Sig::sign(&sk, epoch, &message).expect("signing failed");
    assert!(Sig::verify(&pk, epoch, &message, &sig), "self-verify failed");

    let pk_bytes = pk.as_ssz_bytes();
    let sig_bytes = sig.as_ssz_bytes();

    let mut out = std::fs::File::create("test_vector.bin").unwrap();
    out.write_all(&epoch.to_le_bytes()).unwrap();
    out.write_all(&message).unwrap();
    out.write_all(&(pk_bytes.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&pk_bytes).unwrap();
    out.write_all(&(sig_bytes.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&sig_bytes).unwrap();

    let total = 4 + 32 + 4 + pk_bytes.len() + 4 + sig_bytes.len();
    eprintln!("Wrote test_vector.bin ({total} bytes)");
    eprintln!("  pk: {} bytes, sig: {} bytes", pk_bytes.len(), sig_bytes.len());
}
