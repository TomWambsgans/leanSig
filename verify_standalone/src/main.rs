//! Standalone GeneralizedXMSS signature verifier.
//!
//! Reimplements the verification algorithm from scratch, using only the
//! Plonky3 KoalaBear Poseidon1 permutation as an external dependency.
//!
//! Parameters (matching SchemeAbortingTargetSumLifetime32Dim46Base8):
//!   PARAMETER_LEN  = 5    HASH_LEN     = 8    TWEAK_LEN  = 2
//!   CAPACITY       = 9    NUM_CHUNKS   = 46    BASE       = 8
//!   TARGET_SUM     = 200  LOG_LIFETIME = 6 (test) / 32 (prod)
//!   MSG_HASH_LEN_FE = 8   MSG_LEN_FE  = 9     RAND_LEN   = 7
//!   Z = 8, Q = 127  (aborting hypercube message hash)

use num_bigint::BigUint;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_koala_bear::{KoalaBear, default_koalabear_poseidon1_16, default_koalabear_poseidon1_24};
use p3_symmetric::CryptographicPermutation;
use std::io::Read;

type F = KoalaBear;

// ─── Scheme parameters ──────────────────────────────────────────────────────
const PARAMETER_LEN: usize = 5;
const HASH_LEN: usize = 8;
const TWEAK_LEN: usize = 2;
const CAPACITY: usize = 9;
const NUM_CHUNKS: usize = 46;
const BASE: usize = 8;
const TARGET_SUM: usize = 200;
const LOG_LIFETIME: usize = 32;
const MSG_HASH_LEN_FE: usize = 8;
const MSG_LEN_FE: usize = 9;
const RAND_LEN: usize = 7;
const MESSAGE_LENGTH: usize = 32;

// Aborting hypercube parameters
const Z: usize = 8; // digits per field element
const Q: u64 = 127; // rejection threshold factor
const THRESHOLD: u64 = Q * (BASE as u64).pow(Z as u32); // Q * w^z

const TWEAK_SEPARATOR_CHAIN: u8 = 0x00;
const TWEAK_SEPARATOR_TREE: u8 = 0x01;
const TWEAK_SEPARATOR_MSG: u8 = 0x02;

// ─── Poseidon compression ────────────────────────────────────────────────────
// Compress(x) = Truncate(Perm(pad(x)) + pad(x))

fn poseidon_compress_16(
    perm: &impl CryptographicPermutation<[F; 16]>,
    input: &[F],
) -> [F; HASH_LEN] {
    let mut padded = [F::ZERO; 16];
    padded[..input.len()].copy_from_slice(input);
    let mut state = padded;
    perm.permute_mut(&mut state);
    for i in 0..16 {
        state[i] += padded[i];
    }
    state[..HASH_LEN].try_into().unwrap()
}

fn poseidon_compress_24<const OUT: usize>(
    perm: &impl CryptographicPermutation<[F; 24]>,
    input: &[F],
) -> [F; OUT] {
    let mut padded = [F::ZERO; 24];
    padded[..input.len()].copy_from_slice(input);
    let mut state = padded;
    perm.permute_mut(&mut state);
    for i in 0..24 {
        state[i] += padded[i];
    }
    std::array::from_fn(|i| state[i])
}

// ─── Domain separator for sponge ─────────────────────────────────────────────

fn poseidon_safe_domain_separator(
    perm: &impl CryptographicPermutation<[F; 24]>,
    params: &[u32; 4],
) -> [F; CAPACITY] {
    let mut acc: u128 = 0;
    for &p in params {
        acc = (acc << 32) | (p as u128);
    }
    let order = F::ORDER_U64 as u128;
    let input: [F; 24] = std::array::from_fn(|_| {
        let digit = (acc % order) as u64;
        acc /= order;
        F::from_u64(digit)
    });
    poseidon_compress_24::<CAPACITY>(perm, &input)
}

// ─── Replacement T-Sponge ────────────────────────────────────────────────────

fn poseidon_replacement_t_sponge(
    perm: &impl CryptographicPermutation<[F; 24]>,
    capacity_value: &[F],
    input: &[F],
) -> [F; HASH_LEN] {
    let cap_len = capacity_value.len();
    let rate = 24 - cap_len;

    let mut state = [F::ZERO; 24];
    state[..cap_len].copy_from_slice(capacity_value);

    // Absorb full chunks
    let mut it = input.chunks_exact(rate);
    for chunk in &mut it {
        for (s, &x) in state[cap_len..].iter_mut().zip(chunk) {
            *s = x;
        }
        state = poseidon_compress_24::<24>(perm, &state);
    }
    // Absorb remainder + zero-pad
    if !it.remainder().is_empty() {
        let rem = it.remainder();
        for (i, &x) in rem.iter().enumerate() {
            state[cap_len + i] = x;
        }
        for s in &mut state[cap_len + rem.len()..] {
            *s = F::ZERO;
        }
        state = poseidon_compress_24::<24>(perm, &state);
    }

    // Squeeze (HASH_LEN <= rate, so one squeeze suffices)
    std::array::from_fn(|i| state[cap_len + i])
}

// ─── Tweak encoding ─────────────────────────────────────────────────────────

fn chain_tweak_fe(epoch: u32, chain_index: u8, pos_in_chain: u8) -> [F; TWEAK_LEN] {
    let mut acc = ((epoch as u128) << 24)
        | ((chain_index as u128) << 16)
        | ((pos_in_chain as u128) << 8)
        | (TWEAK_SEPARATOR_CHAIN as u128);
    let order = F::ORDER_U64 as u128;
    std::array::from_fn(|_| {
        let digit = (acc % order) as u64;
        acc /= order;
        F::from_u64(digit)
    })
}

fn tree_tweak_fe(level: u8, pos_in_level: u32) -> [F; TWEAK_LEN] {
    let mut acc = ((level as u128) << 40)
        | ((pos_in_level as u128) << 8)
        | (TWEAK_SEPARATOR_TREE as u128);
    let order = F::ORDER_U64 as u128;
    std::array::from_fn(|_| {
        let digit = (acc % order) as u64;
        acc /= order;
        F::from_u64(digit)
    })
}

// ─── Message encoding ────────────────────────────────────────────────────────

fn encode_message(message: &[u8; MESSAGE_LENGTH]) -> [F; MSG_LEN_FE] {
    let mut acc = BigUint::from_bytes_le(message);
    let order = BigUint::from(F::ORDER_U64);
    std::array::from_fn(|_| {
        let digit: u64 = (&acc % &order).try_into().unwrap();
        acc /= &order;
        F::from_u64(digit)
    })
}

fn encode_epoch(epoch: u32) -> [F; TWEAK_LEN] {
    let acc = ((epoch as u64) << 8) | (TWEAK_SEPARATOR_MSG as u64);
    let order = F::ORDER_U64;
    let mut result = [F::ZERO; TWEAK_LEN];
    if TWEAK_LEN > 0 {
        result[0] = F::from_u64(acc % order);
    }
    if TWEAK_LEN > 1 {
        result[1] = F::from_u64(acc / order);
    }
    result
}

// ─── Aborting hypercube message hash → chunks ────────────────────────────────
//
// 1. Poseidon compress (message | parameter | epoch | randomness) → MSG_HASH_LEN_FE FEs
// 2. For each of the first ceil(DIMENSION / Z) = 6 FEs:
//    - reject if a_i >= Q * w^z
//    - d_i = floor(a_i / Q)
//    - decompose d_i in base w with z digits

fn aborting_hypercube_hash(
    perm24: &impl CryptographicPermutation<[F; 24]>,
    parameter: &[F; PARAMETER_LEN],
    epoch: u32,
    randomness: &[F; RAND_LEN],
    message: &[u8; MESSAGE_LENGTH],
) -> Option<[u8; NUM_CHUNKS]> {
    let message_fe = encode_message(message);
    let epoch_fe = encode_epoch(epoch);

    // Layout: [message | parameter | epoch | randomness]
    let mut combined = Vec::with_capacity(MSG_LEN_FE + PARAMETER_LEN + TWEAK_LEN + RAND_LEN);
    combined.extend_from_slice(&message_fe);
    combined.extend_from_slice(parameter);
    combined.extend_from_slice(&epoch_fe);
    combined.extend_from_slice(randomness);

    let hash_fe = poseidon_compress_24::<MSG_HASH_LEN_FE>(perm24, &combined);

    let num_useful_fes = NUM_CHUNKS.div_ceil(Z); // ceil(46/8) = 6
    let mut chunks = [0u8; NUM_CHUNKS];

    for (i, &fe) in hash_fe[..num_useful_fes].iter().enumerate() {
        let a_i = fe.as_canonical_u64();
        if a_i >= THRESHOLD {
            return None; // abort
        }
        let mut d_i = a_i / Q;
        let base_idx = i * Z;
        for j in 0..Z.min(NUM_CHUNKS - base_idx) {
            chunks[base_idx + j] = (d_i % BASE as u64) as u8;
            d_i /= BASE as u64;
        }
    }

    Some(chunks)
}

// ─── Chain hash (single input, Poseidon-16) ──────────────────────────────────

fn chain_hash(
    perm16: &impl CryptographicPermutation<[F; 16]>,
    parameter: &[F; PARAMETER_LEN],
    epoch: u32,
    chain_index: u8,
    pos_in_chain: u8,
    value: &[F; HASH_LEN],
) -> [F; HASH_LEN] {
    let tweak = chain_tweak_fe(epoch, chain_index, pos_in_chain);
    // Layout: [message | parameter | tweak]
    let mut input = [F::ZERO; 16];
    input[..HASH_LEN].copy_from_slice(value);
    input[HASH_LEN..HASH_LEN + PARAMETER_LEN].copy_from_slice(parameter);
    input[HASH_LEN + PARAMETER_LEN..HASH_LEN + PARAMETER_LEN + TWEAK_LEN].copy_from_slice(&tweak);
    poseidon_compress_16(perm16, &input)
}

fn chain_walk(
    perm16: &impl CryptographicPermutation<[F; 16]>,
    parameter: &[F; PARAMETER_LEN],
    epoch: u32,
    chain_index: u8,
    start_pos: u8,
    steps: usize,
    start: &[F; HASH_LEN],
) -> [F; HASH_LEN] {
    let mut current = *start;
    for j in 0..steps {
        current = chain_hash(
            perm16, parameter, epoch, chain_index,
            start_pos + (j as u8) + 1, &current,
        );
    }
    current
}

// ─── Tree hash (two inputs, Poseidon-24) ─────────────────────────────────────

fn tree_merge(
    perm24: &impl CryptographicPermutation<[F; 24]>,
    parameter: &[F; PARAMETER_LEN],
    level: u8,
    pos_in_level: u32,
    left: &[F; HASH_LEN],
    right: &[F; HASH_LEN],
) -> [F; HASH_LEN] {
    let tweak = tree_tweak_fe(level, pos_in_level);
    // Layout: [parameter | tweak | left | right]
    let mut input = [F::ZERO; 24];
    input[..PARAMETER_LEN].copy_from_slice(parameter);
    input[PARAMETER_LEN..PARAMETER_LEN + TWEAK_LEN].copy_from_slice(&tweak);
    input[PARAMETER_LEN + TWEAK_LEN..PARAMETER_LEN + TWEAK_LEN + HASH_LEN].copy_from_slice(left);
    input[PARAMETER_LEN + TWEAK_LEN + HASH_LEN..PARAMETER_LEN + TWEAK_LEN + 2 * HASH_LEN]
        .copy_from_slice(right);
    poseidon_compress_24::<HASH_LEN>(perm24, &input)
}

// ─── Leaf hash (sponge, many inputs) ─────────────────────────────────────────

fn leaf_hash(
    perm24: &impl CryptographicPermutation<[F; 24]>,
    parameter: &[F; PARAMETER_LEN],
    position: u32,
    chain_ends: &[[F; HASH_LEN]],
) -> [F; HASH_LEN] {
    let tweak = tree_tweak_fe(0, position);
    // Layout: [parameter | tweak | chain_ends...]
    let mut combined =
        Vec::with_capacity(PARAMETER_LEN + TWEAK_LEN + chain_ends.len() * HASH_LEN);
    combined.extend_from_slice(parameter);
    combined.extend_from_slice(&tweak);
    for ce in chain_ends {
        combined.extend_from_slice(ce);
    }

    let lengths: [u32; 4] = [
        PARAMETER_LEN as u32,
        TWEAK_LEN as u32,
        NUM_CHUNKS as u32,
        HASH_LEN as u32,
    ];
    let capacity_value = poseidon_safe_domain_separator(perm24, &lengths);
    poseidon_replacement_t_sponge(perm24, &capacity_value, &combined)
}

// ─── SSZ parsing helpers ─────────────────────────────────────────────────────

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_fe_array<const N: usize>(bytes: &[u8], offset: usize) -> [F; N] {
    std::array::from_fn(|i| F::new(read_u32(bytes, offset + i * 4)))
}

struct TestVector {
    epoch: u32,
    message: [u8; MESSAGE_LENGTH],
    pk_root: [F; HASH_LEN],
    pk_parameter: [F; PARAMETER_LEN],
    rho: [F; RAND_LEN],
    auth_path: Vec<[F; HASH_LEN]>,
    hashes: Vec<[F; HASH_LEN]>,
}

fn parse_test_vector(data: &[u8]) -> TestVector {
    let mut pos = 0;

    let epoch = read_u32(data, pos);
    pos += 4;
    let message: [u8; 32] = data[pos..pos + 32].try_into().unwrap();
    pos += 32;

    // pk SSZ: root (HASH_LEN*4) then parameter (PARAMETER_LEN*4)
    let pk_len = read_u32(data, pos) as usize;
    pos += 4;
    let pk_data = &data[pos..pos + pk_len];
    let pk_root = read_fe_array::<HASH_LEN>(pk_data, 0);
    let pk_parameter = read_fe_array::<PARAMETER_LEN>(pk_data, HASH_LEN * 4);
    pos += pk_len;

    // sig SSZ: offset_path(4) | rho(RAND_LEN*4) | offset_hashes(4) | path_data | hashes_data
    let sig_len = read_u32(data, pos) as usize;
    pos += 4;
    let sig_data = &data[pos..pos + sig_len];

    let offset_path = read_u32(sig_data, 0) as usize;
    let rho = read_fe_array::<RAND_LEN>(sig_data, 4);
    let offset_hashes = read_u32(sig_data, 4 + RAND_LEN * 4) as usize;

    // Auth path: HashTreeOpening SSZ = offset(4) + co_path vec
    let path_ssz = &sig_data[offset_path..offset_hashes];
    let path_vec_data = &path_ssz[4..];
    let num_nodes = path_vec_data.len() / (HASH_LEN * 4);
    let auth_path: Vec<[F; HASH_LEN]> = (0..num_nodes)
        .map(|i| read_fe_array::<HASH_LEN>(path_vec_data, i * HASH_LEN * 4))
        .collect();

    // Hashes vec
    let hashes_data = &sig_data[offset_hashes..];
    let num_hashes = hashes_data.len() / (HASH_LEN * 4);
    let hashes: Vec<[F; HASH_LEN]> = (0..num_hashes)
        .map(|i| read_fe_array::<HASH_LEN>(hashes_data, i * HASH_LEN * 4))
        .collect();

    TestVector { epoch, message, pk_root, pk_parameter, rho, auth_path, hashes }
}

// ─── Verification ────────────────────────────────────────────────────────────

fn verify(tv: &TestVector) -> bool {
    let perm16 = default_koalabear_poseidon1_16();
    let perm24 = default_koalabear_poseidon1_24();

    // 1. Bounds
    if (tv.epoch as u64) >= (1u64 << LOG_LIFETIME) {
        return false;
    }
    if tv.hashes.len() != NUM_CHUNKS {
        return false;
    }

    // 2. Aborting hypercube message hash → chunks
    let chunks = match aborting_hypercube_hash(
        &perm24, &tv.pk_parameter, tv.epoch, &tv.rho, &tv.message,
    ) {
        Some(c) => c,
        None => return false, // hash aborted → invalid signature
    };

    // 3. Target sum check
    let sum: usize = chunks.iter().map(|&x| x as usize).sum();
    if sum != TARGET_SUM {
        return false;
    }

    // 4. Walk hash chains
    let chain_length = BASE;
    let mut chain_ends = Vec::with_capacity(NUM_CHUNKS);
    for (i, &xi) in chunks.iter().enumerate() {
        let steps = (chain_length - 1) as u8 - xi;
        let end = chain_walk(
            &perm16, &tv.pk_parameter, tv.epoch, i as u8,
            xi, steps as usize, &tv.hashes[i],
        );
        chain_ends.push(end);
    }

    // 5. Hash the leaf (sponge mode)
    let mut current_node = leaf_hash(&perm24, &tv.pk_parameter, tv.epoch, &chain_ends);

    // 6. Walk the Merkle auth path
    let depth = tv.auth_path.len();
    let mut current_position = tv.epoch;
    for l in 0..depth {
        let (left, right) = if current_position % 2 == 0 {
            (current_node, tv.auth_path[l])
        } else {
            (tv.auth_path[l], current_node)
        };
        current_position >>= 1;
        current_node = tree_merge(
            &perm24, &tv.pk_parameter, (l + 1) as u8, current_position,
            &left, &right,
        );
    }

    // 7. Check root
    current_node == tv.pk_root
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "../test_vector.bin".to_string());
    let mut data = Vec::new();
    std::fs::File::open(&path)
        .expect("cannot open test vector file")
        .read_to_end(&mut data)
        .unwrap();

    let tv = parse_test_vector(&data);
    println!(
        "epoch={}, {} hashes, depth={}",
        tv.epoch, tv.hashes.len(), tv.auth_path.len()
    );

    if verify(&tv) {
        println!("VERIFIED OK");
    } else {
        println!("VERIFICATION FAILED");
        std::process::exit(1);
    }
}
