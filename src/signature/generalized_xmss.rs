use std::marker::PhantomData;

use rand::RngExt;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    MESSAGE_LENGTH,
    inc_encoding::IncomparableEncoding,
    serialization::Serializable,
    signature::SignatureSchemeSecretKey,
    symmetric::{
        prf::Pseudorandom,
        tweak_hash::{TweakableHash, chain},
        tweak_hash_tree::{HashSubTree, HashTreeOpening, hash_tree_verify},
    },
};

use super::{SignatureScheme, SigningError};

use ssz::{Decode, DecodeError, Encode};

/// Implementation of the generalized XMSS signature scheme
/// from any incomparable encoding scheme and any tweakable hash
///
/// It also uses a PRF for key generation, and one has to specify
/// the (base 2 log of the) key lifetime.
///
/// Note: lifetimes beyond 2^32 are not supported.
pub struct GeneralizedXMSSSignatureScheme<
    PRF: Pseudorandom,
    IE: IncomparableEncoding,
    TH: TweakableHash,
    const LOG_LIFETIME: usize,
> {
    _prf: std::marker::PhantomData<PRF>,
    _ie: std::marker::PhantomData<IE>,
    _th: std::marker::PhantomData<TH>,
}

/// Signature for GeneralizedXMSSSignatureScheme
/// It contains a Merkle authentication path, encoding randomness, and a list of hashes
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct GeneralizedXMSSSignature<IE: IncomparableEncoding, TH: TweakableHash> {
    path: HashTreeOpening<TH>,
    rho: IE::Randomness,
    hashes: Vec<TH::Domain>,
}

impl<IE: IncomparableEncoding, TH: TweakableHash> GeneralizedXMSSSignature<IE, TH> {
    pub const fn path(&self) -> &HashTreeOpening<TH> {
        &self.path
    }

    pub const fn rho(&self) -> &IE::Randomness {
        &self.rho
    }

    pub const fn hashes(&self) -> &Vec<TH::Domain> {
        &self.hashes
    }
}

impl<IE: IncomparableEncoding, TH: TweakableHash> Encode for GeneralizedXMSSSignature<IE, TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        // SSZ Container: offset (4) + rho (fixed) + offset (4) + variable data
        let offset_size = 4;
        let rho_size = self.rho.ssz_bytes_len();
        let path_size = self.path.ssz_bytes_len();
        let hashes_size = self.hashes.ssz_bytes_len();

        offset_size + rho_size + offset_size + path_size + hashes_size
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // Appends the SSZ encoding to the buffer.
        //
        // SSZ Container encoding with fields interleaved in declaration order:
        // - Field 1 (path): variable → write offset
        // - Field 2 (rho): fixed → write data
        // - Field 3 (hashes): variable → write offset
        //
        // Then write variable data in order: path, hashes

        // Calculate offsets (start of variable data)
        let rho_size = self.rho.ssz_bytes_len();
        // offset + rho + offset
        let fixed_size = 4 + rho_size + 4;

        let offset_path = fixed_size;
        let offset_hashes = offset_path + self.path.ssz_bytes_len();

        // 1. Encode offset for first variable field: path
        buf.extend_from_slice(&(offset_path as u32).to_le_bytes());

        // 2. Encode fixed field: rho
        self.rho.ssz_append(buf);

        // 3. Encode offset for second variable field: hashes
        buf.extend_from_slice(&(offset_hashes as u32).to_le_bytes());

        // 4. Encode variable data in order
        self.path.ssz_append(buf);
        self.hashes.ssz_append(buf);
    }
}

impl<IE: IncomparableEncoding, TH: TweakableHash> Decode for GeneralizedXMSSSignature<IE, TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        // Decodes a generalized XMSS signature from SSZ bytes.
        //
        // Fields are interleaved: offset_path → rho → offset_hashes → variable data

        // Get fixed size of rho field
        let rho_size = if <IE::Randomness as Encode>::is_ssz_fixed_len() {
            <IE::Randomness as Encode>::ssz_fixed_len()
        } else {
            return Err(DecodeError::BytesInvalid(
                "IE::Randomness must be fixed length".into(),
            ));
        };

        // Minimum size: offset (4) + rho (fixed) + offset (4)
        let min_size = 4 + rho_size + 4;
        if bytes.len() < min_size {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: min_size,
            });
        }

        // 1. Read offset for first variable field: path
        let offset_path = u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| {
            DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: 4,
            }
        })?) as usize;

        // 2. Decode fixed field: rho
        let rho = IE::Randomness::from_ssz_bytes(&bytes[4..4 + rho_size])?;

        // 3. Read offset for second variable field: hashes
        let offset_hashes =
            u32::from_le_bytes(bytes[4 + rho_size..8 + rho_size].try_into().map_err(|_| {
                DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: 8 + rho_size,
                }
            })?) as usize;

        // Validate offset_path points to end of fixed part
        let expected_offset_path = 4 + rho_size + 4;
        if offset_path != expected_offset_path {
            return Err(DecodeError::InvalidByteLength {
                len: offset_path,
                expected: expected_offset_path,
            });
        }

        // Panic safety: Ensure offsets are monotonic and within bounds
        // This prevents panic when creating slices below
        if offset_path > offset_hashes || offset_hashes > bytes.len() {
            return Err(DecodeError::BytesInvalid(format!(
                "Invalid variable offsets: path={} hashes={} len={}",
                offset_path,
                offset_hashes,
                bytes.len()
            )));
        }

        // 4. Decode variable fields (now safe after bounds check)
        let path = HashTreeOpening::<TH>::from_ssz_bytes(&bytes[offset_path..offset_hashes])?;
        let hashes = Vec::<TH::Domain>::from_ssz_bytes(&bytes[offset_hashes..])?;

        Ok(Self { path, rho, hashes })
    }
}

/// Public key for GeneralizedXMSSSignatureScheme
/// It contains a Merkle root and a parameter for the tweakable hash
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct GeneralizedXMSSPublicKey<TH: TweakableHash> {
    root: TH::Domain,
    parameter: TH::Parameter,
}

impl<TH: TweakableHash> GeneralizedXMSSPublicKey<TH> {
    pub const fn root(&self) -> &TH::Domain {
        &self.root
    }

    pub const fn parameter(&self) -> &TH::Parameter {
        &self.parameter
    }
}

/// Secret key for GeneralizedXMSSSignatureScheme
/// It contains a PRF key and a Merkle tree.
///
/// Note: one may choose to regenerate the tree on the fly, but this
/// would be costly for signatures.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct GeneralizedXMSSSecretKey<
    PRF: Pseudorandom,
    IE: IncomparableEncoding,
    TH: TweakableHash,
    const LOG_LIFETIME: usize,
> {
    prf_key: PRF::Key,
    parameter: TH::Parameter,
    activation_epoch: u64,
    num_active_epochs: u64,
    tree: HashSubTree<TH>,
    _encoding_type: PhantomData<IE>,
}

impl<PRF: Pseudorandom, IE: IncomparableEncoding, TH: TweakableHash, const LOG_LIFETIME: usize>
    Encode for GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>
{
    fn is_ssz_fixed_len() -> bool {
        // It has variable length due to HashSubTree field
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        let prf_key_size = self.prf_key.ssz_bytes_len();
        let parameter_size = self.parameter.ssz_bytes_len();
        let tree_size = self.tree.ssz_bytes_len();

        prf_key_size
            + parameter_size
            + 8 // activation_epoch
            + 8 // num_active_epochs
            + 4 // tree offset
            + tree_size
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // SSZ Container encoding with fields in declaration order:
        // - Field 1 (prf_key): fixed → write data
        // - Field 2 (parameter): fixed → write data
        // - Field 3 (activation_epoch): fixed → write data
        // - Field 4 (num_active_epochs): fixed → write data
        // - Field 5 (tree): variable → write offset
        //
        // Then write variable data: tree

        let prf_key_size = self.prf_key.ssz_bytes_len();
        let parameter_size = self.parameter.ssz_bytes_len();
        let fixed_size = prf_key_size + parameter_size + 8 + 8 + 4;

        // 1. Encode fixed field: prf_key
        self.prf_key.ssz_append(buf);

        // 2. Encode fixed field: parameter
        self.parameter.ssz_append(buf);

        // 3. Encode fixed field: activation_epoch (u64)
        buf.extend_from_slice(&self.activation_epoch.to_le_bytes());

        // 4. Encode fixed field: num_active_epochs (u64)
        buf.extend_from_slice(&self.num_active_epochs.to_le_bytes());

        // 5. Encode offset for variable field: tree
        buf.extend_from_slice(&(fixed_size as u32).to_le_bytes());

        // 6. Encode variable data: tree
        self.tree.ssz_append(buf);
    }
}

impl<PRF: Pseudorandom, IE: IncomparableEncoding, TH: TweakableHash, const LOG_LIFETIME: usize>
    Decode for GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>
{
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let prf_key_size = if <PRF::Key as Encode>::is_ssz_fixed_len() {
            <PRF::Key as Encode>::ssz_fixed_len()
        } else {
            return Err(DecodeError::BytesInvalid(
                "PRF::Key must be fixed length".into(),
            ));
        };

        let parameter_size = if <TH::Parameter as Encode>::is_ssz_fixed_len() {
            <TH::Parameter as Encode>::ssz_fixed_len()
        } else {
            return Err(DecodeError::BytesInvalid(
                "TH::Parameter must be fixed length".into(),
            ));
        };

        // Minimum size: prf_key + parameter + 2×u64 (16) + 1×offset (4)
        let min_fixed_size = prf_key_size + parameter_size + 16 + 4;
        if bytes.len() < min_fixed_size {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: min_fixed_size,
            });
        }

        let mut pos = 0;

        // 1. Decode fixed field: prf_key
        let prf_key = PRF::Key::from_ssz_bytes(&bytes[pos..pos + prf_key_size])?;
        pos += prf_key_size;

        // 2. Decode fixed field: parameter
        let parameter = TH::Parameter::from_ssz_bytes(&bytes[pos..pos + parameter_size])?;
        pos += parameter_size;

        // 3. Decode fixed field: activation_epoch (u64)
        let activation_epoch =
            u64::from_le_bytes(bytes[pos..pos + 8].try_into().map_err(|_| {
                DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: pos + 8,
                }
            })?);
        pos += 8;

        // 4. Decode fixed field: num_active_epochs (u64)
        let num_active_epochs =
            u64::from_le_bytes(bytes[pos..pos + 8].try_into().map_err(|_| {
                DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: pos + 8,
                }
            })?);
        pos += 8;

        // 5. Read offset for variable field: tree
        let offset_tree = u32::from_le_bytes(bytes[pos..pos + 4].try_into().map_err(|_| {
            DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: pos + 4,
            }
        })?) as usize;
        pos += 4;

        if pos != offset_tree {
            return Err(DecodeError::InvalidByteLength {
                len: pos,
                expected: offset_tree,
            });
        }

        // 6. Decode variable field: tree
        let tree = HashSubTree::<TH>::from_ssz_bytes(&bytes[offset_tree..])?;

        Ok(Self {
            prf_key,
            parameter,
            activation_epoch,
            num_active_epochs,
            tree,
            _encoding_type: PhantomData,
        })
    }
}

impl<PRF: Pseudorandom, IE: IncomparableEncoding, TH: TweakableHash, const LOG_LIFETIME: usize>
    SignatureSchemeSecretKey for GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>
where
    PRF::Domain: Into<TH::Domain>,
    PRF::Randomness: Into<IE::Randomness>,
    TH::Parameter: Into<IE::Parameter>,
{
    fn get_activation_interval(&self) -> std::ops::Range<u64> {
        let start = self.activation_epoch;
        let end = start + self.num_active_epochs;
        start..end
    }

    fn get_prepared_interval(&self) -> std::ops::Range<u64> {
        self.get_activation_interval()
    }

    fn advance_preparation(&mut self) {
        // no-op: the full tree for the activation interval is stored
    }
}

impl<
    PRF: Pseudorandom,
    IE: IncomparableEncoding + Sync + Send,
    TH: TweakableHash,
    const LOG_LIFETIME: usize,
> SignatureScheme for GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>
where
    PRF::Domain: Into<TH::Domain>,
    PRF::Randomness: Into<IE::Randomness>,
    TH::Parameter: Into<IE::Parameter>,
{
    type PublicKey = GeneralizedXMSSPublicKey<TH>;

    type SecretKey = GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>;

    type Signature = GeneralizedXMSSSignature<IE, TH>;

    const LIFETIME: u64 = 1 << LOG_LIFETIME;

    fn key_gen<R: RngExt>(
        rng: &mut R,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) -> (Self::PublicKey, Self::SecretKey) {
        const {
            // assert BASE and DIMENSION are small enough to make sure that we can fit
            // pos_in_chain and chain_index in u8.
            assert!(
                IE::BASE <= 1 << 8,
                "Generalized XMSS: Encoding base too large, must be at most 2^8"
            );
            assert!(
                IE::DIMENSION <= 1 << 8,
                "Generalized XMSS: Encoding dimension too large, must be at most 2^8"
            );
        }

        // checks for `activation_epoch` and `num_active_epochs`
        assert!(
            num_active_epochs >= 1,
            "Key gen: `num_active_epochs` must be at least 1"
        );
        assert!(
            activation_epoch + num_active_epochs <= Self::LIFETIME as usize,
            "Key gen: `activation_epoch` and `num_active_epochs` are invalid for this lifetime"
        );

        // we need a random parameter to be used for the tweakable hash
        let parameter = TH::rand_parameter(rng);

        // we need a PRF key to generate our list of actual secret keys
        let prf_key = PRF::key_gen(rng);

        // compute the tree leaves for all epochs in the activation range
        let num_chains = IE::DIMENSION;
        let chain_length = IE::BASE;
        let epochs: Vec<u32> = (activation_epoch..activation_epoch + num_active_epochs)
            .map(|e| e as u32)
            .collect();

        let leaf_hashes =
            TH::compute_tree_leaves::<PRF>(&prf_key, &parameter, &epochs, num_chains, chain_length);

        // build the full sparse tree for the activation range
        let tree = HashSubTree::new_subtree(
            rng,
            0, // lowest_layer = 0 (full tree from leaves)
            LOG_LIFETIME,
            activation_epoch,
            &parameter,
            leaf_hashes,
        );
        let root = tree.root();

        // assemble public key and secret key
        let pk = GeneralizedXMSSPublicKey { root, parameter };
        let sk = GeneralizedXMSSSecretKey {
            prf_key,
            parameter,
            activation_epoch: activation_epoch as u64,
            num_active_epochs: num_active_epochs as u64,
            tree,
            _encoding_type: PhantomData,
        };

        (pk, sk)
    }

    fn sign(
        sk: &Self::SecretKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Result<Self::Signature, SigningError> {
        // check that epoch is indeed a valid epoch in the activation range

        assert!(
            sk.get_activation_interval().contains(&(epoch as u64)),
            "Signing: key not active during this epoch."
        );

        // first component of the signature is the Merkle path that
        // opens the one-time pk for that epoch, where the one-time pk
        // will be recomputed by the verifier from the signature.
        let path = sk.tree.path(epoch);

        // now, we need to encode our message using the incomparable encoding.
        // we retry until we get a valid codeword, or until we give up.
        let max_tries = IE::MAX_TRIES;
        let mut attempts = 0;
        let mut x = None;
        let mut rho = None;
        while attempts < max_tries {
            // get a randomness and try to encode the message. Note: we get the randomness from the PRF
            // which ensures that signing is deterministic. The PRF is applied to the message and the epoch.
            // While the intention is that users of the scheme never call sign twice with the same (epoch, sk) pair,
            // this deterministic approach ensures that calling sign twice is fine, as long as the message stays the same.
            let curr_rho = PRF::get_randomness(&sk.prf_key, epoch, message, attempts as u64).into();
            let curr_x = IE::encode(&sk.parameter.into(), message, &curr_rho, epoch);

            // check if we have found a valid codeword, and if so, stop searching
            if curr_x.is_ok() {
                rho = Some(curr_rho);
                x = curr_x.ok();
                break;
            }

            attempts += 1;
        }

        // if we have not found a valid codeword, return an error
        if x.is_none() {
            return Err(SigningError::EncodingAttemptsExceeded {
                attempts: max_tries,
            });
        }

        // otherwise, unwrap x and rho
        let x = x.unwrap();
        let rho = rho.unwrap();

        // we will include rho in the signature, and
        // we use x to determine how far the signer walks in the chains
        let num_chains = IE::DIMENSION;
        assert!(
            x.len() == num_chains,
            "Encoding is broken: returned too many or too few chunks."
        );

        // In parallel, compute the hash values for each chain based on the codeword `x`.
        let hashes = (0..num_chains)
            .into_par_iter()
            .map(|chain_index| {
                // get back to the start of the chain from the PRF
                let start = PRF::get_domain_element(&sk.prf_key, epoch, chain_index as u64).into();
                // now walk the chain for a number of steps determined by the current chunk of x
                let steps = x[chain_index] as usize;
                chain::<TH>(&sk.parameter, epoch, chain_index as u8, 0, steps, &start)
            })
            .collect();

        // assemble the signature: Merkle path, randomness, chain elements
        Ok(GeneralizedXMSSSignature { path, rho, hashes })
    }

    fn verify(
        pk: &Self::PublicKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
        sig: &Self::Signature,
    ) -> bool {
        debug_assert!(
            (epoch as u64) < Self::LIFETIME,
            "Generalized XMSS - Verify: Epoch too large."
        );

        debug_assert!(
            sig.hashes.len() == IE::DIMENSION,
            "Generalized XMSS - Verify: Wrong number of hashes."
        );

        // some sanity checks on inputs: signature has correct structure
        // and epoch in range. We reject in case a check fails.
        if (epoch as u64) >= Self::LIFETIME {
            return false;
        }
        if sig.hashes.len() != IE::DIMENSION {
            return false;
        }

        // first get back the codeword and make sure
        // encoding succeeded with the given randomness.
        let Ok(x) = IE::encode(&pk.parameter.into(), message, &sig.rho, epoch) else {
            return false;
        };

        // now, we recompute the epoch's one-time public key
        // from the hashes by walking hash chains.
        let chain_length = IE::BASE;
        let num_chains = IE::DIMENSION;
        assert!(
            x.len() == num_chains,
            "Encoding is broken: returned too many or too few chunks."
        );
        let mut chain_ends = Vec::with_capacity(num_chains);
        for (chain_index, xi) in x.iter().enumerate() {
            // If the signer has already walked x[i] steps, then we need
            // to walk chain_length - 1 - x[i] steps to reach the end of the chain
            // Note: by our consistency checks, we have chain_length <= 2^8, so chain_length - 1 fits into u8
            let steps = (chain_length - 1) as u8 - xi;
            let start_pos_in_chain = *xi;
            let start = &sig.hashes[chain_index];
            let end = chain::<TH>(
                &pk.parameter,
                epoch,
                chain_index as u8,
                start_pos_in_chain,
                steps as usize,
                start,
            );
            chain_ends.push(end);
        }

        // this set of chain ends should be a leaf in the Merkle tree
        // we verify that by checking the Merkle authentication path
        hash_tree_verify(
            &pk.parameter,
            &pk.root,
            epoch,
            chain_ends.as_slice(),
            &sig.path,
        )
    }
}

impl<TH: TweakableHash> Encode for GeneralizedXMSSPublicKey<TH> {
    fn is_ssz_fixed_len() -> bool {
        <TH::Domain as Encode>::is_ssz_fixed_len() && <TH::Parameter as Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <TH::Domain as Encode>::ssz_fixed_len() + <TH::Parameter as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.root.ssz_bytes_len() + self.parameter.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.root.ssz_append(buf);
        self.parameter.ssz_append(buf);
    }
}

impl<TH: TweakableHash> Decode for GeneralizedXMSSPublicKey<TH> {
    fn is_ssz_fixed_len() -> bool {
        <TH::Domain as Decode>::is_ssz_fixed_len() && <TH::Parameter as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <TH::Domain as Decode>::ssz_fixed_len() + <TH::Parameter as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let expected_len = <Self as Decode>::ssz_fixed_len();
        if bytes.len() != expected_len {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: expected_len,
            });
        }

        let root_len = <TH::Domain as Decode>::ssz_fixed_len();
        let (root_bytes, param_bytes) = bytes.split_at(root_len);

        let root = TH::Domain::from_ssz_bytes(root_bytes)?;
        let parameter = TH::Parameter::from_ssz_bytes(param_bytes)?;

        Ok(Self { root, parameter })
    }
}

impl<TH: TweakableHash> Serializable for GeneralizedXMSSPublicKey<TH> {}

impl<IE: IncomparableEncoding, TH: TweakableHash> Serializable
    for GeneralizedXMSSSignature<IE, TH>
{
}

impl<PRF: Pseudorandom, IE: IncomparableEncoding, TH: TweakableHash, const LOG_LIFETIME: usize>
    Serializable for GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>
{
}

/// Instantiations of the generalized XMSS signature scheme based on the
/// aborting hypercube message hash (rejection sampling)
pub mod instantiations_aborting;
/// Instantiations of the generalized XMSS signature scheme based on Poseidon1
pub mod instantiations_poseidon;
/// Instantiations of the generalized XMSS signature scheme based on the
/// top level target sum encoding using Poseidon1
pub mod instantiations_poseidon_top_level;

#[cfg(test)]
mod tests {
    use crate::{
        inc_encoding::target_sum::TargetSumEncoding,
        signature::test_templates::test_signature_scheme_correctness,
        symmetric::{
            message_hash::{
                MessageHash,
                aborting::AbortingHypercubeMessageHash,
                poseidon::{PoseidonMessageHash, PoseidonMessageHashW1},
            },
            prf::shake_to_field::ShakePRFtoF,
            tweak_hash::poseidon::PoseidonTweakW1L5,
        },
    };

    use super::*;

    use crate::array::FieldArray;
    use p3_field::PrimeField32;
    use proptest::prelude::*;

    use crate::{F, symmetric::tweak_hash::poseidon::PoseidonTweakHash};
    use p3_field::RawDataSerializable;
    use rand::{RngExt, rng};
    use ssz::{Decode, Encode};

    type TestTH = PoseidonTweakHash<5, 7, 2, 9, 155>;

    #[test]
    pub fn test_target_sum_poseidon() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        test_signature_scheme_correctness::<Sig>(2, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(19, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(11, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_deterministic() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        // we sign the same (epoch, message) pair twice (which users of this code should not do)
        // and ensure that it produces the same randomness for the signature.
        let mut rng = rand::rng();
        let (_pk, sk) = Sig::key_gen(&mut rng, 0, 1 << LOG_LIFETIME);
        let message = rng.random();
        let epoch = 29;

        let sig1 = Sig::sign(&sk, epoch, &message).unwrap();
        let sig2 = Sig::sign(&sk, epoch, &message).unwrap();
        let rho1 = sig1.rho;
        let rho2 = sig2.rho;
        assert_eq!(rho1, rho2);
    }

    #[test]
    pub fn test_large_base_poseidon() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShakePRFtoF<4, 8>;
        type TH = PoseidonTweakHash<4, 4, 2, 8, 32>;
        type MH = PoseidonMessageHash<4, 8, 8, 32, 256, 2, 9>;
        const TARGET_SUM: usize = 1 << 12;
        type IE = TargetSumEncoding<MH, TARGET_SUM>;
        const LOG_LIFETIME: usize = 10;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(11, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_large_dimension_poseidon() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShakePRFtoF<8, 8>;
        type TH = PoseidonTweakHash<4, 8, 2, 8, 256>;
        type MH = PoseidonMessageHash<4, 8, 8, 256, 2, 2, 9>;
        const TARGET_SUM: usize = 128;
        type IE = TargetSumEncoding<MH, TARGET_SUM>;
        const LOG_LIFETIME: usize = 10;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        test_signature_scheme_correctness::<Sig>(2, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(19, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_aborting_target_sum() {
        // KoalaBear: p = 127 * 8^8 + 1, so w=8, z=8, Q=127
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakHash<5, 7, 2, 9, 64>;
        type MH = AbortingHypercubeMessageHash<5, 5, 8, 64, 8, 8, 127, 2, 9>;
        const TARGET_SUM: usize = MH::DIMENSION * (MH::BASE - 1) / 2; // 224
        type IE = TargetSumEncoding<MH, TARGET_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        test_signature_scheme_correctness::<Sig>(2, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(19, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(11, 0, Sig::LIFETIME as usize);
    }

    #[test]
    fn test_ssz_encoding_structure() {
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        let mut rng = rng();

        // Test PublicKey encoding structure
        let root = TestTH::rand_domain(&mut rng);
        let parameter = TestTH::rand_parameter(&mut rng);
        let public_key = GeneralizedXMSSPublicKey::<TestTH> { root, parameter };
        // Serialize to bytes
        let encoded = public_key.as_ssz_bytes();
        // Verify expected size based on field element counts
        assert_eq!(encoded.len(), (7 + 5) * F::NUM_BYTES);
        // Verify first field element is encoded correctly
        let first_fe_bytes = root.as_ssz_bytes();
        assert_eq!(&encoded[0..F::NUM_BYTES], &first_fe_bytes[0..F::NUM_BYTES]);
        // Decode and verify roundtrip
        let decoded = GeneralizedXMSSPublicKey::<TestTH>::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(public_key.root, decoded.root);
        assert_eq!(public_key.parameter, decoded.parameter);

        // Test Signature encoding structure
        let (pk, sk) = Sig::key_gen(&mut rng, 0, 1 << LOG_LIFETIME);
        let message = rng.random();
        let epoch = 5;
        // Generate valid signature
        let signature = Sig::sign(&sk, epoch, &message).unwrap();
        // Serialize to bytes
        let sig_encoded = signature.as_ssz_bytes();
        // Calculate randomness size
        let rho_size = signature.rho.ssz_bytes_len();
        // Verify minimum size includes two offsets plus fixed field
        assert!(sig_encoded.len() >= 4 + rho_size + 4);
        // Read first offset value from bytes 0-4
        let offset_path = u32::from_le_bytes(sig_encoded[0..4].try_into().unwrap()) as usize;
        // Verify first offset points to end of fixed part
        assert_eq!(offset_path, 4 + rho_size + 4);
        // Decode and verify signature still validates
        let sig_decoded =
            <Sig as SignatureScheme>::Signature::from_ssz_bytes(&sig_encoded).unwrap();
        assert!(Sig::verify(&pk, epoch, &message, &sig_decoded));

        // Test SecretKey encoding structure
        let (_pk2, sk2) = Sig::key_gen(&mut rng, 0, 8);
        // Serialize secret key to bytes
        let sk_encoded = sk2.as_ssz_bytes();
        // Calculate fixed field sizes
        let prf_key_size = sk2.prf_key.ssz_bytes_len();
        let param_size = sk2.parameter.ssz_bytes_len();
        let fixed_part_size = prf_key_size + param_size + 8 + 8 + 4;
        // Verify minimum size includes all fixed fields
        assert!(sk_encoded.len() >= fixed_part_size);
        // Read activation epoch value from fixed position
        let activation_start = prf_key_size + param_size;
        let activation_epoch = u64::from_le_bytes(
            sk_encoded[activation_start..activation_start + 8]
                .try_into()
                .unwrap(),
        );
        // Verify stored value matches original
        assert_eq!(activation_epoch, sk2.activation_epoch);
        // Decode and verify roundtrip by re-encoding
        let sk_decoded = <Sig as SignatureScheme>::SecretKey::from_ssz_bytes(&sk_encoded).unwrap();
        let sk_reencoded = sk_decoded.as_ssz_bytes();
        assert_eq!(sk_encoded, sk_reencoded);
    }

    #[test]
    fn test_ssz_decoding_errors() {
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        // PublicKey: buffer too small
        // TestTH = PoseidonTweakW1L5 has FieldArray<7> hash and FieldArray<5> domain
        // Total size: (7 + 5) * F::NUM_BYTES = 12 * 4 = 48 bytes
        // Create buffer with only 47 bytes (one byte short)
        let encoded = vec![0u8; 47];
        // Attempt decode with insufficient bytes
        let result = GeneralizedXMSSPublicKey::<TestTH>::from_ssz_bytes(&encoded);
        // Decoder reports actual buffer size (47) vs expected (48)
        assert!(matches!(
            result,
            Err(DecodeError::InvalidByteLength {
                len: 47,
                expected: 48
            })
        ));

        // Signature: buffer too small - only 8 bytes when we need more
        // IE::Randomness = MH::Randomness = FieldArray<5> (from PoseidonMessageHashW1)
        // FieldArray<5> has ssz_fixed_len() = 5 * F::NUM_BYTES = 5 * 4 = 20 bytes
        // Minimum size: offset (4) + rho (20) + offset (4) = 28 bytes
        let encoded = vec![0u8; 8];
        let result = <Sig as SignatureScheme>::Signature::from_ssz_bytes(&encoded);
        // Decoder checks min_size at line 119: reports actual (8) vs expected (28)
        assert!(matches!(
            result,
            Err(DecodeError::InvalidByteLength {
                len: 8,
                expected: 28
            })
        ));

        // Signature: invalid offset value pointing to wrong location
        // Create buffer with sufficient space (28 + 100 bytes)
        let mut encoded = vec![0u8; 128];
        // Write incorrect offset (99) that doesn't match expected first offset (28)
        encoded[0..4].copy_from_slice(&99u32.to_le_bytes());
        // Write valid rho data at bytes 4..24 (20 bytes of zeros is valid FieldArray<5>)
        for i in 0..20 {
            encoded[4 + i] = 0;
        }
        // Write second offset at position 24..28 (actual value doesn't matter)
        encoded[24..28].copy_from_slice(&78u32.to_le_bytes());
        // Attempt decode with invalid first offset
        let result = <Sig as SignatureScheme>::Signature::from_ssz_bytes(&encoded);
        // Decoder at line 149 checks: offset_path (99) != expected_offset_path (28)
        // Expected offset points to byte immediately after fixed part: 4 + 20 + 4 = 28
        assert!(matches!(
            result,
            Err(DecodeError::InvalidByteLength {
                len: 99,
                expected: 28
            })
        ));
    }

    #[test]
    #[allow(clippy::items_after_statements)]
    fn test_ssz_panic_safety_malicious_offsets() {
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        // Helper: Dynamic Size Calculation
        //
        // We calculate sizes dynamically to avoid hardcoded mismatch errors.
        let mut rng = rand::rng();

        // Generate dummy objects to measure their SSZ encoded length
        let dummy_prf_key = PRF::key_gen(&mut rng);
        let dummy_param = TH::rand_parameter(&mut rng);

        let prf_key_size = dummy_prf_key.ssz_bytes_len();
        let param_size = dummy_param.ssz_bytes_len();
        let u64_size = 8;
        let offset_size = 4;

        // Calculate the exact size of the "Fixed Part" of the SecretKey container.
        //
        // Layout: [PRF] [Param] [ActEpoch] [NumActive] [OffTree]
        let fixed_part_len = prf_key_size
            + param_size
            + u64_size // activation_epoch
            + u64_size // num_active_epochs
            + offset_size; // offset_tree

        // Helper: Error Verifier
        fn assert_bytes_invalid<T>(result: Result<T, DecodeError>, expected_msg_part: &str) {
            match result {
                Err(DecodeError::BytesInvalid(msg)) => {
                    assert!(
                        msg.contains(expected_msg_part),
                        "Error message '{}' did not contain expected part '{}'",
                        msg,
                        expected_msg_part
                    );
                }
                Err(e) => panic!("Wrong error type. Expected BytesInvalid, got {:?}", e),
                Ok(_) => panic!("Should have failed with BytesInvalid, but succeeded"),
            }
        }

        // SCENARIO 1: Signature with Reversed Offsets (Non-Monotonic)
        //
        // - Structure: GeneralizedXMSSSignature { path, rho, hashes }
        // - SSZ Layout: [Offset Path (4)] | [Rho (Var)] | [Offset Hashes (4)] | ...
        // - Malicious Input: offset_hashes < offset_path
        {
            let dummy_rho = IE::rand(&mut rng);
            let rho_size = dummy_rho.ssz_bytes_len();

            // Fixed part = Offset(4) + Rho + Offset(4)
            let sig_fixed_part_size = 4 + rho_size + 4;
            let mut encoded = vec![0u8; 200]; // Sufficient buffer

            // 1. Write [Offset Path] -> Correctly points to end of fixed part
            encoded[0..4].copy_from_slice(&(sig_fixed_part_size as u32).to_le_bytes());

            // 2. Write [Rho] -> Write valid dummy data
            let mut rho_buf = Vec::new();
            dummy_rho.ssz_append(&mut rho_buf);
            encoded[4..4 + rho_size].copy_from_slice(&rho_buf);

            // 3. Write [Offset Hashes] -> MALICIOUS!
            // We set it to 10, which is less than `offset_path` (sig_fixed_part_size).
            // This implies the `path` field has negative length, which causes panic if unchecked.
            let offset_hashes_pos = 4 + rho_size;
            encoded[offset_hashes_pos..offset_hashes_pos + 4].copy_from_slice(&10u32.to_le_bytes());

            let result = <Sig as SignatureScheme>::Signature::from_ssz_bytes(&encoded);
            assert_bytes_invalid(result, "Invalid variable offsets");
        }

        // SCENARIO 2: Signature with Offset Out of Bounds
        //
        // Malicious Input: offset_hashes points outside the buffer
        {
            let dummy_rho = IE::rand(&mut rng);
            let rho_size = dummy_rho.ssz_bytes_len();
            let sig_fixed_part_size = 4 + rho_size + 4;

            let mut encoded = vec![0u8; 100]; // Buffer length is 100

            // 1. Write [Offset Path] -> Correct
            encoded[0..4].copy_from_slice(&(sig_fixed_part_size as u32).to_le_bytes());

            // 2. Write [Rho] -> Correct
            let mut rho_buf = Vec::new();
            dummy_rho.ssz_append(&mut rho_buf);
            encoded[4..4 + rho_size].copy_from_slice(&rho_buf);

            // 3. Write [Offset Hashes] -> MALICIOUS!
            // Set to 200, which is > encoded.len() (100).
            let offset_hashes_pos = 4 + rho_size;
            encoded[offset_hashes_pos..offset_hashes_pos + 4]
                .copy_from_slice(&200u32.to_le_bytes());

            let result = <Sig as SignatureScheme>::Signature::from_ssz_bytes(&encoded);
            assert_bytes_invalid(result, "len=100");
        }

        // SCENARIO 3: Secret Key with Invalid Offset
        //
        // Structure: Fixed Fields with 1 Variable Offset (tree)
        // Malicious Input: offset doesn't match fixed_part_len
        {
            let mut encoded = vec![0u8; fixed_part_len + 100];
            let mut pos = 0;

            // 1. Write Fixed Fields: PRF Key
            let mut prf_buf = Vec::new();
            dummy_prf_key.ssz_append(&mut prf_buf);
            encoded[pos..pos + prf_key_size].copy_from_slice(&prf_buf);
            pos += prf_key_size;

            // 2. Write Fixed Fields: Parameter
            let mut param_buf = Vec::new();
            dummy_param.ssz_append(&mut param_buf);
            encoded[pos..pos + param_size].copy_from_slice(&param_buf);
            pos += param_size;

            // 3. Write Fixed Fields: Activation Epoch (u64)
            pos += 8;

            // 4. Write Fixed Fields: Num Active Epochs (u64)
            pos += 8;

            // 5. Write [Offset Tree] -> MALICIOUS!
            // We set it to 10, which doesn't match fixed_part_len.
            encoded[pos..pos + 4].copy_from_slice(&10u32.to_le_bytes());

            let result = <Sig as SignatureScheme>::SecretKey::from_ssz_bytes(&encoded);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_ssz_determinism() {
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        let mut rng = rng();

        // PublicKey: encode same structure twice
        let root = TestTH::rand_domain(&mut rng);
        let parameter = TestTH::rand_parameter(&mut rng);
        let public_key = GeneralizedXMSSPublicKey::<TestTH> { root, parameter };
        // Serialize twice to verify deterministic output
        let encoded1 = public_key.as_ssz_bytes();
        let encoded2 = public_key.as_ssz_bytes();
        // Verify byte-for-byte identical encoding
        assert_eq!(encoded1, encoded2);

        // Signature: encode same structure twice
        let (_pk, sk) = Sig::key_gen(&mut rng, 0, 1 << LOG_LIFETIME);
        let message = rng.random();
        let epoch = 5;
        let signature = Sig::sign(&sk, epoch, &message).unwrap();
        // Serialize twice to verify deterministic output
        let sig_encoded1 = signature.as_ssz_bytes();
        let sig_encoded2 = signature.as_ssz_bytes();
        // Verify byte-for-byte identical encoding
        assert_eq!(sig_encoded1, sig_encoded2);

        // SecretKey: encode same structure twice
        let (_pk2, sk2) = Sig::key_gen(&mut rng, 0, 8);
        // Serialize twice to verify deterministic output
        let sk_encoded1 = sk2.as_ssz_bytes();
        let sk_encoded2 = sk2.as_ssz_bytes();
        // Verify byte-for-byte identical encoding
        assert_eq!(sk_encoded1, sk_encoded2);
    }

    #[test]
    fn test_ssz_signature_integration() {
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        let mut rng = rng();

        // Generate keypair and sign message
        let (pk, sk) = Sig::key_gen(&mut rng, 0, 1 << LOG_LIFETIME);
        let message = rng.random();
        let epoch = 7;
        // Create valid signature
        let signature = Sig::sign(&sk, epoch, &message).unwrap();
        // Verify signature is valid before serialization
        assert!(Sig::verify(&pk, epoch, &message, &signature));

        // Test PublicKey serialization
        let pk_encoded = pk.as_ssz_bytes();
        let pk_decoded = GeneralizedXMSSPublicKey::<TH>::from_ssz_bytes(&pk_encoded).unwrap();
        // Verify decoded key can still verify signature
        assert!(Sig::verify(&pk_decoded, epoch, &message, &signature));

        // Test Signature serialization
        let sig_encoded = signature.as_ssz_bytes();
        let sig_decoded =
            <Sig as SignatureScheme>::Signature::from_ssz_bytes(&sig_encoded).unwrap();
        // Verify decoded signature still validates with original key
        assert!(Sig::verify(&pk, epoch, &message, &sig_decoded));
        // Verify decoded signature validates with decoded key
        assert!(Sig::verify(&pk_decoded, epoch, &message, &sig_decoded));

        // Test SecretKey serialization
        let sk_encoded = sk.as_ssz_bytes();
        let sk_decoded = <Sig as SignatureScheme>::SecretKey::from_ssz_bytes(&sk_encoded).unwrap();
        // Sign with decoded key
        let sig2 = Sig::sign(&sk_decoded, epoch + 1, &message).unwrap();
        // Verify signature from decoded key validates
        assert!(Sig::verify(&pk, epoch + 1, &message, &sig2));
    }

    proptest! {
        #[test]
        fn proptest_ssz_public_key_roundtrip_and_determinism(
            root_values in prop::collection::vec(0u32..F::ORDER_U32, 7),
            param_values in prop::collection::vec(0u32..F::ORDER_U32, 5)
        ) {
            // build public key from random field element values
            let root_arr: [F; 7] = std::array::from_fn(|i| F::new(root_values[i]));
            let param_arr: [F; 5] = std::array::from_fn(|i| F::new(param_values[i]));

            let original = GeneralizedXMSSPublicKey::<TestTH> {
                root: FieldArray(root_arr),
                parameter: FieldArray(param_arr),
            };

            // encode to SSZ bytes
            let encoded1 = original.as_ssz_bytes();
            let encoded2 = original.as_ssz_bytes();

            // check encoding is deterministic
            prop_assert_eq!(&encoded1, &encoded2);

            // check size matches expected (7 + 5 field elements * 4 bytes)
            let expected_size = 12 * F::NUM_BYTES;
            prop_assert_eq!(encoded1.len(), expected_size);
            prop_assert_eq!(original.ssz_bytes_len(), expected_size);

            // decode and check roundtrip preserves data
            let decoded = GeneralizedXMSSPublicKey::<TestTH>::from_ssz_bytes(&encoded1)
                .expect("valid SSZ bytes should decode");

            prop_assert_eq!(original.root, decoded.root);
            prop_assert_eq!(original.parameter, decoded.parameter);
        }
    }
}
