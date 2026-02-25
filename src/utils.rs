// Copyright 2022 Aztec
// Copyright 2025 Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0 or MIT

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Copyright 2022 Aztec
// Copyright 2024 Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0 or MIT

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{
    constants::{EVM_WORD_SIZE, GROUP_ELEMENT_SIZE},
    errors::{FieldError, GroupError},
    types::G1,
    EVMWord, Fq, Fq2, Fr, G2, U256,
};
use alloc::{format, string::String};
use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup, PrimeField};

pub(crate) trait IntoFq {
    fn into_fq(self) -> Fq;
}

impl IntoFq for U256 {
    fn into_fq(self) -> Fq {
        Fq::from(self)
    }
}

pub(crate) trait IntoU256 {
    fn into_u256(self) -> U256;
}

impl IntoU256 for &EVMWord {
    fn into_u256(self) -> U256 {
        let mut rchunks_iter = self.rchunks_exact(8);
        let limbs: [_; 4] = core::array::from_fn(|_| {
            u64::from_be_bytes(rchunks_iter.next().unwrap().try_into().unwrap())
        });
        debug_assert!(rchunks_iter.remainder().is_empty());

        U256::new(limbs)
    }
}

/// Trait for returning a big-endian representation of some object as an `EVMWord`.
pub(crate) trait IntoBEBytes32 {
    fn into_be_bytes32(self) -> EVMWord;
}

impl IntoBEBytes32 for U256 {
    fn into_be_bytes32(self) -> EVMWord {
        let mut rev_iter_be = self.0.iter().rev().flat_map(|limb| limb.to_be_bytes());
        core::array::from_fn(|_| rev_iter_be.next().unwrap())
    }
}

impl IntoBEBytes32 for Fr {
    fn into_be_bytes32(self) -> EVMWord {
        self.into_bigint().into_be_bytes32()
    }
}

impl IntoBEBytes32 for Fq {
    fn into_be_bytes32(self) -> EVMWord {
        self.into_bigint().into_be_bytes32()
    }
}

impl IntoBEBytes32 for u64 {
    fn into_be_bytes32(self) -> EVMWord {
        let be = self.to_be_bytes();
        let mut arr = [0u8; EVM_WORD_SIZE];
        arr[EVM_WORD_SIZE - 8..].copy_from_slice(&be);
        arr
    }
}

#[inline(always)]
fn parse_u64_evm_word(chunk: &EVMWord) -> Result<u64, ()> {
    let upper = u64::from_be_bytes(
        chunk[0..8]
            .try_into()
            .expect("EVMWords have at least 8 bytes"),
    ) | u64::from_be_bytes(
        chunk[8..16]
            .try_into()
            .expect("EVMWords have at least 16 bytes"),
    ) | u64::from_be_bytes(
        chunk[16..24]
            .try_into()
            .expect("EVMWords have at least 24 bytes"),
    );

    if upper != 0 {
        return Err(());
    }

    Ok(u64::from_be_bytes(
        chunk[24..32]
            .try_into()
            .expect("EVMWords always have 32 bytes"),
    ))
}

pub(crate) fn read_u64_from_evm_word(data: &[u8]) -> Result<u64, ()> {
    let chunk: &EVMWord = data
        .get(..EVM_WORD_SIZE)
        .ok_or(())?
        .try_into()
        .expect("Conversion should succeed at this point");
    parse_u64_evm_word(chunk)
}

pub(crate) fn read_u64_from_evm_word_by_splitting(data: &mut Bytes) -> Result<u64, ()> {
    let chunk = split_off::<EVM_WORD_SIZE>(data);
    parse_u64_evm_word(&chunk)
}

pub(crate) fn read_u256(bytes: &[u8]) -> Result<U256, ()> {
    <&EVMWord>::try_from(bytes)
        .map_err(|_| ())
        .map(IntoU256::into_u256)
}

pub(crate) fn split_off<const N: usize>(data: &mut Bytes) -> [u8; N] {
    let mut chunk = [0_u8; N];
    data.slice(..N as u32).copy_into_slice(&mut chunk);
    *data = data.slice(N as u32..);
    chunk
}

// Parse point in G1.
pub(crate) fn read_g1_by_splitting(data: &mut Bytes) -> Result<G1, GroupError> {
    let chunk = split_off::<GROUP_ELEMENT_SIZE>(data);

    let tmp_x = read_u256(&chunk[0..EVM_WORD_SIZE]).expect("Conversion should work at this point");
    let x = Fq::from_bigint(tmp_x).ok_or(GroupError::CoordinateExceedsModulus {
        coordinate_value: tmp_x,
        modulus: Fq::MODULUS,
    })?;

    let tmp_y = read_u256(&chunk[EVM_WORD_SIZE..GROUP_ELEMENT_SIZE])
        .expect("Conversion should work at this point");
    let y = Fq::from_bigint(tmp_y).ok_or(GroupError::CoordinateExceedsModulus {
        coordinate_value: tmp_y,
        modulus: Fq::MODULUS,
    })?;

    // If (0, 0) is given, we interpret this as the point at infinity:
    // https://docs.rs/ark-ec/0.5.0/src/ark_ec/models/short_weierstrass/affine.rs.html#212-218
    if x == Fq::ZERO && y == Fq::ZERO {
        return Ok(G1::zero(data.env()));
    }

    let point = G1::new_unchecked(data.env(), x, y);

    Ok(point)
}

// Utility function for parsing points in G2.
pub(crate) fn read_fq_util(data: &[u8]) -> Result<Fq, FieldError> {
    if data.len() != 32 {
        return Err(FieldError::InvalidSliceLength {
            expected_length: 32,
            actual_length: data.len(),
        });
    }

    let mut rchunks_iter = data.rchunks(8);
    let limbs = core::array::from_fn(|_| {
        u64::from_be_bytes(rchunks_iter.next().unwrap().try_into().unwrap())
    });

    Ok(U256::new(limbs).into_fq())
}

// Utility for logging and debugging.
pub(crate) fn to_hex_string(data: &[u8]) -> String {
    let hex_string: String = data.iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{hex_string}")
}

// Soroban type conversion utils
use ark_ff::BigInteger;
use soroban_sdk::{Bytes, Env};

pub(crate) fn to_soroban_fr(env: &Env, fr: &Fr) -> soroban_sdk::crypto::bn254::Fr {
    let be_bytes = fr.into_bigint().to_bytes_be();
    soroban_sdk::crypto::bn254::Fr::from_u256(soroban_sdk::U256::from_be_bytes(
        env,
        &Bytes::from_slice(env, &be_bytes),
    ))
}

// pub(crate) fn to_soroban_g1(env: &Env, affine: &G1) -> soroban_sdk::crypto::bn254::Bn254G1Affine {
//     let mut out = [0u8; 64];

//     if affine.is_zero() {
//         return soroban_sdk::crypto::bn254::Bn254G1Affine::from_array(env, &out);
//         // 64 zero bytes = point at infinity
//     }

//     let x = affine.x().into_bigint().to_bytes_be();
//     let y = affine.y().into_bigint().to_bytes_be();

//     out[..32].copy_from_slice(&x);
//     out[32..].copy_from_slice(&y);

//     // Spec requires flag bits (0x80 and 0x40) of the first byte to be unset.
//     // For a valid BN254 Fq element these should never be set — assert to catch
//     // any encoding bugs early rather than producing a silently wrong point.
//     assert!(out[0] & 0xc0 == 0, "flag bits set in G1 point encoding");

//     soroban_sdk::crypto::bn254::Bn254G1Affine::from_array(env, &out)
// }

// pub(crate) fn from_soroban_g1(point: &soroban_sdk::crypto::bn254::Bn254G1Affine) -> G1 {
//     let arr = point.to_array();
//     let x = read_u256(&arr[..32]).expect("Conversion should work at this point");
//     let y = read_u256(&arr[32..]).expect("Conversion should work at this point");

//     // If (0, 0) is given, we interpret this as the point at infinity:
//     // https://docs.rs/ark-ec/0.5.0/src/ark_ec/models/short_weierstrass/affine.rs.html#212-218
//     if x == U256::zero() && y == U256::zero() {
//         return G1::zero();
//     }

//     G1::new_unchecked(x.into_fq(), y.into_fq())
// }

// pub(crate) fn to_soroban_g2(env: &Env, affine: &G2) -> soroban_sdk::crypto::bn254::Bn254G2Affine {
//     let mut out = [0u8; 128];

//     if affine.is_zero() {
//         return soroban_sdk::crypto::bn254::Bn254G2Affine::from_array(env, &out);
//         // 128 zero bytes = point at infinity
//     }

//     // Fq2 elements have two components: c0 and c1
//     // Ethereum encoding order: c1 before c0 for each coordinate
//     let x_c1 = affine.x().c1.into_bigint().to_bytes_be();
//     let x_c0 = affine.x().c0.into_bigint().to_bytes_be();
//     let y_c1 = affine.y().c1.into_bigint().to_bytes_be();
//     let y_c0 = affine.y().c0.into_bigint().to_bytes_be();

//     out[0..32].copy_from_slice(&x_c1);
//     out[32..64].copy_from_slice(&x_c0);
//     out[64..96].copy_from_slice(&y_c1);
//     out[96..128].copy_from_slice(&y_c0);

//     // Same flag bit check as G1 — valid Fq elements always have top two bits unset
//     assert!(out[0] & 0xc0 == 0, "flag bits set in G2 point encoding");
//     assert!(out[32] & 0xc0 == 0, "flag bits set in G2 point encoding");
//     assert!(out[64] & 0xc0 == 0, "flag bits set in G2 point encoding");
//     assert!(out[96] & 0xc0 == 0, "flag bits set in G2 point encoding");

//     soroban_sdk::crypto::bn254::Bn254G2Affine::from_array(env, &out)
// }

pub(crate) fn soroban_msm(env: &Env, points: &[G1], scalars: &[crate::Fr]) -> crate::G1 {
    assert_eq!(points.len(), scalars.len());

    let mut acc = soroban_sdk::crypto::bn254::Bn254G1Affine::from_array(env, &[0u8; 64]);
    for (point, scalar) in points.iter().zip(scalars.iter()) {
        let scaled = env
            .crypto()
            .bn254()
            .g1_mul(&point.0, &to_soroban_fr(env, scalar));
        acc = acc + scaled;
    }
    crate::G1(acc)
}
