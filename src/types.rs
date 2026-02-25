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

use core::ops::Neg;
use core::str::FromStr;

use crate::{constants::EVM_WORD_SIZE, utils::IntoBEBytes32};
use ark_bn254::G2Affine;
pub use ark_bn254::{Fq, Fq2, Fr, FrConfig};
use ark_ff::{BigInt, Fp, PrimeField};
use soroban_sdk::{Bytes, BytesN, Env};

pub type EVMWord = [u8; EVM_WORD_SIZE];
pub type U256 = ark_ff::BigInteger256;
// pub type G1 = G1Affine;
pub type G2 = G2Affine;
pub type Bn254 = ark_bn254::Bn254;

pub struct Keccak256<'a> {
    env: &'a Env,
    hashbuffer: Bytes,
}

impl<'a> Keccak256<'a> {
    pub fn new(env: &'a Env) -> Self {
        Keccak256 {
            env,
            hashbuffer: Bytes::new(env),
        }
    }

    pub fn chain(mut self, data: impl AsRef<[u8]>) -> Self {
        self.hashbuffer.extend_from_slice(data.as_ref());
        self
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.hashbuffer.extend_from_slice(data.as_ref());
    }

    pub fn chain_update(mut self, data: impl AsRef<[u8]>) -> Self {
        self.hashbuffer.extend_from_slice(data.as_ref());
        self
    }

    pub fn finalize(self) -> [u8; 32] {
        let hash = self.env.crypto().keccak256(&self.hashbuffer);
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash.to_array());
        result
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct G1(pub soroban_sdk::crypto::bn254::Bn254G1Affine);

impl G1 {
    pub fn new_unchecked(env: &Env, x: Fq, y: Fq) -> Self {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(x.into_be_bytes32().as_slice());
        bytes[32..64].copy_from_slice(y.into_be_bytes32().as_slice());
        G1(soroban_sdk::crypto::bn254::Bn254G1Affine::from_array(
            env, &bytes,
        ))
    }

    pub fn zero(env: &Env) -> Self {
        G1(soroban_sdk::crypto::bn254::Bn254G1Affine::from_array(
            env, &[0u8; 64],
        ))
    }

    pub fn default(env: &Env) -> Self {
        Self::zero(env)
    }

    pub fn generator(env: &Env) -> Self {
        Self::new_unchecked(
            env,
            Fp::new(BigInt::from_str("1").unwrap()),
            Fp::new(BigInt::from_str("2").unwrap()),
        )
    }

    pub fn x(&self) -> Fq {
        let bytes = self.0.as_bytes();
        Fq::from_be_bytes_mod_order(bytes.to_array()[0..32].try_into().unwrap())
    }

    pub fn y(&self) -> Fq {
        let bytes = self.0.as_bytes();
        Fq::from_be_bytes_mod_order(bytes.to_array()[32..64].try_into().unwrap())
    }

    pub fn is_zero(&self) -> bool {
        self.0.as_bytes() == &BytesN::from_array(self.0.env(), &[0; 64])
    }
}

impl Neg for G1 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}
