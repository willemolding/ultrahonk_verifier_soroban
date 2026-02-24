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

use crate::constants::EVM_WORD_SIZE;
pub use ark_bn254::{Fq, Fq2, Fr, FrConfig};
use ark_bn254::{G1Affine, G2Affine};
use soroban_sdk::{Bytes, Env};

pub type EVMWord = [u8; EVM_WORD_SIZE];
pub type U256 = ark_ff::BigInteger256;
pub type G1 = G1Affine;
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
