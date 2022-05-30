/**
 *  Copyright (C) 2021 FISCO BCOS.
 *  SPDX-License-Identifier: Apache-2.0
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * @brief Hash algorithm of keccak256
 * @file Keccak256.cpp
 */
#include <bcos-crypto/hash/Keccak256.h>
#include <wedpr-crypto/WedprCrypto.h>

using namespace bcos;
using namespace bcos::crypto;
HashType bcos::crypto::keccak256Hash(bytesConstRef _data)
{
    OPENSSL_Keccak256_Hasher hasher;
    return hasher.calculate(_data);
}

HashType Keccak256::hash(bytesConstRef _data)
{
    return m_hasher->calculate(_data);
}

// init a hashContext
void* Keccak256::init()
{
    return m_hasher->init();
}

// update the hashContext
void* Keccak256::update(void* _hashContext, bytesConstRef _data)
{
    return m_hasher->update(_hashContext, _data);
}

// final the hashContext
HashType Keccak256::final(void* _hashContext)
{
    return m_hasher->final(_hashContext);
}
