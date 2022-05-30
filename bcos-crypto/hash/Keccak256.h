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
 * @file Keccak256.h
 * @date 2021.03.04
 * @author yujiechen
 */
#pragma once
#include "OpenSSLHasher.h"
#include <bcos-crypto/interfaces/crypto/Hash.h>
#include <wedpr-crypto/WedprCrypto.h>

namespace bcos
{
namespace crypto
{
class Keccak256 : public Hash
{
public:
    using Ptr = std::shared_ptr<Keccak256>;
    Keccak256() : m_hasher(std::make_shared<OPENSSL_Keccak256_Hasher>())
    {
        setHashImplType(HashImplType::Keccak256Hash);
    }
    ~Keccak256() override {}
    HashType hash(bytesConstRef _data) override;
    // init a hashContext
    void* init() override;
    // update the hashContext
    void* update(void* _hashContext, bytesConstRef _data) override;
    // final the hashContext
    HashType final(void* _hashContext) override;

private:
    std::shared_ptr<OPENSSL_Keccak256_Hasher> m_hasher;
};
HashType keccak256Hash(bytesConstRef _data);
}  // namespace crypto
}  // namespace bcos
