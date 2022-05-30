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
 * @brief Hash algorithm of sha3
 * @file Sha3.h
 * @date 2021.04.01
 * @author yujiechen
 */
#pragma once
#include "OpenSSLHasher.h"
#include <bcos-crypto/interfaces/crypto/Hash.h>
#include <wedpr-crypto/WedprCrypto.h>
#include <wedpr-crypto/WedprUtilities.h>

namespace bcos
{
namespace crypto
{
HashType inline sha3Hash(bytesConstRef _data)
{
    OpenSSL_SHA3_256_Hasher hasher;
    return hasher.calculate(_data);
}
class Sha3 : public Hash
{
public:
    using Ptr = std::shared_ptr<Sha3>;
    Sha3() : m_hasher(std::make_shared<OpenSSL_SHA3_256_Hasher>())
    {
        setHashImplType(HashImplType::Sha3);
    }
    virtual ~Sha3() {}
    HashType hash(bytesConstRef _data) override { return m_hasher->calculate(_data); }
    // init a hashContext
    void* init() override { return m_hasher->init(); }
    // update the hashContext
    void* update(void* _hashContext, bytesConstRef _data) override
    {
        return m_hasher->update(_hashContext, _data);
    }
    // final the hashContext
    HashType final(void* _hashContext) override { return m_hasher->final(_hashContext); }

private:
    std::shared_ptr<OpenSSL_SHA3_256_Hasher> m_hasher;
};
}  // namespace crypto
}  // namespace bcos