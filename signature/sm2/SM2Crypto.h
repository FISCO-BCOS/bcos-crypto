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
 * @brief implementation for sm2 signature
 * @file SM2Crypto.h
 * @date 2021.03.10
 * @author yujiechen
 */
#pragma once
#include <bcos-framework/interfaces/crypto/Signature.h>


namespace bcos
{
namespace crypto
{
const int SM2_SIGNATURE_LEN = 64;
std::shared_ptr<bytes> sm2Sign(KeyPair const& _keyPair, const HashType& _hash);
bool sm2Verify(Public const& _pubKey, const HashType& _hash, bytesConstRef _signatureData);
std::shared_ptr<KeyPair> sm2GenerateKeyPair();
Public sm2Recover(const HashType& _hash, bytesConstRef _signData);
std::pair<bool, bytes> sm2Recover(Hash::Ptr _hashImpl, bytesConstRef _in);

class SM2Crypto : public SignatureCrypto
{
public:
    using Ptr = std::shared_ptr<SM2Crypto>;
    SM2Crypto() = default;
    ~SM2Crypto() override {}
    std::shared_ptr<bytes> sign(KeyPair const& _keyPair, const HashType& _hash) override
    {
        return sm2Sign(_keyPair, _hash);
    }

    bool verify(Public const& _pubKey, const HashType& _hash, bytesConstRef _signatureData) override
    {
        return sm2Verify(_pubKey, _hash, _signatureData);
    }

    Public recover(const HashType& _hash, bytesConstRef _signatureData) override
    {
        return sm2Recover(_hash, _signatureData);
    }
    std::shared_ptr<KeyPair> generateKeyPair() override { return sm2GenerateKeyPair(); }
};
}  // namespace crypto
}  // namespace bcos