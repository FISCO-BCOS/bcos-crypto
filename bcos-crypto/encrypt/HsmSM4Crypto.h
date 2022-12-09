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
 * @brief implementation for HSM sm4 encryption/decryption
 * @file HsmSM4Crypto.h
 * @date 2022.11.04
 * @author lucasli
 */
#pragma once
#include <bcos-crypto/interfaces/crypto/SymmetricEncryption.h>

namespace bcos
{
namespace crypto
{
class HsmSM4Crypto : public SymmetricEncryption
{
public:
    using Ptr = std::shared_ptr<HsmSM4Crypto>;
    HsmSM4Crypto(std::string _libPath) { m_hsmLibPath = _libPath; }
    ~HsmSM4Crypto() override {}

    bytesPointer symmetricEncrypt(const unsigned char* _plainData, size_t _plainDataSize,
        const unsigned char* _key, size_t _keySize) override
    {
        return symmetricEncrypt(_plainData, _plainDataSize, _key, _keySize, _key, 16);
    }
    bytesPointer symmetricDecrypt(const unsigned char* _cipherData, size_t _cipherDataSize,
        const unsigned char* _key, size_t _keySize) override
    {
        return symmetricDecrypt(_cipherData, _cipherDataSize, _key, _keySize, _key, 16);
    }
    bytesPointer symmetricEncrypt(const unsigned char* _plainData, size_t _plainDataSize,
        const unsigned char* _key, size_t _keySize, const unsigned char* _ivData,
        size_t _ivDataSize) override
    {
        return HsmSM4Encrypt(_plainData, _plainDataSize, _key, _keySize, _ivData, _ivDataSize);
    }
    bytesPointer symmetricDecrypt(const unsigned char* _cipherData, size_t _cipherDataSize,
        const unsigned char* _key, size_t _keySize, const unsigned char* _ivData,
        size_t _ivDataSize) override
    {
        return HsmSM4Decrypt(_cipherData, _cipherDataSize, _key, _keySize, _ivData, _ivDataSize);
    }

    bytesPointer HsmSM4Encrypt(const unsigned char* _plainData, size_t _plainDataSize,
        const unsigned char* _key, size_t _keySize, const unsigned char* _ivData,
        size_t _ivDataSize);
    bytesPointer HsmSM4Decrypt(const unsigned char* _cipherData, size_t _cipherDataSize,
        const unsigned char* _key, size_t _keySize, const unsigned char* _ivData,
        size_t _ivDataSize);

private:
    std::string m_hsmLibPath;
};
}  // namespace crypto
}  // namespace bcos