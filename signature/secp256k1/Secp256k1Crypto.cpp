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
 * @brief implementation for secp256k1 signature algorithm
 * @file Secp256k1Signature.cpp
 * @date 2021.03.05
 * @author yujiechen
 */

#include "Secp256k1Crypto.h"
#include "Secp256k1KeyPair.h"
#include <bcos-crypto/signature/Exceptions.h>
#include <bcos-crypto/signature/codec/SignatureDataWithV.h>
#include <wedpr-crypto/WeDPRCrypto.h>

using namespace bcos;
using namespace bcos::crypto;

std::shared_ptr<bytes> bcos::crypto::secp256k1Sign(KeyPair const& _keyPair, const HashType& _hash)
{
    FixedBytes<SECP256K1_SIGNATURE_LEN> signatureDataArray;
    CInputBuffer privateKey{(const char*)_keyPair.secretKey().data(), Secret::size};
    CInputBuffer msgHash{(const char*)_hash.data(), HashType::size};
    COutputBuffer secp256k1SignatureResult{
        (char*)signatureDataArray.data(), SECP256K1_SIGNATURE_LEN};
    auto retCode = wedpr_secp256k1_sign(&privateKey, &msgHash, &secp256k1SignatureResult);
    if (retCode != 0)
    {
        BOOST_THROW_EXCEPTION(SignException() << errinfo_comment(
                                  "secp256k1Sign exception, raw data: " + _hash.hex()));
    }
    std::shared_ptr<bytes> signatureData = std::make_shared<bytes>();
    *signatureData = signatureDataArray.asBytes();
    return signatureData;
}

bool bcos::crypto::secp256k1Verify(
    Public const& _pubKey, const HashType& _hash, bytesConstRef _signatureData)
{
    CInputBuffer publicKey{(const char*)_pubKey.data(), Public::size};
    CInputBuffer msgHash{(const char*)_hash.data(), HashType::size};
    CInputBuffer signature{(const char*)_signatureData.data(), _signatureData.size()};
    auto verifyResult = wedpr_secp256k1_verify(&publicKey, &msgHash, &signature);
    if (verifyResult == 0)
    {
        return true;
    }
    return false;
}

std::shared_ptr<KeyPair> bcos::crypto::secp256k1GenerateKeyPair()
{
    auto keyPair = std::make_shared<Secp256k1KeyPair>();
    COutputBuffer publicKey{(char*)keyPair->mutPublicKey().data(), Public::size};
    COutputBuffer privateKey{(char*)keyPair->mutSecretKey().data(), Secret::size};
    auto retCode = wedpr_secp256k1_gen_key_pair(&publicKey, &privateKey);
    if (retCode != 0)
    {
        BOOST_THROW_EXCEPTION(
            GenerateKeyPairException() << errinfo_comment("secp256k1GenerateKeyPair exception"));
    }
    return keyPair;
}

Public bcos::crypto::secp256k1Recover(const HashType& _hash, bytesConstRef _signatureData)
{
    CInputBuffer msgHash{(const char*)_hash.data(), HashType::size};
    CInputBuffer signature{(const char*)_signatureData.data(), _signatureData.size()};
    Public pubKey;
    COutputBuffer publicKeyResult{(char*)pubKey.data(), Public::size};
    auto retCode = wedpr_secp256k1_recover_public_key(&msgHash, &signature, &publicKeyResult);
    if (retCode != 0)
    {
        BOOST_THROW_EXCEPTION(InvalidSignature() << errinfo_comment(
                                  "invalid signature: secp256k1Recover failed, msgHash : " +
                                  _hash.hex() + ", signData:" + *toHexString(_signatureData)));
    }
    return pubKey;
}

std::pair<bool, bytes> bcos::crypto::secp256k1Recover(Hash::Ptr _hashImpl, bytesConstRef _input)
{
    struct
    {
        HashType hash;
        h256 v;
        h256 r;
        h256 s;
    } in;
    memcpy(&in, _input.data(), std::min(_input.size(), sizeof(_input)));
    u256 v = (u256)in.v;
    if (v >= 27 && v <= 28)
    {
        auto signatureData = std::make_shared<SignatureDataWithV>(
            in.r, in.s, (byte)((int)v - 27), SECP256K1_SIGNATURE_LEN);
        try
        {
            auto encodedBytes = std::make_shared<bytes>();
            signatureData->encode(encodedBytes);
            auto publicKey = secp256k1Recover(
                in.hash, bytesConstRef(encodedBytes->data(), encodedBytes->size()));
            auto address = getAddress(_hashImpl, publicKey);
            return {true, address.asBytes()};
        }
        catch (const std::exception& e)
        {
            LOG(WARNING) << LOG_DESC("secp256k1Recover failed")
                         << LOG_KV("error", boost::diagnostic_information(e));
        }
    }
    return {false, {}};
}