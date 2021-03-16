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
#include <WeDPRCrypto.h>
#include <bcos-crypto/signature/Exceptions.h>

using namespace bcos;
using namespace bcos::crypto;
std::shared_ptr<bytes> bcos::crypto::secp256k1Sign(KeyPair const& _keyPair, const h256& _hash)
{
    FixedBytes<65> signatureDataArray;
    SignatureResult secp256k1SignatureResult{(char*)signatureDataArray.data(), 65};
    auto retCode = wedpr_secp256k1_sign_binary(&secp256k1SignatureResult,
        (const char*)_keyPair.secretKey().data(), Secret::size, (const char*)_hash.data(),
        h256::size);
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
    Public const& _pubKey, const h256& _hash, bytesConstRef _signatureData)
{
    auto verifyResult = wedpr_secp256k1_verify_binary((const char*)_pubKey.data(), Public::size,
        (const char*)_hash.data(), h256::size, (const char*)_signatureData.data(),
        _signatureData.size());
    if (verifyResult == 0)
    {
        return true;
    }
    return false;
}

std::shared_ptr<KeyPair> bcos::crypto::secp256k1GenerateKeyPair()
{
    auto keyPair = std::make_shared<Secp256k1KeyPair>();
    KeyPairData keyPairData = {(char*)keyPair->mutPublicKey().data(), Public::size,
        (char*)keyPair->mutSecretKey().data(), Secret::size};
    auto retCode = wedpr_secp256k1_gen_binary_key_pair(&keyPairData);
    if (retCode != 0)
    {
        BOOST_THROW_EXCEPTION(
            GenerateKeyPairException() << errinfo_comment("secp256k1GenerateKeyPair exception"));
    }
    return keyPair;
}

Public bcos::crypto::secp256k1Recover(const h256& _hash, bytesConstRef _signatureData)
{
    Public pubKey;
    PublicKey publicKeyResult{(char*)pubKey.data(), Public::size};
    auto retCode =
        wedpr_secp256k1_recover_binary_public_key(&publicKeyResult, (const char*)_hash.data(),
            h256::size, (const char*)_signatureData.data(), _signatureData.size());
    if (retCode != 0)
    {
        BOOST_THROW_EXCEPTION(InvalidSignature() << errinfo_comment(
                                  "invalid signature: secp256k1Recover failed, msgHash : " +
                                  _hash.hex() + ", signData:" + *toHexString(_signatureData)));
    }
    return pubKey;
}

std::pair<bool, bytes> bcos::crypto::secp256k1Recover(bytesConstRef _input)
{
    struct
    {
        h256 hash;
        h256 v;
        h256 r;
        h256 s;
    } in;
    memcpy(&in, _input.data(), std::min(_input.size(), sizeof(_input)));
    u256 v = (u256)in.v;
    if (v >= 27 && v <= 28)
    {
        auto signatureData =
            std::make_shared<Secp256k1SignatureData>(in.r, in.s, (byte)((int)v - 27));
        try
        {
            auto encodedBytes = std::make_shared<bytes>();
            signatureData->encode(encodedBytes);
            auto publicKey = secp256k1Recover(
                in.hash, bytesConstRef(encodedBytes->data(), encodedBytes->size()));
            auto address = secp256k1ToAddress(publicKey);
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

Address Secp256k1Crypto::calculateAddress(Public const& _pubKey)
{
    return secp256k1ToAddress(_pubKey);
}