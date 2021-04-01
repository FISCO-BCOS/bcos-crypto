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
 * @file SM2Crypto.cpp
 * @date 2021.03.10
 * @author yujiechen
 */
#include "SM2Crypto.h"
#include "SM2KeyPair.h"
#include <bcos-crypto/hash/SM3.h>
#include <bcos-crypto/signature/Exceptions.h>
#include <bcos-crypto/signature/codec/SignatureDataWithPub.h>

using namespace bcos;
using namespace bcos::crypto;

std::shared_ptr<bytes> bcos::crypto::sm2Sign(KeyPair const& _keyPair, const HashType& _hash)
{
    FixedBytes<SM2_SIGNATURE_LEN> signatureDataArray;
    CInputBuffer rawPrivateKey{(const char*)_keyPair.secretKey().data(), Secret::size};
    CInputBuffer rawPublicKey{(const char*)_keyPair.publicKey().data(), Public::size};
    CInputBuffer rawMsgHash{(const char*)_hash.data(), HashType::size};
    COutputBuffer sm2SignatureResult{(char*)signatureDataArray.data(), SM2_SIGNATURE_LEN};
    auto retCode =
        wedpr_sm2_sign_fast(&rawPrivateKey, &rawPublicKey, &rawMsgHash, &sm2SignatureResult);
    if (retCode != 0)
    {
        BOOST_THROW_EXCEPTION(
            SignException() << errinfo_comment("sm2Sign failed, raw data: " + _hash.hex()));
    }
    std::shared_ptr<bytes> signatureData = std::make_shared<bytes>();
    *signatureData = signatureDataArray.asBytes();
    // append the public key
    signatureData->insert(
        signatureData->end(), _keyPair.publicKey().begin(), _keyPair.publicKey().end());
    return signatureData;
}

std::shared_ptr<KeyPair> bcos::crypto::sm2GenerateKeyPair()
{
    auto keyPair = std::make_shared<SM2KeyPair>();
    COutputBuffer publicKey{(char*)keyPair->mutPublicKey().data(), Public::size};
    COutputBuffer privateKey{(char*)keyPair->mutSecretKey().data(), Secret::size};
    auto retCode = wedpr_sm2_gen_key_pair(&publicKey, &privateKey);
    if (retCode != 0)
    {
        BOOST_THROW_EXCEPTION(GenerateKeyPairException() << errinfo_comment("sm2GenerateKeyPair"));
    }
    return keyPair;
}

bool bcos::crypto::sm2Verify(
    Public const& _pubKey, const HashType& _hash, bytesConstRef _signatureData)
{
    auto signatureWithoutPub = bytesConstRef(_signatureData.data(), SM2_SIGNATURE_LEN);
    CInputBuffer publicKey{(const char*)_pubKey.data(), Public::size};
    CInputBuffer messageHash{(const char*)_hash.data(), HashType::size};
    CInputBuffer signature{(const char*)signatureWithoutPub.data(), signatureWithoutPub.size()};
    auto verifyResult = wedpr_sm2_verify(&publicKey, &messageHash, &signature);
    if (verifyResult == 0)
    {
        return true;
    }
    return false;
}

Public bcos::crypto::sm2Recover(const HashType& _hash, bytesConstRef _signData)
{
    auto signatureStruct = std::make_shared<SignatureDataWithPub>(_signData, SM2_SIGNATURE_LEN);
    if (sm2Verify(signatureStruct->pub(), _hash, _signData))
    {
        return signatureStruct->pub();
    }
    BOOST_THROW_EXCEPTION(InvalidSignature() << errinfo_comment(
                              "invalid signature: sm2 recover public key failed, msgHash : " +
                              _hash.hex() + ", signature:" + *toHexString(_signData)));
}

std::pair<bool, bytes> bcos::crypto::sm2Recover(Hash::Ptr _hashImpl, bytesConstRef _input)
{
    struct
    {
        HashType hash;
        h512 pub;
        h256 r;
        h256 s;
    } in;
    memcpy(&in, _input.data(), std::min(_input.size(), sizeof(_input)));
    // verify the signature
    auto signatureData =
        std::make_shared<SignatureDataWithPub>(in.r, in.s, in.pub, SM2_SIGNATURE_LEN);
    try
    {
        std::shared_ptr<bytes> encodedData = std::make_shared<bytes>();
        signatureData->encode(encodedData);
        if (sm2Verify(signatureData->pub(), in.hash,
                bytesConstRef(encodedData->data(), encodedData->size())))
        {
            auto address = getAddress(_hashImpl, signatureData->pub());
            return {true, address.asBytes()};
        }
    }
    catch (const std::exception& e)
    {
        LOG(WARNING) << LOG_DESC("sm2Recover failed")
                     << LOG_KV("error", boost::diagnostic_information(e));
    }
    return {false, {}};
}
