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
 * @brief test cases for secp256k1/sm2
 * @file SignatureTest.h
 * @date 2021.03.06
 */
#include <bcos-crypto/hash/Keccak256.h>
#include <bcos-crypto/hash/SM3.h>
#include <bcos-crypto/signature/Exceptions.h>
#include <bcos-crypto/signature/secp256k1/Secp256k1Crypto.h>
#include <bcos-crypto/signature/secp256k1/Secp256k1KeyPair.h>
#include <bcos-crypto/signature/sm2/SM2Crypto.h>
#include <bcos-crypto/signature/sm2/SM2KeyPair.h>
#include <bcos-test/libutils/TestPromptFixture.h>
#include <boost/test/unit_test.hpp>
#include <string>
using namespace bcos;
using namespace bcos::crypto;

namespace bcos
{
namespace test
{
BOOST_FIXTURE_TEST_SUITE(SignatureTest, TestPromptFixture)
BOOST_AUTO_TEST_CASE(testSecp256k1KeyPair)
{
    BOOST_CHECK(Secret::size == 32);
    BOOST_CHECK(Public::size == 64);
    // check secret->public
    bcos::crypto::Secret sec1(
        "bcec428d5205abe0f0cc8a7340839"
        "08d9eb8563e31f943d760786edf42ad67dd");
    bcos::crypto::Public pub1 = secp256k1PriToPub(sec1);
    bcos::crypto::Secret sec2("bcec428d5205abe0");
    bcos::crypto::Public pub2 = secp256k1PriToPub(sec2);
    BOOST_CHECK(pub1 != pub2);
    // check address
    auto secp256k1KeyPair1 = std::make_shared<Secp256k1KeyPair>(sec1);
    auto secp256k1KeyPair2 = std::make_shared<Secp256k1KeyPair>(sec2);

    Address address1 = secp256k1KeyPair1->address();
    Address address2 = secp256k1KeyPair2->address();
    BOOST_CHECK(address1 != address2);
    // test calculateAddress
    BOOST_CHECK(secp256k1KeyPair1->address() == secp256k1KeyPair1->calculateAddress(pub1));
    BOOST_CHECK(secp256k1KeyPair2->address() == secp256k1KeyPair2->calculateAddress(pub2));
    BOOST_CHECK(secp256k1KeyPair1->calculateAddressBySecret(sec1) ==
                secp256k1KeyPair1->calculateAddress(pub1));
    BOOST_CHECK(secp256k1KeyPair2->calculateAddressBySecret(sec2) ==
                secp256k1KeyPair2->calculateAddress(pub2));
    BOOST_CHECK(secp256k1KeyPair1->calculateAddressBySecret(sec1) !=
                secp256k1KeyPair2->calculateAddressBySecret(sec2));

    // create KeyPair
    auto keyPair = secp256k1GenerateKeyPair();
    BOOST_CHECK(keyPair->secretKey());
    BOOST_CHECK(keyPair->publicKey());
    std::cout << "#### generated public key:" << keyPair->publicKey().hex() << std::endl;
    Public testPub = secp256k1PriToPub(keyPair->secretKey());
    BOOST_CHECK_EQUAL(keyPair->publicKey(), testPub);

    Secret empty;
    BOOST_CHECK_THROW(Secp256k1KeyPair emptyKeyPair(empty), PriToPublicKeyException);
}
BOOST_AUTO_TEST_CASE(testSecp256k1SignAndVerify)
{
    auto keyPair = secp256k1GenerateKeyPair();
    auto hashData = keccak256Hash((std::string)("abcd"));
    std::cout << "### hashData:" << *toHexString(hashData) << std::endl;
    /// normal check
    // sign
    auto signData = secp256k1Sign(*keyPair, hashData);
    std::cout << "### signData:" << *toHexString(*signData) << std::endl;
    // verify
    bool result = secp256k1Verify(
        keyPair->publicKey(), hashData, bytesConstRef(signData->data(), signData->size()));
    BOOST_CHECK(result == true);
    std::cout << "### verify result:" << result << std::endl;

    // recover
    auto pub = secp256k1Recover(hashData, bytesConstRef(signData->data(), signData->size()));
    std::cout << "### secp256k1Recover begin, publicKey:" << *toHexString(keyPair->publicKey())
              << std::endl;
    std::cout << "#### recoverd publicKey:" << *toHexString(pub) << std::endl;
    BOOST_CHECK(pub == keyPair->publicKey());
    /// exception check:
    // check1: invalid payload(hash)
    h256 invalidHash = keccak256Hash((std::string)("abce"));
    result = secp256k1Verify(
        keyPair->publicKey(), invalidHash, bytesConstRef(signData->data(), signData->size()));
    BOOST_CHECK(result == false);

    Public invalidPub = {};
    invalidPub = secp256k1Recover(invalidHash, bytesConstRef(signData->data(), signData->size()));
    BOOST_CHECK(invalidPub != keyPair->publicKey());

    // check2: invalid sig
    auto anotherSig(secp256k1Sign(*keyPair, invalidHash));
    result = secp256k1Verify(
        keyPair->publicKey(), hashData, bytesConstRef(anotherSig->data(), anotherSig->size()));
    BOOST_CHECK(result == false);

    invalidPub = secp256k1Recover(hashData, bytesConstRef(anotherSig->data(), anotherSig->size()));
    BOOST_CHECK(invalidPub != keyPair->publicKey());

    // check3: invalid keyPair
    auto keyPair2 = secp256k1GenerateKeyPair();
    result = secp256k1Verify(
        keyPair2->publicKey(), hashData, bytesConstRef(signData->data(), signData->size()));
    BOOST_CHECK(result == false);

    h256 r(keccak256Hash(std::string("+++")));
    h256 s(keccak256Hash(std::string("24324")));
    byte v = 4;
    auto signatureData = std::make_shared<Secp256k1SignatureData>(r, s, v);
    auto secp256k1Crypto = std::make_shared<Secp256k1Crypto>();
    BOOST_CHECK_THROW(secp256k1Crypto->recoverSignature(hashData, signatureData), InvalidSignature);

    // test signatureData encode and decode
    auto encodedData = std::make_shared<bytes>();
    signatureData->encode(encodedData);
    auto signatureData2 = std::make_shared<Secp256k1SignatureData>(
        bytesConstRef(encodedData->data(), encodedData->size()));
    BOOST_CHECK(signatureData2->r() == signatureData->r());
    BOOST_CHECK(signatureData2->s() == signatureData->s());
    BOOST_CHECK(signatureData2->v() == signatureData->v());

    auto signatureData3 =
        std::make_shared<Secp256k1SignatureData>(bytesConstRef(signData->data(), signData->size()));
    signatureData3->encode(encodedData);
    BOOST_CHECK(*signData == *encodedData);
    auto publicKey = secp256k1Crypto->recoverSignature(hashData, signatureData3);
    BOOST_CHECK(publicKey == keyPair->publicKey());
}

BOOST_AUTO_TEST_CASE(testSM2KeyPair)
{
    BOOST_CHECK(Secret::size == 32);
    BOOST_CHECK(Public::size == 64);
    // check secret->public
    Secret sec1(
        "bcec428d5205abe0f0cc8a7340839"
        "08d9eb8563e31f943d760786edf42ad67dd");
    auto pub1 = sm2PriToPub(sec1);
    Secret sec2("bcec428d5205abe0");
    auto pub2 = sm2PriToPub(sec2);
    BOOST_CHECK(pub1 != pub2);

    // check public to address
    Address address1 = sm2ToAddress(pub1);
    Address address2 = sm2ToAddress(pub2);
    BOOST_CHECK(address1 != address2);
    // check secret to address
    Address addressSec1 = sm2ToAddress(sec1);
    Address addressSec2 = sm2ToAddress(sec2);
    BOOST_CHECK(addressSec1 != addressSec2);
    BOOST_CHECK(address1 == addressSec1);
    BOOST_CHECK(address2 == addressSec2);
    // create keyPair
    auto keyPair = sm2GenerateKeyPair();
    BOOST_CHECK(keyPair->publicKey());
    BOOST_CHECK(keyPair->secretKey());
    pub1 = sm2PriToPub(keyPair->secretKey());
    BOOST_CHECK_EQUAL(keyPair->publicKey(), pub1);

/// TODO: fix the wedpr-crypto panic bug
#if 0
    // empty case
    Secret empty;
    SM2KeyPair sm2KeyPair(empty);
    BOOST_CHECK(!sm2KeyPair.address());
#endif
}
BOOST_AUTO_TEST_CASE(testSM2SignAndVerify)
{
    auto signatureCrypto = std::make_shared<SM2Crypto>();
    auto hashCrypto = std::make_shared<SM3>();
    auto keyPair = signatureCrypto->generateKeyPair();
    auto hashData = hashCrypto->hash(std::string("abcd"));
    // sign
    auto sig = signatureCrypto->sign(*keyPair, hashData);
    // verify
    bool result = signatureCrypto->verify(
        keyPair->publicKey(), hashData, bytesConstRef(sig->data(), sig->size()));
    std::cout << "#### phase 1, signatureData:" << *toHexString(*sig) << std::endl;
    BOOST_CHECK(result == true);
    // recover
    auto pub = signatureCrypto->recover(hashData, bytesConstRef(sig->data(), sig->size()));
    std::cout << "#### phase 2" << std::endl;
    BOOST_CHECK(pub == keyPair->publicKey());

    // exception case
    // invalid payload(hash)
    auto invalidHash = hashCrypto->hash(std::string("abce"));
    result = signatureCrypto->verify(
        keyPair->publicKey(), invalidHash, bytesConstRef(sig->data(), sig->size()));
    BOOST_CHECK(result == false);

    // recover
    BOOST_CHECK_THROW(
        signatureCrypto->recover(invalidHash, bytesConstRef(sig->data(), sig->size())),
        InvalidSignature);

    // invalid signature
    auto anotherSig = signatureCrypto->sign(*keyPair, invalidHash);
    result = signatureCrypto->verify(
        keyPair->publicKey(), hashData, bytesConstRef(anotherSig->data(), anotherSig->size()));
    BOOST_CHECK(result == false);
    BOOST_CHECK_THROW(
        signatureCrypto->recover(hashData, bytesConstRef(anotherSig->data(), anotherSig->size())),
        InvalidSignature);

    // invalid sig
    auto keyPair2 = signatureCrypto->generateKeyPair();
    result = signatureCrypto->verify(
        keyPair2->publicKey(), hashData, bytesConstRef(sig->data(), sig->size()));
    BOOST_CHECK(result == false);

    auto signatureStruct =
        std::make_shared<SM2SignatureData>(bytesConstRef(sig->data(), sig->size()));
    auto r = signatureStruct->r();
    auto s = signatureStruct->s();

    auto signatureStruct2 = std::make_shared<SM2SignatureData>(r, s, signatureStruct->pub());
    auto encodedData = std::make_shared<bytes>();
    signatureStruct2->encode(encodedData);
    auto recoverKey =
        signatureCrypto->recover(hashData, bytesConstRef(encodedData->data(), encodedData->size()));
    BOOST_CHECK(recoverKey == keyPair->publicKey());

#if 0
    // construct invalid r, v,s and check isValid() function
    h256 r(crypto::Hash("+++"));
    h256 s(crypto::Hash("24324"));
    h512 v(crypto::Hash("123456"));
    auto signatureData = std::make_shared<SM2SignatureData>(r, s, v);
    // check recover
    signatureData->encode(encodedData);
    BOOST_CHECK_THROW(signatureCrypto->recover(hashData, encodedData), InvalidSignature);
#endif
}
BOOST_AUTO_TEST_SUITE_END()
}  // namespace test
}  // namespace bcos