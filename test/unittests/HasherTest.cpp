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
 * @brief test cases for hashing256
 * @file HashingTest.h
 * @date 2022.04.19
 */
#include <bcos-crypto/hasher/OpenSSLHasher.h>
#include <bcos-crypto/interfaces/crypto/CryptoSuite.h>
#include <bcos-utilities/testutils/TestPromptFixture.h>
#include <boost/test/unit_test.hpp>
#include <string>

using namespace bcos;
using namespace crypto;
namespace bcos
{
namespace test
{
BOOST_FIXTURE_TEST_SUITE(HasherTest, TestPromptFixture)
BOOST_AUTO_TEST_CASE(testSHA256)
{
    std::string a = "arg";

    openssl::OpenSSL_SHA3_256_Hasher hash1;
    hash1.update(a);
    hash1.update("abcdefg");
    hash1.update(100);

    auto h1 = hash1.final();
    auto h2 = openssl::OpenSSL_SHA3_256_Hasher{}.update(a).update("abcdefg").update(100).final();

    BOOST_CHECK_EQUAL(h1, h2);
}

BOOST_AUTO_TEST_CASE(testHasherType)
{
    std::string a = "str";
    std::string_view view = a;
    bcos::h256 h(100);

    auto hash = openssl::OpenSSL_SHA3_256_Hasher{}.update(a).update(view).update(h).final();

    BOOST_CHECK_NE(hash, bcos::h256());

    auto hash2 = openssl::OpenSSL_SHA3_256_Hasher{}
                     .update(a)
                     .update(view)
                     .update(std::span((const byte*)h.data(), h.size))
                     .final();

    BOOST_CHECK_EQUAL(hash, hash2);
}

BOOST_AUTO_TEST_SUITE_END()
}  // namespace test
}  // namespace bcos
