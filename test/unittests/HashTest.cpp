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
 * @brief test cases for keccak256/sm3
 * @file HashTest.h
 * @date 2021.03.04
 */
#include <bcos-framework/interfaces/crypto/CryptoSuite.h>
#include <hash/Keccak256.h>
#include <hash/SM3.h>
#include <test/bcos-test/libutils/TestPromptFixture.h>
#include <boost/test/unit_test.hpp>
#include <string>

using namespace bcos;
using namespace crypto;
namespace bcos
{
namespace test
{
BOOST_FIXTURE_TEST_SUITE(HashTest, TestPromptFixture)
BOOST_AUTO_TEST_CASE(testKeccak256)
{
    auto keccak256 = std::make_shared<Keccak256>();
    auto cryptoSuite = std::make_shared<CryptoSuite>(keccak256, nullptr, nullptr);
    std::string ts = keccak256->emptyHash().hex();
    BOOST_CHECK_EQUAL(
        ts, std::string("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"));
    std::cout << "#### checkx passed" << std::endl;

    std::string hashData = "abcde";
    ts = keccak256->hash(hashData).hex();
    BOOST_CHECK_EQUAL(
        ts, std::string("6377c7e66081cb65e473c1b95db5195a27d04a7108b468890224bedbe1a8a6eb"));
    std::cout << "#### check1 passed" << std::endl;

    h256 emptyKeccak256(
        *fromHexString("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"));
    BOOST_REQUIRE_EQUAL(emptyKeccak256, keccak256->emptyHash());

    BOOST_REQUIRE_EQUAL(cryptoSuite->hash(""),
        h256("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"));
    BOOST_REQUIRE_EQUAL(cryptoSuite->hash("hello"),
        h256("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"));
    std::cout << "#### check2 passed" << std::endl;
}
BOOST_AUTO_TEST_CASE(testSM3)
{
    auto sm3 = std::make_shared<SM3>();
    auto cryptoSuite = std::make_shared<CryptoSuite>(sm3, nullptr, nullptr);
    std::string ts = sm3->emptyHash().hex();
    BOOST_CHECK_EQUAL(
        ts, std::string("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"));
    std::cout << "#### check4 passed" << std::endl;

    std::string hashData = "abcde";
    ts = sm3->hash(hashData).hex();
    BOOST_CHECK_EQUAL(
        ts, std::string("afe4ccac5ab7d52bcae36373676215368baf52d3905e1fecbe369cc120e97628"));
    std::cout << "#### check5 passed" << std::endl;

    h256 emptyKeccak256(
        *fromHexString("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"));
    BOOST_REQUIRE_EQUAL(emptyKeccak256, sm3->emptyHash());
    std::cout << "#### check6 passed" << std::endl;

    BOOST_REQUIRE_EQUAL(cryptoSuite->hash(""),
        h256("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"));
    std::cout << "#### check7 passed" << std::endl;

    BOOST_REQUIRE_EQUAL(cryptoSuite->hash("hello"),
        h256("becbbfaae6548b8bf0cfcad5a27183cd1be6093b1cceccc303d9c61d0a645268"));
    std::cout << "#### check8 passed" << std::endl;
}
BOOST_AUTO_TEST_SUITE_END()
}  // namespace test
}  // namespace bcos
