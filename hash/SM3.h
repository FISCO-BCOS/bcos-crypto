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
 * @brief Hash algorithm of sm3
 * @file SM3.h
 * @date 2021.03.04
 * @author yujiechen
 */
#pragma once
#include <WeDPRCrypto.h>
#include <bcos-framework/interfaces/crypto/Hash.h>

namespace bcos
{
namespace crypto
{
h256 inline sm3Hash(bytesConstRef _data)
{
    h256 hashData;
    HashResult hashResult{(char*)hashData.data(), h256::size};
    wedpr_sm3_hash_binary(&hashResult, (const char*)_data.data(), _data.size());
    // Note: Due to the return value optimize of the C++ compiler, there will be no additional copy
    // overhead
    return hashData;
}
class SM3 : public Hash
{
public:
    using Ptr = std::shared_ptr<SM3>;
    SM3() {}
    virtual ~SM3() {}
    h256 hash(bytesConstRef _data) override { return sm3Hash(_data); }
};
}  // namespace crypto
}  // namespace bcos
