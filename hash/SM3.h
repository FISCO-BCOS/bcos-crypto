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
#include <bcos-framework/interfaces/libcrypto/Hash.h>

namespace bcos
{
namespace crypto
{
class SM3 : public Hash
{
public:
    using Ptr = std::shared_ptr<SM3>;
    SM3() {}
    virtual ~SM3() {}
    h256 hash(bytesConstRef _data) override
    {
        char* hexData = (char*)(toHexString(_data)->c_str());
        // TODO: wedpr crypto supports direct hash calculation on binary
        char* result = wedpr_sm3_hash(hexData);
        auto hashResult = h256(result, h256::StringDataType::FromHex);
        if (result)
        {
            delete result;
        }
        return hashResult;
    }

private:
};
}  // namespace crypto
}  // namespace bcos
