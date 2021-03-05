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
 * @brief Hash algorithm of keccak256
 * @file Keccak256.cpp
 */
#include "Keccak256.h"
#include "WeDPRCrypto.h"

using namespace bcos;
using namespace bcos::crypto;
h256 Keccak256::hash(bytesConstRef _data)
{
    char* hexData = (char*)(toHexString(_data)->c_str());
    char* result = wedpr_keccak256_hash(hexData);
    // TODO: wedpr crypto supports direct hash calculation on binary
    auto hashResult = h256(result, h256::StringDataType::FromHex);
    // release the allocated memory
    if (result)
    {
        delete result;
    }
    return hashResult;
}
