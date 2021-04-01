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
 * @brief implementation for SM2KeyPair
 * @file SM2KeyPair.cpp
 * @date 2021.03.10
 * @author yujiechen
 */
#include "SM2KeyPair.h"
#include <bcos-crypto/hash/SM3.h>
#include <bcos-crypto/signature/Exceptions.h>

using namespace bcos;
using namespace bcos::crypto;
Public bcos::crypto::sm2PriToPub(Secret const& _secretKey)
{
    CInputBuffer privateKey{(const char*)_secretKey.data(), Secret::size};
    Public pubKey;
    COutputBuffer publicKey{(char*)pubKey.data(), Public::size};
    auto retCode = wedpr_sm2_derive_public_key(&privateKey, &publicKey);
    if (retCode != 0)
    {
        BOOST_THROW_EXCEPTION(
            PriToPublicKeyException() << errinfo_comment("sm2PriToPub exception"));
    }
    return pubKey;
}