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
 * @file SM2KeyPair.h
 * @date 2021.03.10
 * @author yujiechen
 */
#pragma once
#include <bcos-framework/interfaces/crypto/Signature.h>

namespace bcos
{
namespace crypto
{
Public sm2PriToPub(Secret const& _secret);
class SM2KeyPair : public KeyPair
{
public:
    SM2KeyPair() = default;
    explicit SM2KeyPair(Secret const& _secretKey) : KeyPair()
    {
        m_secretKey = _secretKey;
        m_publicKey = priToPub(_secretKey);
    }
    SM2KeyPair(Secret const& _secretKey, Public const& _publicKey) : KeyPair(_secretKey, _publicKey)
    {}
    explicit SM2KeyPair(KeyPair const& _keyPair) : KeyPair(_keyPair) {}
    ~SM2KeyPair() override {}
    Public priToPub(Secret const& _secretKey) override { return sm2PriToPub(_secretKey); }
};
}  // namespace crypto
}  // namespace bcos