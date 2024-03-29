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
 * @brief interfaces for KeyPair
 * @file KeyPairInterface.h
 * @author: yujiechen
 * @date 2021-04-02
 */
#pragma once
#include <bcos-crypto/interfaces/crypto/Hash.h>
#include <bcos-crypto/interfaces/crypto/KeyInterface.h>
#include <memory>
namespace bcos
{
namespace crypto
{
enum class KeyPairType : int
{
    Secp256K1 = 0,
    SM2 = 1,
    Ed25519 = 2,
    HsmSM2 = 3
};
class KeyPairInterface
{
public:
    using Ptr = std::shared_ptr<KeyPairInterface>;
    using UniquePtr = std::unique_ptr<KeyPairInterface>;

    KeyPairInterface() = default;
    virtual ~KeyPairInterface() {}

    virtual SecretPtr secretKey() const = 0;
    virtual PublicPtr publicKey() const = 0;
    virtual Address address(Hash::Ptr _hashImpl) = 0;
    virtual KeyPairType keyPairType() const = 0;
};
}  // namespace crypto
}  // namespace bcos
