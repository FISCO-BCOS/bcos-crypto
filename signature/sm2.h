/**
 *  Copyright (C) 2022 FISCO BCOS.
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
 * @brief implementation for ed25519 keyPair algorithm
 * @file sm2.h
 * @date 2022.01.17
 * @author yujiechen
 */
#pragma once
#include <bcos-utilities/Common.h>
#include <interfaces/crypto/CommonType.h>
#include <interfaces/crypto/KeyInterface.h>
#include <interfaces/crypto/KeyPairInterface.h>
namespace bcos
{
namespace crypto
{
std::shared_ptr<bytes> sm2Sign(
    KeyPairInterface::Ptr _keyPair, const HashType& _hash, bool _signatureWithPub = false);
bool sm2Verify(PublicPtr _pubKey, const HashType& _hash, bytesConstRef _signatureData);
KeyPairInterface::Ptr sm2GenerateKeyPair();
PublicPtr sm2Recover(const HashType& _hash, bytesConstRef _signData);

std::pair<bool, bytes> sm2Recover(Hash::Ptr _hashImpl, bytesConstRef _in);
}  // namespace crypto
}  // namespace bcos