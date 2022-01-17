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
 * @file sm2.cpp
 * @date 2022.01.17
 * @author yujiechen
 */
#include "sm2.h"
#include "signature/sm2/SM2Crypto.h"

#if SM2_OPTIMIZE
#include "signature/fastsm2/FastSM2Crypto.h"
bcos::crypto::FastSM2Crypto c_sm2Crypto;
#else
bcos::crypto::SM2Crypto c_sm2Crypto;
#endif

using namespace bcos;
using namespace bcos::crypto;


std::shared_ptr<bytes> bcos::crypto::sm2Sign(
    KeyPairInterface::Ptr _keyPair, const HashType& _hash, bool _signatureWithPub)
{
    return c_sm2Crypto.sign(_keyPair, _hash, _signatureWithPub);
}

KeyPairInterface::Ptr bcos::crypto::sm2GenerateKeyPair()
{
    return c_sm2Crypto.generateKeyPair();
}

bool bcos::crypto::sm2Verify(PublicPtr _pubKey, const HashType& _hash, bytesConstRef _signatureData)
{
    return c_sm2Crypto.verify(_pubKey, _hash, _signatureData);
}

PublicPtr bcos::crypto::sm2Recover(const HashType& _hash, bytesConstRef _signData)
{
    return c_sm2Crypto.recover(_hash, _signData);
}

std::pair<bool, bytes> bcos::crypto::sm2Recover(Hash::Ptr _hashImpl, bytesConstRef _input)
{
    return c_sm2Crypto.recoverAddress(_hashImpl, _input);
}