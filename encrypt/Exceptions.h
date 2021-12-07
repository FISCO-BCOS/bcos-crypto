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
 * @brief define the exceptions for encryption/decryption algorithm of bcos-crypto
 * @file Execptions.h
 * @date 2021.04.05
 * @author yujiechen
 */
#pragma once
#include <bcos-framework/libutilities/Exceptions.h>

namespace bcos
{
namespace crypto
{
DERIVE_BCOS_EXCEPTION(EncryptException);
DERIVE_BCOS_EXCEPTION(DecryptException);
}  // namespace crypto
}  // namespace bcos