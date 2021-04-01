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
 * @brief codec for signature data with pub
 * @file SignatureDataWithPub.h
 * @date 2021.03.10
 * @author yujiechen
 */
#pragma once
#include <bcos-framework/interfaces/crypto/Signature.h>
namespace bcos
{
namespace crypto
{
class SignatureDataWithPub : public SignatureData
{
public:
    using Ptr = std::shared_ptr<SignatureDataWithPub>;
    explicit SignatureDataWithPub(bytesConstRef _data, int _signatureLen)
    {
        m_signatureLen = _signatureLen + Public::size;
        m_signatureLenWithoutPub = _signatureLen;
        decode(_data);
    }

    SignatureDataWithPub(h256 const& _r, h256 const& _s, Public const& _pub, int _signatureLen)
      : SignatureData(_r, _s), m_pub(_pub)
    {
        m_signatureLen = _signatureLen + Public::size;
        m_signatureLenWithoutPub = _signatureLen;
    }
    ~SignatureDataWithPub() override {}

    Public const& pub() { return m_pub; }

    void encode(bytesPointer _signatureData) const override
    {
        encodeCommonFields(_signatureData);
        memcpy(_signatureData->data() + m_signatureLenWithoutPub, m_pub.data(), Public::size);
    }

    void decode(bytesConstRef _signatureData) override
    {
        decodeCommonFields(_signatureData);
        m_pub = Public(
            _signatureData.data() + m_signatureLenWithoutPub, Public::ConstructorType::FromPointer);
    }

private:
    Public m_pub;
    int m_signatureLenWithoutPub;
};
}  // namespace crypto
}  // namespace bcos
