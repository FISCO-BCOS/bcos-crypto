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
 * @brief openssl implementation for Hasher
 * @file OpenSSLHasher.h
 * @date 2022.05.30
 * @author ancelmo
 */

#pragma once

#include "bcos-crypto/interfaces/crypto/hasher/Hasher.h"
#include <openssl/evp.h>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/throw_exception.hpp>
#include <stdexcept>

namespace bcos::crypto
{
enum HasherType
{
    SM3_256,
    SHA3_256,
    SHA2_256,
    OPENSSL_Keccak256,
};

template <HasherType hasherType>
class OpenSSLHasher : public HasherBase<OpenSSLHasher<hasherType>>
{
public:
    OpenSSLHasher() : HasherBase<OpenSSLHasher<hasherType>>() {}

    OpenSSLHasher(const OpenSSLHasher&) = delete;
    OpenSSLHasher(OpenSSLHasher&&) = default;
    OpenSSLHasher& operator=(const OpenSSLHasher&) = delete;
    OpenSSLHasher& operator=(OpenSSLHasher&&) = default;
    ~OpenSSLHasher() override = default;

    void* impl_update(void* _mdCtx, bytesConstRef in)
    {
        // std::unique_ptr<EVP_MD_CTX, Deleter> mdCtx((EVP_MD_CTX*)_mdCtx);
        auto mdCtx = (EVP_MD_CTX*)_mdCtx;
        if (!EVP_DigestUpdate(mdCtx, in.data(), in.size()))
        {
            // free the mdCtx when update error
            if (mdCtx)
            {
                EVP_MD_CTX_free(mdCtx);
            }
            BOOST_THROW_EXCEPTION(std::runtime_error{"EVP_DigestUpdate error!"});
        }
        return _mdCtx;
    }

    void impl_final(void* _mdCtx, HashType& out)
    {
        std::unique_ptr<EVP_MD_CTX, Deleter> mdCtx((EVP_MD_CTX*)_mdCtx);
        // Note: EVP_DigestFinal will clean up EVP_MD_CTX with EVP_MD_CTX_reset after computing the
        // digest
        if (!EVP_DigestFinal(mdCtx.get(), reinterpret_cast<unsigned char*>(out.data()), nullptr))
        {
            BOOST_THROW_EXCEPTION(std::runtime_error{"EVP_DigestFinal error!"});
        }
    }

    void* init()
    {
        std::unique_ptr<EVP_MD_CTX, Deleter> mdCtx(EVP_MD_CTX_new());
        auto md = chooseMD();

        if (!EVP_DigestInit(mdCtx.get(), md))
        {
            BOOST_THROW_EXCEPTION(std::runtime_error{"EVP_DigestInit error!"});
        }

        // OPENSSL_Keccak256 need special padding
        if constexpr (hasherType == OPENSSL_Keccak256)
        {
            struct KECCAK1600_CTX
            {
                uint64_t A[5][5];
                size_t block_size;
                size_t md_size;
                size_t num;
                unsigned char buf[1600 / 8 - 32];
                unsigned char pad;
            };

            struct EVP_MD_CTX_Keccak256
            {
                const EVP_MD* digest;
                ENGINE* engine;
                unsigned long flags;

                KECCAK1600_CTX* md_data;
            };

            auto keccak256 = reinterpret_cast<EVP_MD_CTX_Keccak256*>(mdCtx.get());
            if (keccak256->md_data->pad != 0x06)  // The sha3 origin pad
            {
                BOOST_THROW_EXCEPTION(std::runtime_error{
                    "OpenSSL KECCAK1600_CTX layout error! Maybe untested openssl version"});
            }
            keccak256->md_data->pad = 0x01;
        }
        return mdCtx.release();
    }

private:
    constexpr const EVP_MD* chooseMD()
    {
        if constexpr (hasherType == SM3_256)
        {
            return EVP_sm3();
        }
        else if constexpr (hasherType == SHA3_256 || hasherType == OPENSSL_Keccak256)
        {
            return EVP_sha3_256();
        }
        else if constexpr (hasherType == SHA2_256)
        {
            return EVP_sha256();
        }
        else
        {
            static_assert(!sizeof(*this), "Unknown EVP Type!");
        }
    }

    struct Deleter
    {
        void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
    };
};

using OpenSSL_SHA3_256_Hasher = OpenSSLHasher<SHA3_256>;
using OpenSSL_SHA2_256_Hasher = OpenSSLHasher<SHA2_256>;
using OPENSSL_SM3_Hasher = OpenSSLHasher<SM3_256>;
using OPENSSL_Keccak256_Hasher = OpenSSLHasher<OPENSSL_Keccak256>;
}  // namespace bcos::crypto
