#pragma once

#include "../interfaces/crypto/Hasher.h"
#include <openssl/evp.h>
#include <boost/throw_exception.hpp>

namespace bcos::crypto::openssl
{

struct Exception : public std::exception, public boost::exception
{
};

enum EVP_TYPE
{
    SM3_256,
    SHA3_256,
    SHA2_256,
    Keccak256,
};

template <EVP_TYPE evpType>
class OpenSSLHasher : public HasherBase<OpenSSLHasher<evpType>>
{
public:
    constexpr OpenSSLHasher()
      : HasherBase<OpenSSLHasher<evpType>>(),
        m_mdCtx(EVP_MD_CTX_new(), &EVP_MD_CTX_free),
        m_init(false)
    {}

    OpenSSLHasher(const OpenSSLHasher&) = delete;
    OpenSSLHasher(OpenSSLHasher&&) = default;
    OpenSSLHasher& operator=(const OpenSSLHasher&) = delete;
    OpenSSLHasher& operator=(OpenSSLHasher&&) = default;
    ~OpenSSLHasher() = default;

    void impl_update(std::span<std::byte const> view)
    {
        if (!m_init)
        {
            init();
            m_init = true;
        }
        EVP_DigestUpdate(m_mdCtx.get(), view.data(), view.size());
    }

    void impl_final(std::span<std::byte> view)
    {
        if (view.size() < HASH_SIZE)
        {
            BOOST_THROW_EXCEPTION(Exception{});
        }
        EVP_DigestFinal(m_mdCtx.get(), reinterpret_cast<unsigned char*>(view.data()), nullptr);
        m_init = false;
    }

    constexpr static size_t impl_hashSize() { return HASH_SIZE; }


private:
    void init()
    {
        auto md = chooseMD();
        EVP_DigestInit(m_mdCtx.get(), md);

        // Keccak256 need special padding
        if constexpr (evpType == Keccak256)
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

            auto keccak256 = reinterpret_cast<EVP_MD_CTX_Keccak256*>(m_mdCtx.get());
            if (keccak256->md_data->pad != 0x06)  // The sha3 origin pad
            {
                BOOST_THROW_EXCEPTION(Exception{});
            }
            keccak256->md_data->pad = 0x01;
        }
    }

    const EVP_MD* chooseMD()
    {
        switch (evpType)
        {
        case SM3_256:
            return EVP_sm3();
        case SHA3_256:
            return EVP_sha3_256();
        case SHA2_256:
            return EVP_sha256();
        case Keccak256:
            return EVP_sha3_256();
        default:
            return nullptr;
        }
    }

    std::unique_ptr<EVP_MD_CTX, std::function<void(EVP_MD_CTX*)>> m_mdCtx;
    bool m_init;

    constexpr static size_t HASH_SIZE = 32;
};

using OpenSSL_SHA3_256_Hasher = OpenSSLHasher<SHA3_256>;
using OpenSSL_SHA2_256_Hasher = OpenSSLHasher<SHA2_256>;
using OPENSSL_SM3_Hasher = OpenSSLHasher<SM3_256>;
using OPENSSL_Keccak256_Hasher = OpenSSLHasher<Keccak256>;

static_assert(Hasher<OpenSSL_SHA3_256_Hasher>, "Assert OpenSSLHasher type");
static_assert(Hasher<OpenSSL_SHA2_256_Hasher>, "Assert OpenSSLHasher type");
static_assert(Hasher<OPENSSL_SM3_Hasher>, "Assert OpenSSLHasher type");
static_assert(Hasher<OPENSSL_Keccak256_Hasher>, "Assert OpenSSLHasher type");

}  // namespace bcos::crypto::openssl
