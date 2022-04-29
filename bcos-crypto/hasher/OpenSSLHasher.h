#pragma once

#include "../interfaces/crypto/Hasher.h"
#include <openssl/evp.h>

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
      : HasherBase<OpenSSLHasher<evpType>>(), m_mdCtx(EVP_MD_CTX_new(), &EVP_MD_CTX_free)
    {
        switch (evpType)
        {
        case SM3_256:
            m_md = EVP_sm3();
            break;
        case SHA3_256:
            m_md = EVP_sha3_256();
            break;
        case SHA2_256:
            m_md = EVP_sha256();
            break;
        case Keccak256:
            m_md = EVP_sha3_256();
            break;
        default:
            break;
        }

        EVP_DigestInit(m_mdCtx.get(), m_md);

        if constexpr (evpType == Keccak256)
        {
            // change the pad of sha3_256
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
            keccak256->md_data->pad = 0x01;
        }
    }
    OpenSSLHasher(const OpenSSLHasher&) = delete;
    OpenSSLHasher(OpenSSLHasher&&) = default;
    OpenSSLHasher& operator=(const OpenSSLHasher&) = delete;
    OpenSSLHasher& operator=(OpenSSLHasher&&) = default;
    ~OpenSSLHasher() = default;

    void impl_update(std::span<byte const> view)
    {
        EVP_DigestUpdate(m_mdCtx.get(), view.data(), view.size());
    }

    void impl_final(std::span<byte> view)
    {
        if (view.size() < HASH_SIZE)
        {
            BOOST_THROW_EXCEPTION(Exception{});
        }
        EVP_DigestFinal(m_mdCtx.get(), view.data(), nullptr);
        EVP_DigestInit(m_mdCtx.get(), m_md);
    }

    constexpr static size_t impl_hashSize() { return HASH_SIZE; }

private:
    std::unique_ptr<EVP_MD_CTX, std::function<void(EVP_MD_CTX*)>> m_mdCtx;
    const EVP_MD* m_md;

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
