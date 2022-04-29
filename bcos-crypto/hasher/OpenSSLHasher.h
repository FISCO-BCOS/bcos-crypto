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
        default:
            break;
        }
        EVP_DigestInit(m_mdCtx.get(), m_md);
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
            BOOST_THROW_EXCEPTION(Error{});
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

static_assert(Hasher<OpenSSL_SHA3_256_Hasher>, "Assert OpenSSLHasher type");
static_assert(Hasher<OpenSSL_SHA2_256_Hasher>, "Assert OpenSSLHasher type");
static_assert(Hasher<OPENSSL_SM3_Hasher>, "Assert OpenSSLHasher type");

}  // namespace bcos::crypto::openssl
