#pragma one

#include <../interfaces/crypto/Hashing.h>
#include <openssl/evp.h>

namespace bcos::crypto::openssl
{

enum EVP_TYPE
{
    SM3_256,
    SHA3_256,
    SHA2_256,
};

template <EVP_TYPE evpType>
class EVPHashing : public Hashing<EVPHashing<evpType>>
{
public:
    EVPHashing()
    {
        m_md = getMD();
        m_mdCtx = EVP_MD_CTX_new();
        EVP_DigestInit(m_mdCtx, m_md);
    }

    ~EVPHashing() { EVP_MD_CTX_free(m_mdCtx); }

    constexpr const EVP_MD* getMD()
    {
        switch (evpType)
        {
        case SM3_256:
            return EVP_sm3();
        case SHA3_256:
            return EVP_sha3_256();
        case SHA2_256:
            return EVP_sha256();
        default:
            break;
        }
    }

    void impl_update(gsl::span<byte const> view)
    {
        EVP_DigestUpdate(m_mdCtx, view.data(), view.size());
    }

    bcos::h256 impl_final()
    {
        bcos::h256 hash;

        unsigned int length;
        EVP_DigestFinal(m_mdCtx, hash.data(), &length);
        EVP_DigestInit(m_mdCtx, m_md);

        return hash;
    }

private:
    const EVP_MD* m_md;
    EVP_MD_CTX* m_mdCtx;
};

using SHA3_256Hashing = EVPHashing<SHA3_256>;
using SHA2_256Hashing = EVPHashing<SHA2_256>;
using SM3_256Hashing = EVPHashing<SM3_256>;

}  // namespace bcos::crypto::openssl
