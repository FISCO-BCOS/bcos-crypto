#pragma one

#include <../interfaces/crypto/Hashing.h>
#include <openssl/evp.h>

namespace bcos::crypto
{
class SHA3Hashing : public Hashing<SHA3Hashing>
{
public:
    SHA3Hashing()
    {
        m_md = EVP_sha3_256();
        m_mdCtx = EVP_MD_CTX_new();
        EVP_DigestInit(m_mdCtx, m_md);
    }

    ~SHA3Hashing() { EVP_MD_CTX_free(m_mdCtx); }

    void impl_update(gsl::span<byte const> view)
    {
        EVP_DigestUpdate(m_mdCtx, view.data(), view.size());
    }

    bcos::h256 impl_final()
    {
        bcos::h256 hash;

        unsigned int length;
        EVP_DigestFinal(m_mdCtx, hash.data(), &length);
        if (length != hash.size)
        {
            // Length error
        }
        EVP_DigestInit(m_mdCtx, m_md);

        return hash;
    }

private:
    const EVP_MD* m_md;
    EVP_MD_CTX* m_mdCtx;
};
}  // namespace bcos::crypto
