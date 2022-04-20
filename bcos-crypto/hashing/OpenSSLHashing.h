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
    EVPHashing() : Hashing<EVPHashing<evpType>>(), m_mdCtx(EVP_MD_CTX_new(), &EVP_MD_CTX_free)
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
    EVPHashing(const EVPHashing&) = delete;
    EVPHashing(EVPHashing&&) = default;
    EVPHashing& operator=(const EVPHashing&) = delete;
    EVPHashing& operator=(EVPHashing&&) = default;
    ~EVPHashing() = default;

    void impl_update(gsl::span<byte const> view)
    {
        EVP_DigestUpdate(m_mdCtx.get(), view.data(), view.size());
    }

    bcos::h256 impl_final()
    {
        bcos::h256 hash;

        unsigned int length = hash.size;
        EVP_DigestFinal(m_mdCtx.get(), hash.data(), &length);
        EVP_DigestInit(m_mdCtx.get(), m_md);

        return hash;
    }

private:
    std::unique_ptr<EVP_MD_CTX, std::function<void(EVP_MD_CTX*)>> m_mdCtx;
    const EVP_MD* m_md;
};

using SHA3_256Hashing = EVPHashing<SHA3_256>;
using SHA2_256Hashing = EVPHashing<SHA2_256>;
using SM3_256Hashing = EVPHashing<SM3_256>;

}  // namespace bcos::crypto::openssl
