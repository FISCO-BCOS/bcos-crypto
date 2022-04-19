#pragma once
#include <../interfaces/crypto/Hashing.h>
#include <openssl/sha.h>

namespace bcos::crypto
{
class SHA3Hashing : public Hashing<SHA3Hashing>
{
public:
    SHA3Hashing() { SHA256_Init(&m_context); }

    void impl_update(gsl::span<byte const> view) { SHA256_Update(&m_context, view.data(), view.size()); }

    bcos::h256 impl_final()
    {
        bcos::h256 hash;
        SHA256_Final(hash.data(), &m_context);

        return hash;
    }

private:
    SHA256_CTX m_context;
};
}  // namespace bcos::crypto
