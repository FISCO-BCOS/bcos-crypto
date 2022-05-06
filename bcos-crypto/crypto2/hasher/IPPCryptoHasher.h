#pragma once

#include "Hasher.h"
#include "ippcp.h"

namespace bcos::crypto::ippcrypto
{

enum HasherType
{
    SM3_256,
    SHA3_256,
    SHA2_256,
    Keccak256,
};

template <HasherType hasherType>
class IPPCryptoHasher : public bcos::crypto::HasherBase<IPPCryptoHasher<hasherType>>
{
public:
    IPPCryptoHasher()
    {
        m_method = ippsHashMethod_SM3();
    }

    void impl_update(std::span<std::byte const> in) {}

    void impl_final(std::span<std::byte> out) {}

    constexpr static size_t impl_hashSize() noexcept { return HASH_SIZE; }

private:
    constexpr static size_t HASH_SIZE = 32;

    const IppsHashMethod* m_method;
};
}  // namespace bcos::crypto::ippcrypto