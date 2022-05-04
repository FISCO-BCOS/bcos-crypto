#pragma once

#include "../interfaces/crypto/Hasher.h"

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
    void impl_update(std::span<std::byte const> in) {}

    void impl_final(std::span<std::byte> out) {}
};
}  // namespace bcos::crypto::ippcrypto