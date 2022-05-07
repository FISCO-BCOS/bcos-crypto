#include <bcos-crypto/crypto2/hasher/IPPCryptoHasher.h>
#include <bcos-crypto/crypto2/hasher/OpenSSLHasher.h>
#include <boost/core/ignore_unused.hpp>
#include <array>
#include <iostream>
#include <vector>

using namespace bcos;
using namespace bcos::crypto;

auto hashingPerf(bcos::crypto::Hasher auto& hasher, std::string_view input, size_t count)
{
    std::vector<std::array<std::byte, 32>> results;
    results.reserve(count);
    for (size_t i = 0; i < count; i++)
    {
        hasher.update(input);

        results.emplace_back(hasher.final());
    }

    return results;
}

void startTest(std::string_view inputData, size_t count)
{
    openssl::OPENSSL_SM3_Hasher hasherSM3;
    auto opensslResult = hashingPerf(hasherSM3, inputData, count);

    ippcrypto::IPPCrypto_SM3_256_Hasher ippHasherSM3;
    auto ippResult = hashingPerf(ippHasherSM3, inputData, count);

    for (size_t i = 0; i < opensslResult.size(); ++i)
    {
        if (opensslResult[i] != ippResult[i])
        {
            std::cout << "Mismatch!" << std::endl;
        }
    }
}

int main(int argc, char* argv[])
{
    boost::ignore_unused(argc, argv);
    return 0;
}