find_package(OpenSSL)
find_package(IPPCrypto REQUIRED MODULE)
find_package(OpenMP 4.5 REQUIRED)

if (NOT IPPCRYPTO_FOUND)
    message(FATAL_ERROR "No Intel IPP Cryptography library found on the system. To build bcos-crypto, please specify -DIPPCRYPTO_ROOT_DIR=<path> option, where <path> is the path to directory that contains include/ and lib/ folders of Intel IPP Cryptography product.")
endif()

add_executable(perf_demo perf_demo.cpp ${HEADERS})
add_executable(hasher_test hasher_test.cpp ${HEADERS})
target_include_directories(perf_demo PUBLIC ${IPPCRYPTO_INCLUDE_DIRS})
target_include_directories(hasher_test PUBLIC ${IPPCRYPTO_INCLUDE_DIRS})
target_link_libraries(perf_demo PUBLIC ${BCOS_CRYPTO_TARGET} OpenSSL::Crypto ${IPPCRYPTO_LIBRARIES})
target_link_libraries(hasher_test PUBLIC ${BCOS_CRYPTO_TARGET} OpenSSL::Crypto ${IPPCRYPTO_LIBRARIES} OpenMP::OpenMP_CXX)