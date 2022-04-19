file(GLOB SRC_LIST "*.cpp")
file(GLOB HEADERS "*.h")

find_package(OpenSSL)

add_executable(perf_demo  ${SRC_LIST} ${HEADERS})
target_link_libraries(perf_demo PUBLIC ${BCOS_CRYPTO_TARGET} OpenSSL::Crypto)