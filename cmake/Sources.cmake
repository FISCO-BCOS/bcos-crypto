file(GLOB_RECURSE SRC_LIST bcos-crypto/*.cpp)
file(GLOB_RECURSE HSM_SRCS bcos-crypto/Hsm*.cpp)

set(DependLibraries bcos-utilities::bcos-utilities wedpr-crypto::crypto)

if (WIN32)
set(DependLibraries ${DependLibraries} Ws2_32 Wldap32 Crypt32 userenv)
else()
set(DependLibraries ${DependLibraries} pthread dl)
endif()

list(APPEND DependLibraries SDF)

set(ExcludePattern "bcos-crypto/signature/fastsm2*")
hunter_add_package(OpenSSL)
find_package(OpenSSL REQUIRED)
set(DependLibraries OpenSSL::Crypto ${DependLibraries})
set(ExcludePattern "")