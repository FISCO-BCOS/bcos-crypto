file(GLOB_RECURSE SRC_LIST bcos-crypto/*.cpp)
file(GLOB_RECURSE HSM_SRCS bcos-crypto/Hsm*.cpp)

set(DependLibraries bcos-utilities::bcos-utilities wedpr-crypto::crypto)

if (WIN32)
set(DependLibraries ${DependLibraries} Ws2_32 Wldap32 Crypt32 userenv)
else()
set(DependLibraries ${DependLibraries} pthread dl)
endif()

if (NOT WITH_HSM_SDF)
    list(REMOVE_ITEM SRC_LIST ${HSM_SRCS})
else ()
    list(APPEND DependLibraries SDF gmt0018)
endif ()

set(ExcludePattern "bcos-crypto/signature/fastsm2*")
hunter_add_package(OpenSSL)
find_package(OpenSSL REQUIRED)
set(DependLibraries OpenSSL::Crypto ${DependLibraries})
set(ExcludePattern "")