if(HUNTER_ENABLED)
    hunter_add_package(Boost COMPONENTS all)
    hunter_add_package(bcos-utilities)
    hunter_add_package(wedpr-crypto)

    find_package(wedpr-crypto CONFIG REQUIRED)
    find_package(bcos-utilities CONFIG REQUIRED)
else()
    include(ExternalProject)

    # install bcos-utilities
    set(BCOS_UTILITIES_INSTALL ${CMAKE_CURRENT_BINARY_DIR}/bcos-utilities-install)
    make_directory(${BCOS_UTILITIES_INSTALL}/include)
    
    ExternalProject_Add(bcos-utilities
        URL https://${URL_BASE}/FISCO-BCOS/bcos-utilities/archive/eaf6322d310f343663bb18b46e402ed328e2745b.tar.gz
        URL_HASH SHA1=409cdddc666eb6aea40ed8fb492c840b8614875b
        CMAKE_ARGS -DHUNTER_ENABLED=OFF -DCMAKE_INSTALL_PREFIX=${BCOS_UTILITIES_INSTALL}
    )

    add_library(bcos-utilities::bcos-utilities STATIC IMPORTED)
    target_include_directories(bcos-utilities::bcos-utilities INTERFACE ${BCOS_UTILITIES_INSTALL}/include)
    set_property(TARGET bcos-utilities::bcos-utilities PROPERTY
        IMPORTED_LOCATION ${BCOS_UTILITIES_INSTALL}/lib/libbcos-utilities.a)
    add_dependencies(bcos-utilities::bcos-utilities bcos-utilities)

    # install wedpr-crypto
    set(WEDPR_CRYPTO_INSTALL ${CMAKE_CURRENT_BINARY_DIR}/wedpr-crypto-install)
    make_directory(${WEDPR_CRYPTO_INSTALL}/include)

    ExternalProject_Add(wedpr-crypto
        URL https://${URL_BASE}/WeBankBlockchain/WeDPR-Lab-Crypto/archive/0e3ca8614808825da4f91acc51e1031a5184119e.tar.gz
        URL_HASH SHA1=dcbb69c96085ada1d107380b3771fd8e177ad207
        CONFIGURE_COMMAND ""
        BUILD_COMMAND cargo +nightly-2021-06-17 build --release --manifest-path ${CMAKE_CURRENT_BINARY_DIR}/wedpr-crypto-prefix/src/wedpr-crypto/Cargo.toml
        INSTALL_COMMAND cp -r ${CMAKE_CURRENT_BINARY_DIR}/wedpr-crypto-prefix/src/wedpr-crypto/third_party/include ${WEDPR_CRYPTO_INSTALL}/include/wedpr-crypto
    )

    add_library(wedpr-crypto::crypto STATIC IMPORTED)
    target_include_directories(wedpr-crypto::crypto INTERFACE ${WEDPR_CRYPTO_INSTALL}/include/)
    set_property(TARGET wedpr-crypto::crypto PROPERTY
        IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/wedpr-crypto-prefix/src/wedpr-crypto/target/release/libffi_c_crypto_binary.a)
    add_dependencies(wedpr-crypto::crypto wedpr-crypto)
endif()