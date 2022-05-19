if(HUNTER_ENABLED)
    hunter_add_package(Boost COMPONENTS all)
    hunter_add_package(bcos-utilities)
    hunter_add_package(wedpr-crypto)

    find_package(wedpr-crypto CONFIG REQUIRED)
    find_package(bcos-utilities CONFIG REQUIRED)
else()
    include(ExternalProject)

    if(AUTO_INSTALL_DEPENDENCY)
        # install bcos-utilities
        set(BCOS_UTILITIES_INSTALL ${CMAKE_CURRENT_BINARY_DIR}/bcos-utilities-install)
        make_directory(${BCOS_UTILITIES_INSTALL}/include)

        ExternalProject_Add(bcos-utilities
            URL https://${URL_BASE}/FISCO-BCOS/bcos-utilities/archive/e3cc2f7176f495ceacbd5b3ee29c2de6f6c90b2e.tar.gz
            URL_HASH SHA1=793ff58a37d013f5efd4583f81eeff6345d5c4af
            CMAKE_ARGS -DHUNTER_ENABLED=OFF -DCMAKE_INSTALL_PREFIX=${BCOS_UTILITIES_INSTALL} -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                -DBOOST_INCLUDEDIR=${BOOST_INCLUDEDIR} -DBOOST_LIBRARYDIR=${BOOST_LIBRARYDIR}
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
endif()