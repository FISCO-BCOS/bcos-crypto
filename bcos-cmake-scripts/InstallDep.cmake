if(HUNTER_ENABLED)
    hunter_add_package(Boost COMPONENTS all)
    hunter_add_package(bcos-utilities)
    hunter_add_package(wedpr-crypto)

    find_package(wedpr-crypto CONFIG REQUIRED)
    find_package(bcos-utilities CONFIG REQUIRED)
    find_package(Boost CONFIG REQUIRED COMPONENTS log thread chrono unit_test_framework)
else()
    include(ExternalProject)
    include(GNUInstallDirs)
    find_package(Boost REQUIRED COMPONENTS log thread chrono unit_test_framework)

    if(AUTO_INSTALL_DEPENDENCY)
        # install bcos-utilities
        set(BCOS_UTILITIES_INSTALL ${CMAKE_CURRENT_BINARY_DIR}/bcos-utilities-install)
        make_directory(${BCOS_UTILITIES_INSTALL}/include)

        ExternalProject_Add(bcos-utilities
            URL https://${URL_BASE}/FISCO-BCOS/bcos-utilities/archive/0503f34db0cf6ea748debf1faa42f887647bce9b.tar.gz
            URL_HASH SHA1=06d9102ff4e050e70254a51310e96f32b84c91be
            CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} -DHUNTER_ENABLED=OFF -DCMAKE_INSTALL_PREFIX=${BCOS_UTILITIES_INSTALL} -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        )

        add_library(bcos-utilities::bcos-utilities MODULE IMPORTED)
        target_include_directories(bcos-utilities::bcos-utilities INTERFACE ${BCOS_UTILITIES_INSTALL}/include)
        set_property(TARGET bcos-utilities::bcos-utilities PROPERTY
            IMPORTED_LOCATION ${BCOS_UTILITIES_INSTALL}/${CMAKE_INSTALL_LIBDIR}/libbcos-utilities.a)
        add_dependencies(bcos-utilities::bcos-utilities bcos-utilities)

        # install wedpr-crypto
        set(WEDPR_CRYPTO_INSTALL ${CMAKE_CURRENT_BINARY_DIR}/wedpr-crypto-install)
        make_directory(${WEDPR_CRYPTO_INSTALL}/include)

        ExternalProject_Add(wedpr-crypto
            URL https://${URL_BASE}/WeBankBlockchain/WeDPR-Lab-Crypto/archive/0e3ca8614808825da4f91acc51e1031a5184119e.tar.gz
            URL_HASH SHA1=dcbb69c96085ada1d107380b3771fd8e177ad207
            CONFIGURE_COMMAND ""
            BUILD_COMMAND cargo +nightly-2021-06-17 build --release --features "wedpr_f_hash_keccak256 wedpr_f_signature_secp256k1 wedpr_f_signature_sm2 wedpr_f_hash_sm3 wedpr_f_vrf_curve25519 wedpr_f_crypto_block_cipher_aes wedpr_f_crypto_block_cipher_sm4 wedpr_f_hash_ripemd160 wedpr_f_hash_sha2 wedpr_f_hash_sha3 wedpr_f_hash_blake2b wedpr_f_signature_ed25519" --no-default-features --manifest-path ${CMAKE_CURRENT_BINARY_DIR}/wedpr-crypto-prefix/src/wedpr-crypto/ffi/ffi_c/ffi_c_crypto_binary/Cargo.toml
            INSTALL_COMMAND cp -r ${CMAKE_CURRENT_BINARY_DIR}/wedpr-crypto-prefix/src/wedpr-crypto/third_party/include ${WEDPR_CRYPTO_INSTALL}/include/wedpr-crypto
        )

        add_library(wedpr-crypto::crypto STATIC IMPORTED)
        target_include_directories(wedpr-crypto::crypto INTERFACE ${WEDPR_CRYPTO_INSTALL}/include/)
        set_property(TARGET wedpr-crypto::crypto PROPERTY
            IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/wedpr-crypto-prefix/src/wedpr-crypto/target/release/libffi_c_crypto_binary.a)
        add_dependencies(wedpr-crypto::crypto wedpr-crypto)
    endif()
endif()