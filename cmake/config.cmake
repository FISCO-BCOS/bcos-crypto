hunter_config(bcos-utilities VERSION 3.0.0-rc2-local
    URL https://${URL_BASE}/FISCO-BCOS/bcos-utilities/archive/71e57c0172cdda81f4fed6871ab56d9d5dc75fb9.tar.gz
    SHA1 2de5293ae44c7234a7ccd51ba16c8ea223f0ecb8
    CMAKE_ARGS HUNTER_PACKAGE_LOG_BUILD=ON HUNTER_PACKAGE_LOG_INSTALL=ON
)

hunter_config(
    Boost VERSION "1.79.0"
    URL
    "https://osp-1257653870.cos.ap-guangzhou.myqcloud.com/FISCO-BCOS/FISCO-BCOS/deps/boost_1_79_0.tar.bz2
    https://downloads.sourceforge.net/project/boost/boost/1.79.0/source/boost_1_79_0.tar.bz2
    https://nchc.dl.sourceforge.net/project/boost/boost/1.79.0/boost_1_79_0.tar.bz2"
    SHA1
    31209dcff292bd6a64e5e08ceb3ce44a33615dc0
    CMAKE_ARGS
    CONFIG_MACRO=BOOST_UUID_RANDOM_PROVIDER_FORCE_POSIX
)

hunter_config(OpenSSL VERSION tassl_1.1.1b_v1.4-local
    URL https://${URL_BASE}/FISCO-BCOS/TASSL-1.1.1b/archive/f9d60fa510e5fbe24413b4abdf1ea3a48f9ee6aa.tar.gz
    SHA1 e56121278bf07587d58d154b4615f96575957d6f
)

hunter_config(wedpr-crypto VERSION 1.0.0
    URL https://${URL_BASE}/WeBankBlockchain/WeDPR-Lab-Crypto/archive/caeea48d7fa6c879fef52063cf107873744629b2.tar.gz
    SHA1 03e76f0759a0da0f55cad5d49af510657bb6f343
)

hunter_config(range-v3 VERSION 1.0.0
    URL https://${URL_BASE}/ericniebler/range-v3/archive/a81477931a8aa2ad025c6bda0609f38e09e4d7ec.tar.gz
    SHA1 2d84b639bfd42bb1cbe2fd88f85ff0d1cca25952
)
