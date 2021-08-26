hunter_config(bcos-framework
VERSION 3.0.0-local
URL "https://${URL_BASE}/FISCO-BCOS/bcos-framework/archive/946fb10bc67119c9646c22d515cafb2e1390e5f9.tar.gz"
SHA1 550b02ccc4e35497e5eaa8cbf5ac66a2d53d6031
)

hunter_config(wedpr-crypto VERSION 1.1.0-10f314de
	URL https://${URL_BASE}/WeBankBlockchain/WeDPR-Lab-Crypto/archive/10f314de45ec31ce9e330922b522ce173662ed33.tar.gz
	SHA1 626df59f87ea2c6bb5128f7d104588179809910b
	CMAKE_ARGS HUNTER_PACKAGE_LOG_BUILD=OFF HUNTER_PACKAGE_LOG_INSTALL=ON
)
