install(
    DIRECTORY "hash/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/bcos-crypto/hash"
    FILES_MATCHING PATTERN "*.h"
)
install(
    DIRECTORY "signature/secp256k1"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/bcos-crypto/signature/secp256k1"
    FILES_MATCHING PATTERN "*.h"
)
