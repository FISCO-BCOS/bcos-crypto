install(
    DIRECTORY "hash/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/bcos-crypto/hash"
    FILES_MATCHING PATTERN "*.h"
)
