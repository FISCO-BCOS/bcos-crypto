aux_source_directory(./hash SRC_LIST)
include_directories(./hash)
aux_source_directory(./signature/ SRC_LIST)
include_directories(./signature)
aux_source_directory(./signature/secp256k1 SRC_LIST)
include_directories(./signature/secp256k1)
aux_source_directory(./signature/sm2 SRC_LIST)
include_directories(./signature/sm2)
aux_source_directory(./signature/ed25519 SRC_LIST)
include_directories(./signature/ed25519)
aux_source_directory(./encrypt SRC_LIST)
include_directories(./encrypt)
