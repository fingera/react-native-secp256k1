cmake_minimum_required(VERSION 3.4)

set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_definitions(-DUSE_NUM_NONE=1)
add_definitions(-DUSE_FIELD_INV_BUILTIN=1)
add_definitions(-DUSE_SCALAR_INV_BUILTIN=1)
add_definitions(-DUSE_FIELD_10X26=1)
add_definitions(-DUSE_SCALAR_8X32=1)
add_definitions(-DENABLE_MODULE_ECDH=1)
add_definitions(-DENABLE_MODULE_RECOVERY=1)

include_directories(../external/secp256k1)
include_directories(../external/secp256k1/src)

add_library( secp256k1
             SHARED
             ../external/secp256k1/src/java/org_bitcoin_NativeSecp256k1.c
             ../external/secp256k1/src/java/org_bitcoin_Secp256k1Context.c
             ../external/secp256k1/src/secp256k1.c )

target_link_libraries( secp256k1 )
