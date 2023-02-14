include(ExternalProject)
include(GNUInstallDirs)

if (WIN32)
    set(SDF_LIB_NAME "sdf-crypto.lib")
else()
    set(SDF_LIB_NAME "libsdf-crypto.a")
endif (WIN32)

ExternalProject_Add(libsdf
    PREFIX ${CMAKE_SOURCE_DIR}/deps
    GIT_REPOSITORY https://${URL_BASE}/WeBankBlockchain/hsm-crypto.git
    GIT_TAG        654f2253e890dc6c868ba759201cfad4c7cf928d
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
    BUILD_IN_SOURCE true
    LOG_CONFIGURE 0
    LOG_BUILD 0
    LOG_INSTALL 0
)

ExternalProject_Get_Property(libsdf INSTALL_DIR)

set(HSM_INCLUDE_DIR ${INSTALL_DIR}/include/)
file(MAKE_DIRECTORY ${HSM_INCLUDE_DIR})  # Must exist.

set(SDF_LIB "${INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/${SDF_LIB_NAME}")

add_library(SDF STATIC IMPORTED GLOBAL)
set_property(TARGET SDF PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${HSM_INCLUDE_DIR})
set_property(TARGET SDF PROPERTY IMPORTED_LOCATION ${SDF_LIB})
add_dependencies(SDF libsdf)
unset(INSTALL_DIR)