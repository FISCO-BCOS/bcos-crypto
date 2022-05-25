# If found the following variables will be available:
#       BCOS_UTILITIES_FOUND
#       BCOS_UTILITIES_ROOT_DIR
#       BCOS_UTILITIES_INCLUDE_DIRS
#       BCOS_UTILITIES_LIBRARIES
#
# Target BCOSUtilities::BCOSUtilities
#

include(FindPackageHandleStandardArgs)
include(ExternalProject)
include(GNUInstallDirs)

add_library(BCOSUtilities::BCOSUtilities MODULE IMPORTED)
# Check found directory
if(NOT BCOS_UTILITIES_ROOT_DIR)
  message(STATUS "Installing bcos-utilities from github")
  set(BCOS_UTILITIES_INSTALL ${CMAKE_CURRENT_BINARY_DIR}/bcos-utilities-install)
  make_directory(${BCOS_UTILITIES_INSTALL}/include)

  ExternalProject_Add(bcos-utilities
    URL https://${URL_BASE}/FISCO-BCOS/bcos-utilities/archive/4d3d5889e0b6aa22d4a376a384d0978042549254.tar.gz
    URL_HASH SHA1=aee2b9ffdc03bc56ffc1e055eea76816079b71a2
    CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} -DHUNTER_ENABLED=OFF -DCMAKE_INSTALL_PREFIX=${BCOS_UTILITIES_INSTALL} -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
  )

  set(BCOS_UTILITIES_INCLUDE_DIRS "${BCOS_UTILITIES_INSTALL}/include")
  set(BCOS_UTILITIES_LIBRARIES "${BCOS_UTILITIES_INSTALL}/${CMAKE_INSTALL_LIBDIR}/${CMAKE_STATIC_LIBRARY_PREFIX}bcos-utilities${CMAKE_STATIC_LIBRARY_SUFFIX}")
  
  add_dependencies(BCOSUtilities::BCOSUtilities bcos-utilities)
else()
  message(STATUS "Find bcos-utilties in ${BCOS_UTILITIES_ROOT_DIR}")
  find_path(BCOS_UTILITIES_INCLUDE_DIRS NAMES bcos-utilities PATHS ${BCOS_UTILITIES_ROOT_DIR}/include/ REQUIRED)
  find_library(BCOS_UTILITIES_LIBRARIES NAMES ${CMAKE_STATIC_LIBRARY_PREFIX}bcos-utilities${CMAKE_STATIC_LIBRARY_SUFFIX}
    PATHS ${BCOS_UTILITIES_ROOT_DIR}/${CMAKE_INSTALL_LIBDIR} REQUIRED)

  message(STATUS "Found bcos-utilities include dir: ${BCOS_UTILITIES_INCLUDE_DIRS} lib: ${BCOS_UTILITIES_LIBRARIES}")
endif()

find_package(Boost REQUIRED COMPONENTS log)
target_include_directories(BCOSUtilities::BCOSUtilities INTERFACE ${BCOS_UTILITIES_INCLUDE_DIRS})
set_property(TARGET BCOSUtilities::BCOSUtilities PROPERTY IMPORTED_LOCATION ${BCOS_UTILITIES_LIBRARIES})
target_link_libraries(BCOSUtilities::BCOSUtilities INTERFACE Boost::log)

set(BCOS_UTILITIES_FOUND ON)