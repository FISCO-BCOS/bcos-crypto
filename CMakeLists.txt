#------------------------------------------------------------------------------
# Top-level CMake file for bcos-crypto
# ------------------------------------------------------------------------------
# Copyright (C) 2021 bcos-crypto
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.10)
set(CMAKE_OSX_DEPLOYMENT_TARGET "10.13" CACHE STRING "Minimum OS X deployment version")

if (NOT DEFINED URL_BASE)
    set(URL_BASE "github.com")
    # set(URL_BASE "github.com.cnpmjs.org")
endif()

set(BCOS_CMAKE_SCRIPTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/bcos-cmake-scripts)
set(BCOS_CRYPTO_CMAKE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmake" CACHE PATH "The cmake path for the library")
list(APPEND CMAKE_MODULE_PATH ${BCOS_CMAKE_SCRIPTS_DIR})
list(APPEND CMAKE_MODULE_PATH ${BCOS_CRYPTO_CMAKE_DIR})
#init hunter
include(HunterGate)
HunterGate(
    URL "https://${URL_BASE}/FISCO-BCOS/hunter/archive/155dfdb7b5888493eefb656b3abcc026edb98730.tar.gz"
    SHA1 "a797abf35de1904ec089a9f517d847637731d467"
    FILEPATH "${BCOS_CRYPTO_CMAKE_DIR}/config.cmake"
)

project(bcos-crypto VERSION "1.0.0")
set(VERSION_SUFFIX "-rc3")

# basic settings
include(Options)
configure_project()
include(CompilerSettings)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# install dependencies
include(InstallBcosUtilities)

hunter_add_package(wedpr-crypto)
find_package(wedpr-crypto CONFIG REQUIRED)

if (NOT MSVC)
    hunter_add_package(range-v3)
    find_package(range-v3 CONFIG REQUIRED)
endif()

# add source directory
include(Sources)
option(DEMO "compile demo or not" OFF)

set(BCOS_CRYPTO_TARGET bcos-crypto)
add_library(${BCOS_CRYPTO_TARGET} ${SRC_LIST} ${HEADERS})
target_link_libraries(${BCOS_CRYPTO_TARGET} PUBLIC ${DependLibraries})

if(DEMO)
add_subdirectory(demo)
endif()

if (TESTS)
    enable_testing()
    set(CTEST_OUTPUT_ON_FAILURE TRUE)
    add_subdirectory(test)
endif()

# hardware crypto SDF
include(ProjectSDF)

include(InstallConfig)
# install crypto target
install(
    TARGETS ${BCOS_CRYPTO_TARGET}
    EXPORT "${TARGETS_EXPORT_NAME}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)
# install the include files for hash
include(InstallInclude)

# for doxygen
include(BuildDocs)
buildDoc(bcos-crypto-doc)

# for code coverage
if (COVERAGE)
    include(Coverage)
    config_coverage("coverage" "'/usr*' '${CMAKE_CURRENT_SOURCE_DIR}/bcos-cmake-scripts*' '${CMAKE_CURRENT_SOURCE_DIR}/test/bcos-test*'")
endif ()
