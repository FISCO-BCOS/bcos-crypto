#------------------------------------------------------------------------------
# Top-level CMake file for FISCO-BCOS.
# ------------------------------------------------------------------------------
# Copyright (C) 2021 FISCO BCOS.
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

set(BCOS_CMAKE_SCRIPTS "bcos-cmake-scripts")
set(BCOS_CMAKE_SCRIPTS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/${BCOS_CMAKE_SCRIPTS}" CACHE PATH "The path for the ${BCOS_CMAKE_SCRIPTS} submodule")
set(BCOS_CRYPTO_CMAKE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmake" CACHE PATH "The cmake path for the library")
list(APPEND CMAKE_MODULE_PATH ${BCOS_CMAKE_SCRIPTS_DIR})
list(APPEND CMAKE_MODULE_PATH ${BCOS_CRYPTO_CMAKE_DIR})
#init hunter
include(HunterGate)
HunterGate(
    URL "https://github.com/cyjseagull/hunter/archive/635d03816ec70dfe23ecf37e37bb59aca2d00221.tar.gz"
    SHA1 "02af7e34e3843680bfc9e861a01c7cd43eeb042f"
)
project(bcos-crypto VERSION "3.0.0")
set(VERSION_SUFFIX "")

# basic settings
include(Options)
configure_project()
include(CompilerSettings)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/..)
# install dependencies
include(InstallBcosFrameworkDependencies)
hunter_add_package(wedpr-crypto)
find_package(wedpr-crypto CONFIG REQUIRED)

# add source directory
include(Sources)

set(BCOS_CRYPTO_TARGET bcos-crypto)
add_library(${BCOS_CRYPTO_TARGET} ${SRC_LIST} ${HEADERS})
target_link_libraries(${BCOS_CRYPTO_TARGET} PUBLIC bcos-framework::utilities wedpr-crypto::wedpr-crypto)

if (TESTS)
    enable_testing()
    set(CTEST_OUTPUT_ON_FAILURE TRUE)
    add_subdirectory(test)
endif()

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

# for code coverage
if (COVERAGE)
    include(Coverage)
    config_coverage("'/usr*' '${CMAKE_SOURCE_DIR}/bcos-cmake-scripts*' '${CMAKE_SOURCE_DIR}/test/bcos-test*'")
endif ()