if(HUNTER_UTILITIES)
    hunter_add_package(Boost COMPONENTS all)
    hunter_add_package(bcos-utilities)
    find_package(Boost CONFIG REQUIRED log chrono system filesystem iostreams thread program_options)
    find_package(bcos-utilities CONFIG REQUIRED)
else()
    make_directory(${CMAKE_CURRENT_BINARY_DIR}/bcos-utilities-install/include)

    include(ExternalProject)
    ExternalProject_Add(bcos-utilities
        URL https://${URL_BASE}/FISCO-BCOS/bcos-utilities/archive/eaf6322d310f343663bb18b46e402ed328e2745b.tar.gz
        URL_HASH SHA1=409cdddc666eb6aea40ed8fb492c840b8614875b
        CMAKE_ARGS -DHUNTER_ENABLED=OFF -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/bcos-utilities-install
        INSTALL_COMMAND make install
    )

    add_library(bcos-utilities::bcos-utilities STATIC IMPORTED)
    target_include_directories(bcos-utilities::bcos-utilities INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/bcos-utilities-install/include)
    set_property(TARGET bcos-utilities::bcos-utilities PROPERTY
        IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/bcos-utilities-install/lib/libbcos-utilities.a)
    add_dependencies(bcos-utilities::bcos-utilities bcos-utilities)
endif()