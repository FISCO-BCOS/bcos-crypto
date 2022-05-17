SET(Boost_USE_STATIC_LIBS ON)
install_dep(Boost 1.69 log chrono system filesystem iostreams thread program_options)
hunter_add_package(bcos-utilities)
find_package(bcos-utilities CONFIG REQUIRED)