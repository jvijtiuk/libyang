cmake_minimum_required(VERSION 2.8.12)

# force out-of-source build
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    message(FATAL_ERROR "In-source build is not allowed. Please make a standalone build directory and run CMake from there. You may need to remove CMakeCache.txt.")
endif()

project(libyang C)

include(GNUInstallDirs)
include(CheckSymbolExists)

set(LIBYANG_DESCRIPTION "libyang is YANG data modelling language parser and toolkit written (and providing API) in C.")

# Correct RPATH usage on OS X
set(CMAKE_MACOSX_RPATH TRUE)

# set version of the project
set(LIBYANG_MAJOR_VERSION 2)
set(LIBYANG_MINOR_VERSION 0)
set(LIBYANG_MICRO_VERSION 0)
set(LIBYANG_VERSION ${LIBYANG_MAJOR_VERSION}.${LIBYANG_MINOR_VERSION}.${LIBYANG_MICRO_VERSION})
# set version of the library
set(LIBYANG_MAJOR_SOVERSION 2)
set(LIBYANG_MINOR_SOVERSION 0)
set(LIBYANG_MICRO_SOVERSION 0)
set(LIBYANG_SOVERSION_FULL ${LIBYANG_MAJOR_SOVERSION}.${LIBYANG_MINOR_SOVERSION}.${LIBYANG_MICRO_SOVERSION})
set(LIBYANG_SOVERSION ${LIBYANG_MAJOR_SOVERSION})

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE debug)
endif()

# options
if((CMAKE_BUILD_TYPE STREQUAL debug) OR (CMAKE_BUILD_TYPE STREQUAL Package))
    option(ENABLE_BUILD_TESTS "Build tests" ON)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" ON)
    option(ENABLE_COVERAGE "Build code coverage report from tests" OFF)
else()
    option(ENABLE_BUILD_TESTS "Build tests" OFF)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" OFF)
    option(ENABLE_COVERAGE "Build code coverage report from tests" OFF)
endif()

option(ENABLE_FUZZ_TARGETS "Build target programs suitable for fuzzing with AFL" OFF)
#option(ENABLE_CALLGRIND_TESTS "Build performance tests to be run with callgrind" OFF)

#option(ENABLE_CACHE "Enable data caching for schemas and hash tables for data (time-efficient at the cost of increased space-complexity)" ON)
#option(ENABLE_LATEST_REVISIONS "Enable reusing of latest revisions of schemas" ON)
#option(ENABLE_LYD_PRIV "Add a private pointer also to struct lyd_node (data node structure), just like in struct lys_node, for arbitrary user data" OFF)
#set(PLUGINS_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/libyang" CACHE STRING "Directory with libyang plugins (extensions and user types)")

#if(ENABLE_CACHE)
#    set(LY_ENABLED_CACHE 1)
#endif()
#if(ENABLE_LATEST_REVISIONS)
#    set(LY_ENABLED_LATEST_REVISIONS 1)
#endif()
#if(ENABLE_LYD_PRIV)
#    set(LY_ENABLED_LYD_PRIV 1)
#endif()

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(COMPILER_UNUSED_ATTR "UNUSED_ ## x __attribute__((__unused__))")
    set(COMPILER_PACKED_ATTR "__attribute__((__packed__))")
elseif(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    set(COMPILER_UNUSED_ATTR "UNUSED_ ## x __attribute__((__unused__))")
    set(COMPILER_PACKED_ATTR "__attribute__((__packed__))")
else()
    set(COMPILER_UNUSED_ATTR "UNUSED_ ## x")
    set(COMPILER_PACKED_ATTR "")
endif()

if(ENABLE_COVERAGE)
    find_program(PATH_GCOV NAMES gcov)
    if(NOT PATH_GCOV)
        message(WARNING "'gcov' executable not found! Disabling building code coverage report.")
        set(ENABLE_COVERAGE OFF)
    endif()

    find_program(PATH_LCOV NAMES lcov)
    if(NOT PATH_GCOV)
        message(WARNING "'lcov' executable not found! Disabling building code coverage report.")
        set(ENABLE_COVERAGE OFF)
    endif()

    find_program(PATH_GENHTML NAMES genhtml)
    if(NOT PATH_GCOV)
        message(WARNING "'genhtml' executable not found! Disabling building code coverage report.")
        set(ENABLE_COVERAGE OFF)
    endif()

    if(NOT CMAKE_COMPILER_IS_GNUCC)
        message(WARNING "Compiler is not gcc! Coverage may break the tests!")
    endif()

    if(ENABLE_COVERAGE)
        set(CMAKE_C_FLAGS_COVERAGE "${CMAKE_C_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    endif()
endif()

set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_COVERAGE} -Wall -Wextra -Wno-missing-field-initializers -std=c99")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_C_FLAGS_PACKAGE "-g -O2 -DNDEBUG")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0")

list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
check_symbol_exists(get_current_dir_name unistd.h HAVE_GET_CURRENT_DIR_NAME)
check_symbol_exists(vdprintf stdio.h HAVE_VDPRINTF)
check_symbol_exists(strnstr string.h HAVE_STRNSTR)

include_directories(${PROJECT_BINARY_DIR}/src ${PROJECT_SOURCE_DIR}/src)
configure_file(${PROJECT_SOURCE_DIR}/src/config.h.in ${PROJECT_BINARY_DIR}/src/config.h @ONLY)

#set(EXTENSIONS_PLUGINS_DIR_MACRO "${PLUGINS_DIR}/extensions")
#set(USER_TYPES_PLUGINS_DIR_MACRO "${PLUGINS_DIR}/user_types")

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

# setup bindings
#set(GEN_LANGUAGE_BINDINGS 0 CACHE BOOL "Enable language bindings generation.")
#set(GEN_CPP_BINDINGS 1 CACHE BOOL "Enable C++ bindings.")
# Python bindings depend on C++ bindings because of SWIG
#set(GEN_PYTHON_BINDINGS 1 CACHE BOOL "Enable Python bindings.")
#set(GEN_PYTHON_VERSION "3" CACHE STRING "Python version")
#set(GEN_JAVASCRIPT_BINDINGS 0 CACHE BOOL "Enable JavaScript bindings.")

#find_program(DEB_BUILDER NAMES debuild)
#find_program(RPM_BUILDER NAMES rpmbuild)

#if (NOT DEFINED ENV{TRAVIS_BRANCH})
#    execute_process(COMMAND "git" "rev-parse" "--abbrev-ref" "HEAD"
#                    OUTPUT_VARIABLE GIT_BRANCH
#                    OUTPUT_STRIP_TRAILING_WHITESPACE
#                    ERROR_QUIET
#                )
#    if (NOT GIT_BRANCH)
#        set(ENV{TRAVIS_BRANCH} "master")
#    else()
#        if (GIT_BRANCH MATCHES "master|devel")
#            set(ENV{TRAVIS_BRANCH} ${GIT_BRANCH})
#        else()
#            set(ENV{TRAVIS_BRANCH} "master")
#        endif()
#    endif()
#    set(GIT_BRANCH $ENV{TRAVIS_BRANCH})
#endif()
#
#if ($ENV{TRAVIS_BRANCH} STREQUAL "master")
#    set(PACKAGE_NAME "libyang")
#    set(PACKAGE_PART_NAME "")
#    set(BRANCH "master")
#    set(BUILD_TYPE "Package")
#    set(CONFLICT_PACKAGE_NAME "libyang-experimental")
#else ()
#    set(PACKAGE_NAME "libyang-experimental")
#    set(PACKAGE_PART_NAME "-experimental")
#    set(BRANCH "devel")
#    set(BUILD_TYPE "debug")
#    set(CONFLICT_PACKAGE_NAME "libyang")
#endif()
# change version in config files
#configure_file(${PROJECT_SOURCE_DIR}/packages/libyang.spec.in ${PROJECT_BINARY_DIR}/build-packages/libyang.spec)
#configure_file(${PROJECT_SOURCE_DIR}/packages/libyang.dsc.in ${PROJECT_BINARY_DIR}/build-packages/libyang.dsc)
#configure_file(${PROJECT_SOURCE_DIR}/packages/debian.control.in ${PROJECT_BINARY_DIR}/build-packages/debian.control @ONLY)
#configure_file(${PROJECT_SOURCE_DIR}/packages/debian.rules.in ${PROJECT_BINARY_DIR}/build-packages/debian.rules)

#if (NOT DEB_BUILDER)
#    message(WARNING "Missing tools (devscripts, debhelper package) for building deb package.\nYou won't be able to generate deb package from source code.\nCompiling libyang should still works fine.")
#else ()
#    # target for local build deb package
#    add_custom_target(build-deb
#                      WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
#                      COMMAND build-packages/local-deb.sh
#    )
#    configure_file(${PROJECT_SOURCE_DIR}/packages/local-deb.sh.in ${PROJECT_BINARY_DIR}/build-packages/local-deb.sh @ONLY)
#endif()

#if (NOT RPM_BUILDER)
#    message(WARNING "Missing tools (rpm package) for building rpm package. \nYou won't be able to generate rpm package from source code.\nCompiling libyang should still works fine.")
#else ()
#    # target for local build rpm package
#    string(REPLACE ${PROJECT_SOURCE_DIR} "." EXCLUDE_BUILD_DIR ${PROJECT_BINARY_DIR})
#    add_custom_target(build-rpm
#                      WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
#                      COMMAND build-packages/local-rpm.sh
#    )
#    configure_file(${PROJECT_SOURCE_DIR}/packages/local-rpm.sh.in ${PROJECT_BINARY_DIR}/build-packages/local-rpm.sh @ONLY)
#endif()

# by default build shared library
# static build requires static libpcre2 library
option(ENABLE_STATIC "Build static (.a) library" OFF)

# check the supported platform
if(NOT UNIX)
    message(FATAL_ERROR "Only *nix like systems are supported.")
endif()

set(libsrc
    src/common.c
    src/compat.c
    src/log.c
    src/hash_table.c
    src/set.c
    src/context.c
    src/tree_data.c
    src/tree_data_free.c
    src/tree_data_helpers.c
    src/tree_data_hash.c
    src/parser_xml.c
    src/printer_data.c
    src/printer_xml.c
    src/printer_json.c
    src/tree_schema.c
    src/tree_schema_free.c
    src/tree_schema_compile.c
    src/tree_schema_helpers.c
    src/parser_yang.c
    src/printer.c
    src/printer_schema.c
    src/printer_yang.c
    src/plugins_types.c
    src/xml.c
    src/xpath.c)

set(lintsrc
    tools/lint/main.c
    tools/lint/main_ni.c
    tools/lint/commands.c
    tools/lint/completion.c
    tools/lint/configuration.c
    tools/lint/linenoise/linenoise.c)

set(resrc
    tools/re/main.c)

set(headers
    src/libyang.h
    src/context.h
    src/tree.h
    src/tree_data.h
    src/printer_data.h
    src/tree_schema.h
    src/printer_schema.h
    src/extensions.h
    src/plugins_types.h
    src/dict.h
    src/log.h
    src/set.h)

# create static libyang library
if(ENABLE_STATIC)
    add_definitions(-DSTATIC)
    set(CMAKE_EXE_LINKER_FLAGS -static)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
    set(CMAKE_EXE_LINK_DYNAMIC_C_FLAGS)       # remove -Wl,-Bdynamic
    set(CMAKE_EXE_LINK_DYNAMIC_CXX_FLAGS)
    add_library(yang STATIC ${libsrc})
else()
    set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
    add_library(yangobj OBJECT ${libsrc})
    add_library(yang SHARED $<TARGET_OBJECTS:yangobj>)

    #link dl
    target_link_libraries(yang ${CMAKE_DL_LIBS})
endif(ENABLE_STATIC)

set_target_properties(yang PROPERTIES VERSION ${LIBYANG_SOVERSION_FULL} SOVERSION ${LIBYANG_SOVERSION})
set_target_properties(yangobj PROPERTIES COMPILE_FLAGS "-fvisibility=hidden")

# link math
target_link_libraries(yang m)

# find pthreads
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads REQUIRED)
if(ENABLE_STATIC)
    target_link_libraries(yang -Wl,--whole-archive ${CMAKE_THREAD_LIBS_INIT} -Wl,--no-whole-archive)
else()
    target_link_libraries(yang ${CMAKE_THREAD_LIBS_INIT})
endif(ENABLE_STATIC)

# find PCRE2 library
unset(PCRE2_LIBRARY CACHE)
find_package(PCRE2 10.30 REQUIRED)
include_directories(${PCRE2_INCLUDE_DIRS})
target_link_libraries(yang ${PCRE2_LIBRARIES})

install(TARGETS yang DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${headers} ${PROJECT_BINARY_DIR}/src/config.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libyang)

find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
    # generate and install pkg-config file
    configure_file("libyang.pc.in" "libyang.pc" @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libyang.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
    # check that pkg-config includes the used path
    execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} --variable pc_path pkg-config RESULT_VARIABLE RETURN OUTPUT_VARIABLE PC_PATH ERROR_QUIET)
    if(RETURN EQUAL 0)
	string(STRIP "${PC_PATH}" PC_PATH)
	set(PC_PATH "${PC_PATH}:$ENV{PKG_CONFIG_PATH}")
        string(REGEX MATCH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/pkgconfig" SUBSTR "${PC_PATH}")
        string(LENGTH "${SUBSTR}" SUBSTR_LEN)
        if(SUBSTR_LEN EQUAL 0)
            message(WARNING "pkg-config will not detect the new package after installation, adjust PKG_CONFIG_PATH using \"export PKG_CONFIG_PATH=\${PKG_CONFIG_PATH}:${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/pkgconfig\".")
        endif()
    endif()
endif()

# generate doxygen documentation for libyang API
find_package(Doxygen)
if(DOXYGEN_FOUND)
    find_program(DOT_PATH dot PATH_SUFFIXES graphviz2.38/bin graphviz/bin)
    if(DOT_PATH)
        set(HAVE_DOT "YES")
    else()
        set(HAVE_DOT "NO")
        message(AUTHOR_WARNING "Doxygen: to generate UML diagrams please install graphviz")
    endif()
    add_custom_target(doc
            COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_BINARY_DIR}/Doxyfile
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    configure_file(Doxyfile.in Doxyfile)
endif()

# clean cmake cache
add_custom_target(cclean
        COMMAND make clean
        COMMAND find . -iname '*cmake*' -not -name CMakeLists.txt -not -path './CMakeModules*' -exec rm -rf {} +
        COMMAND rm -rf Makefile Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# YANG extensions plugins
#set(EXTENSIONS_LIST "nacm" "metadata" "yangdata")
# if the tests are enabled, build libyang_ext_test
if(ENABLE_BUILD_TESTS)
    find_package(CMocka 1.0.0)
#    if(CMOCKA_FOUND AND CMAKE_BUILD_TYPE MATCHES debug)
#        list(APPEND EXTENSIONS_LIST "libyang_ext_test")
#    endif(CMOCKA_FOUND AND CMAKE_BUILD_TYPE MATCHES debug)
endif(ENABLE_BUILD_TESTS)

#if(ENABLE_STATIC)
#    set(EXTENSIONS_LIST_SIZE " 0 ")
#    set(ITEM 0)
#    foreach(EXTENSION ${EXTENSIONS_LIST})
#        add_library(${EXTENSION} STATIC "src/extensions/${EXTENSION}.c")
#        target_link_libraries(yang ${EXTENSION})
#        set(EXTENSIONS_LIST_SIZE "${EXTENSIONS_LIST_SIZE} + lyext_size(${EXTENSION})")
#        set(EXTERN_EXTENSIONS_LIST "${EXTERN_EXTENSIONS_LIST}extern struct lyext_plugin_list ${EXTENSION}[];\n")
#        set(MEMCPY_EXTENSIONS_LIST "${MEMCPY_EXTENSIONS_LIST}    lyext_add(plugin, count, ${EXTENSION});\n")
#        set(STATIC_LOADED_PLUGINS "${STATIC_LOADED_PLUGINS} \"${EXTENSION}\",")
#        MATH(EXPR ITEM "${ITEM}+1")
#    endforeach()
#else()
#    add_subdirectory(src/extensions)
#endif(ENABLE_STATIC)

# YANG user types plugins ("user_ipv4" is just an example, not installed by default)
#set(USER_TYPE_LIST "user_date_and_time")
#if(ENABLE_STATIC)
#    set(USER_TYPE_LIST_SIZE " 0 ")
#    foreach(USER_TYPE ${USER_TYPE_LIST})
#        add_library(${USER_TYPE} STATIC "src/user_types/${USER_TYPE}.c")
#        target_link_libraries(yang ${USER_TYPE})
#        set(USER_TYPE_LIST_SIZE "${USER_TYPE_LIST_SIZE} + lytype_size(${USER_TYPE})")
#        set(EXTERN_USER_TYPE_LIST "${EXTERN_USER_TYPE_LIST}extern struct lytype_plugin_list ${USER_TYPE}[];\n")
#        set(MEMCPY_USER_TYPE_LIST "${MEMCPY_USER_TYPE_LIST}    lytype_add(plugin, count, ${USER_TYPE});\n")
#        set(STATIC_LOADED_PLUGINS "${STATIC_LOADED_PLUGINS} \"${USER_TYPE}\",")
#        MATH(EXPR ITEM "${ITEM}+1")
#    endforeach()
#    set(STATIC_LOADED_PLUGINS_COUNT "${ITEM}")
#else()
#    add_subdirectory(src/user_types)
#endif(ENABLE_STATIC)
#
#configure_file(${PROJECT_SOURCE_DIR}/src/plugin_config.h.in ${PROJECT_BINARY_DIR}/src/plugin_config.h)

# config file for tools
configure_file(${PROJECT_SOURCE_DIR}/tools/config.h.in ${PROJECT_BINARY_DIR}/tools/config.h @ONLY)

# yanglint
add_executable(yanglint ${lintsrc})
target_link_libraries(yanglint yang)
install(TARGETS yanglint DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${PROJECT_SOURCE_DIR}/tools/lint/yanglint.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
target_include_directories(yanglint BEFORE PRIVATE ${PROJECT_BINARY_DIR}/tools)

# yangre
add_executable(yangre ${resrc})
target_link_libraries(yangre yang)
install(TARGETS yangre DESTINATION ${CMAKE_INSTALL_BINDIR})
target_include_directories(yangre BEFORE PRIVATE ${PROJECT_BINARY_DIR}/tools)

if(ENABLE_VALGRIND_TESTS)
    set(ENABLE_BUILD_TESTS ON)
endif()

if(ENABLE_BUILD_TESTS)
    if(CMOCKA_FOUND)
        enable_testing()
        add_subdirectory(tests)
    else(CMOCKA_FOUND)
        message(STATUS "Disabling tests because of missing CMocka")
        set(ENABLE_BUILD_TESTS NO)
    endif(CMOCKA_FOUND)
endif(ENABLE_BUILD_TESTS)

if(ENABLE_FUZZ_TARGETS)
	add_subdirectory(tests/fuzz)
endif(ENABLE_FUZZ_TARGETS)

#if(GEN_LANGUAGE_BINDINGS AND GEN_CPP_BINDINGS)
#    add_subdirectory(swig)
#endif()

