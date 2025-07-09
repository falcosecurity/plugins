cmake_minimum_required(VERSION 3.28)

if(NOT DEFINED CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
    set(CMAKE_BUILD_TYPE "release")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

# project metadata
project(
        container
        VERSION 0.3.1
        DESCRIPTION "Falco container metadata enrichment Plugin"
        LANGUAGES CXX)

# compiler related configs
include(compiler)

# Include capabilities module.
# This also defines CAPS_SOURCES.
include(caps)

# Configure the macros header
configure_file(src/macros.h.in src/macros.h @ONLY)

file(GLOB SOURCES src/*.cpp src/matchers/*.cpp)

# project target
add_library(container SHARED ${SOURCES} ${CAPS_SOURCES})

# dependencies
if(ENABLE_ASYNC)
    include(go-worker)
    add_dependencies(container go-worker)
endif()
include(plugin-sdk-cpp)
include(reflex)
include(fmt)

# project compilation options
set_property(TARGET container PROPERTY POSITION_INDEPENDENT_CODE ON)
if (NOT MSVC)
    target_compile_options(container PRIVATE "-Wl,-z,relro,-z,now")
    target_compile_options(container PRIVATE "-fstack-protector-strong")
else()
    # Workaround https://github.com/golang/go/issues/71921
    target_compile_definitions(container PRIVATE "_CRT_USE_C_COMPLEX_H")
endif()
# When compiling in Debug mode, this will define the DEBUG symbol for use in your code.
target_compile_options(container PUBLIC "$<$<CONFIG:DEBUG>:-DDEBUG>")
target_compile_features(container PUBLIC cxx_std_20)

# project includes
target_include_directories(container PRIVATE ${CMAKE_BINARY_DIR}/src/ src/ ${PLUGIN_SDK_INCLUDE} ${PLUGIN_SDK_DEPS_INCLUDE} ${WORKER_INCLUDE})

# project linked libraries
target_link_libraries(container PRIVATE fmt::fmt-header-only ReflexLibStatic ${WORKER_DEP} ${WORKER_LIB})

option(ENABLE_TESTS "Enable build of unit tests" ON)
if(ENABLE_TESTS)
    add_subdirectory(${CMAKE_SOURCE_DIR}/test/)
endif()
