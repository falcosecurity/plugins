include(gtest)
include(libs)

# Configure the test variables header from template
set(TEST_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/include")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/plugin_test_var.h.in"
    "${TEST_INCLUDE_DIR}/container_tests/plugin_test_var.h"
    @ONLY
)

add_executable(test src/extract.cpp
    config.cpp
    container_info_json.cpp
    matchers.cpp
    mounts.cpp
)

target_include_directories(test PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/matchers
    ${TEST_INCLUDE_DIR}
    ${PLUGIN_SDK_DEPS_INCLUDE}
    ${PLUGIN_SDK_INCLUDE})

target_link_libraries(test PRIVATE
    sinsp_test_support
    GTest::gmock
    GTest::gmock_main
    fmt::fmt-header-only
    container
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(test PRIVATE resolv container)
endif()
