include(gtest)
include(libs)

# Configure the test variables header from template
set(TEST_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/include")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/plugin_test_var.h.in"
    "${TEST_INCLUDE_DIR}/container_tests/plugin_test_var.h"
    @ONLY
)

add_executable(integration_tests src/extract.cpp)

target_include_directories(integration_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${TEST_INCLUDE_DIR}
    ${PLUGIN_SDK_DEPS_INCLUDE}
    ${PLUGIN_SDK_INCLUDE})

target_link_libraries(integration_tests PRIVATE
    sinsp_test_support
    GTest::gmock
    GTest::gmock_main
    fmt::fmt-header-only
    container)
