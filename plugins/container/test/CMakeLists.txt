include(gtest)

message(STATUS "Unit tests enabled.")

file(GLOB_RECURSE SOURCES *.cpp)

add_executable(test ${SOURCES})

# project linked libraries
target_include_directories(test PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/src/matchers ${PLUGIN_SDK_DEPS_INCLUDE} ${PLUGIN_SDK_INCLUDE})

target_link_libraries(test PRIVATE GTest::gtest GTest::gtest_main fmt::fmt-header-only ReflexLibStatic container)