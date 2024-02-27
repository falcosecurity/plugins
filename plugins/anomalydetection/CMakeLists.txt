cmake_minimum_required(VERSION 3.22)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

option(BUILD_TESTS "Enable tests" ON)

# Project metadata
project(
  anomalydetection
  VERSION 0.1.0
  DESCRIPTION "Falco Anomaly Detection Plugin"
  LANGUAGES CXX)

# Dependencies
include(FetchContent)
include(plugin-sdk-cpp)
include(libs) # Temporarily include libs for initial dev
include(xxhash)

# Project target
file(GLOB_RECURSE anomalydetection_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
add_library(anomalydetection SHARED ${anomalydetection_SOURCES} )
set_target_properties(anomalydetection PROPERTIES CXX_EXTENSIONS OFF)

# Project compilation options
target_compile_options(anomalydetection PRIVATE "-fPIC")
target_compile_options(anomalydetection PRIVATE "-Wl,-z,relro,-z,now")
target_compile_options(anomalydetection PRIVATE "-fstack-protector-strong")
# When compiling in Debug mode, this will define the DEBUG symbol for use in your code
target_compile_options(anomalydetection PUBLIC "$<$<CONFIG:DEBUG>:-DDEBUG>")
target_compile_features(anomalydetection PUBLIC cxx_std_17)

# Project includes
target_include_directories(
  anomalydetection PRIVATE "${PLUGIN_SDK_INCLUDE}" "${XXHASH_INCLUDE}" "${LIBS_INCLUDE}")

# Project linked libraries
target_link_libraries(anomalydetection ${_REFLECTION})

# Testing
# if(BUILD_TESTS)
#   add_subdirectory(test)
# endif()
