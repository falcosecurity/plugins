cmake_minimum_required(VERSION 3.22)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

option(BUILD_TESTS "Enable test" ON)

# project metadata
project(
  k8smeta
  VERSION 0.1.0
  DESCRIPTION "Falco Kubernetes enrichment Plugin"
  LANGUAGES CXX)

# dependencies
include(FetchContent)
include(plugin-sdk-cpp)
include(k8s-metacollector)

find_package(protobuf CONFIG REQUIRED)
find_package(gRPC REQUIRED)
find_package(spdlog REQUIRED)

set(PROTO_PATH "${K8S_METACOLLECTOR_DIR}/metadata/metadata.proto")
get_filename_component(meta_proto "${PROTO_PATH}" ABSOLUTE)
get_filename_component(meta_proto_path "${meta_proto}" PATH)

set(PROTO_OUTPUT_DIR "${CMAKE_BINARY_DIR}/generated")

# generate the protobuf output directory
file(MAKE_DIRECTORY "${PROTO_OUTPUT_DIR}")
message(STATUS "Protobuf files will be generated in: ${PROTO_OUTPUT_DIR}")

# project target
add_library(k8smeta SHARED
  src/plugin.cpp
  src/grpc_client.cpp
)

# Set the output directory for protobuf generation
set_target_properties(k8smeta PROPERTIES
  PROTOC_OUT_DIR "${PROTO_OUTPUT_DIR}")

# Generate protobuf files
protobuf_generate(
    TARGET k8smeta
    PROTOS "${meta_proto}"
    IMPORT_DIRS "${meta_proto_path}"
    PROTOC_OUT_DIR "${PROTO_OUTPUT_DIR}")

# Generate gRPC files
protobuf_generate(
    TARGET k8smeta
    LANGUAGE grpc
    GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
    PLUGIN "protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>"
    PROTOS "${meta_proto}"
    IMPORT_DIRS "${meta_proto_path}"
    PROTOC_OUT_DIR "${PROTO_OUTPUT_DIR}")
set_target_properties(k8smeta PROPERTIES CXX_EXTENSIONS OFF)

# project compilation options
target_compile_options(k8smeta PRIVATE "-fPIC")
target_compile_options(k8smeta PRIVATE "-Wl,-z,relro,-z,now")
target_compile_options(k8smeta PRIVATE "-fstack-protector-strong")
# When compiling in Debug mode, this will define the DEBUG symbol for use in
# your code.
target_compile_options(k8smeta PUBLIC "$<$<CONFIG:DEBUG>:-DDEBUG>")
target_compile_features(k8smeta PUBLIC cxx_std_17)

# project includes
target_include_directories(
  k8smeta PRIVATE "${PLUGIN_SDK_INLCUDE}" "${PROTO_OUTPUT_DIR}")

# project linked libraries
target_link_libraries(k8smeta
  spdlog::spdlog
  gRPC::grpc++)

# Testing
if(BUILD_TESTS)
  add_subdirectory(test)
endif()
