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
include(grpc)
include(spdlog)
include(plugin-sdk-cpp)
include(k8s-metacollector)

set(PROTO_PATH "${K8S_METACOLLECTOR_DIR}/metadata/metadata.proto")

get_filename_component(meta_proto "${PROTO_PATH}" ABSOLUTE)
get_filename_component(meta_proto_path "${meta_proto}" PATH)

# Generated sources
set(PROTO_GENERATED_INCLUDE "${CMAKE_BINARY_DIR}/generated")
if(NOT EXISTS "${PROTO_GENERATED_INCLUDE}")
  file(MAKE_DIRECTORY "${PROTO_GENERATED_INCLUDE}")
endif()

set(meta_proto_srcs "${PROTO_GENERATED_INCLUDE}/metadata.pb.cc")
set(meta_proto_hdrs "${PROTO_GENERATED_INCLUDE}/metadata.pb.h")
set(meta_grpc_srcs "${PROTO_GENERATED_INCLUDE}/metadata.grpc.pb.cc")
set(meta_grpc_hdrs "${PROTO_GENERATED_INCLUDE}/metadata.grpc.pb.h")
add_custom_command(
  OUTPUT "${meta_proto_srcs}" "${meta_proto_hdrs}" "${meta_grpc_srcs}"
         "${meta_grpc_hdrs}"
  COMMAND
    ${_PROTOBUF_PROTOC} ARGS --grpc_out "${PROTO_GENERATED_INCLUDE}" --cpp_out
    "${PROTO_GENERATED_INCLUDE}" -I "${meta_proto_path}"
    --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}" "${meta_proto}"
  DEPENDS "${meta_proto}")

# project target
file(GLOB_RECURSE K8S_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
add_library(k8smeta SHARED ${K8S_SOURCES} ${meta_grpc_srcs} ${meta_grpc_hdrs}
                           ${meta_proto_srcs} ${meta_proto_hdrs})
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
  k8smeta PRIVATE "${PLUGIN_SDK_INLCUDE}" "${PROTO_GENERATED_INCLUDE}"
                  "${SPDLOG_INLCUDE}")

# project linked libraries
target_link_libraries(k8smeta ${_REFLECTION} ${_GRPC_GRPCPP}
                      ${_PROTOBUF_LIBPROTOBUF} re2::re2)

# Testing
if(BUILD_TESTS)
  add_subdirectory(test)
endif()
