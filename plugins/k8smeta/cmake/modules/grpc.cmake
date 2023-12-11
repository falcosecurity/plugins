# This cmake module is adapted from the grpc repo:
# `examples/cpp/cmake/common.cmake`

message(STATUS "Fetching grpc at 'https://github.com/grpc/grpc'")

find_package(Threads REQUIRED)

# See:
# https://github.com/protocolbuffers/protobuf/issues/12185#issuecomment-1594685860
set(ABSL_ENABLE_INSTALL ON)

# To solve:
#
# CMake Warning at build/_deps/grpc-src/third_party/abseil-cpp/CMakeLists.txt:77
# (message): A future Abseil release will default ABSL_PROPAGATE_CXX_STD to ON
# for CMake 3.8 and up.  We recommend enabling this option to ensure your
# project still builds correctly
set(ABSL_PROPAGATE_CXX_STD ON)

FetchContent_Declare(
  gRPC
  GIT_REPOSITORY https://github.com/grpc/grpc
  GIT_TAG v1.44.0
  GIT_PROGRESS TRUE)

set(FETCHCONTENT_QUIET OFF)
FetchContent_MakeAvailable(gRPC)

set(_PROTOBUF_LIBPROTOBUF libprotobuf)
set(_REFLECTION grpc++_reflection)
set(_PROTOBUF_PROTOC $<TARGET_FILE:protoc>)
set(_GRPC_GRPCPP grpc++)
set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:grpc_cpp_plugin>)

message(STATUS "Using grpc at '${gRPC_SOURCE_DIR}'")
