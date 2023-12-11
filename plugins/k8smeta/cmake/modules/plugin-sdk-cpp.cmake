message(
  STATUS
    "Fetching plugin-sdk-cpp at 'https://github.com/falcosecurity/plugin-sdk-cpp.git'"
)

FetchContent_Declare(
  plugin-sdk-cpp
  GIT_REPOSITORY https://github.com/falcosecurity/plugin-sdk-cpp.git
  GIT_TAG 2097bdb5a5d77f3f38162da1f438382912465340)

FetchContent_MakeAvailable(plugin-sdk-cpp)
set(PLUGIN_SDK_INLCUDE "${plugin-sdk-cpp_SOURCE_DIR}/include")
message(STATUS "Using plugin-sdk-cpp include at '${PLUGIN_SDK_INLCUDE}'")
