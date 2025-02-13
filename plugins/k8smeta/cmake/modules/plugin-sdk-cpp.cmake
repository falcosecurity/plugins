message(
  STATUS
    "Fetching plugin-sdk-cpp at 'https://github.com/falcosecurity/plugin-sdk-cpp.git'"
)

FetchContent_Declare(
  plugin-sdk-cpp
  GIT_REPOSITORY https://github.com/falcosecurity/plugin-sdk-cpp.git
  GIT_TAG 0.2.0)

FetchContent_MakeAvailable(plugin-sdk-cpp)
set(PLUGIN_SDK_INLCUDE "${plugin-sdk-cpp_SOURCE_DIR}/include")
message(STATUS "Using plugin-sdk-cpp include at '${PLUGIN_SDK_INLCUDE}'")
