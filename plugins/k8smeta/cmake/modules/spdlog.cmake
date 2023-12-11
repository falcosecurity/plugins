message(STATUS "Fetching spdlog at at 'https://github.com/gabime/spdlog'")

# Header only library
FetchContent_Declare(
  spdlog
  GIT_REPOSITORY "https://github.com/gabime/spdlog.git"
  GIT_TAG v1.12.0)

FetchContent_MakeAvailable(spdlog)
set(SPDLOG_INLCUDE "${spdlog_SOURCE_DIR}/include")
message(STATUS "Using spdlog include at '${SPDLOG_INLCUDE}'")
