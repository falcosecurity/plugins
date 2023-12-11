message(STATUS "Fetching libs at 'https://github.com/falcosecurity/libs.git'")

# Just populate it we don't want to build it
FetchContent_Declare(
  libs
  GIT_REPOSITORY https://github.com/falcosecurity/libs.git
  GIT_TAG 8fee2fb4791d50ec5ee4808e5ed235c8b1b309f3
  CONFIGURE_COMMAND "" BUILD_COMMAND "")

FetchContent_Populate(libs)
set(LIBS_DIR "${libs_SOURCE_DIR}")
