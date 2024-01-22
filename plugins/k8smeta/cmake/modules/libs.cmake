message(STATUS "Fetching libs at 'https://github.com/falcosecurity/libs.git'")

# Just populate it we don't want to build it
FetchContent_Declare(
  libs
  GIT_REPOSITORY https://github.com/falcosecurity/libs.git
  GIT_TAG 0.14.1
  CONFIGURE_COMMAND "" BUILD_COMMAND "")

FetchContent_Populate(libs)
set(LIBS_DIR "${libs_SOURCE_DIR}")
