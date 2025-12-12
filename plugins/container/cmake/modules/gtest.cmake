include(FetchContent)
FetchContent_Declare(
    gtest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.17.0
    OVERRIDE_FIND_PACKAGE
)
FetchContent_MakeAvailable(gtest)

enable_testing()
