include(FetchContent)
FetchContent_Declare(gtest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.16.0)
FetchContent_MakeAvailable(gtest)

enable_testing()