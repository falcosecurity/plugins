include(FetchContent)
FetchContent_Declare(
        reflex
        GIT_REPOSITORY https://github.com/Genivia/RE-flex.git
        GIT_TAG v5.3.0
        UPDATE_DISCONNECTED TRUE
        EXCLUDE_FROM_ALL TRUE
)
FetchContent_MakeAvailable(reflex)
