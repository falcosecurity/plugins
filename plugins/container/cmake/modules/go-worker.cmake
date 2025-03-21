include(ExternalProject)

message(STATUS "Building go-worker static library")

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    # btrfs cmake dep
    include(btrfs)
endif()

ExternalProject_Add(go-worker
        SOURCE_DIR ${CMAKE_SOURCE_DIR}/go-worker
        BUILD_IN_SOURCE 1
        CONFIGURE_COMMAND ""
        BUILD_COMMAND make ${BTRFS_CGO_CFLAG} lib
        BUILD_BYPRODUCTS libworker.a libworker.h
        INSTALL_COMMAND ""
)

# https://tip.golang.org/doc/go1.20#cgo:
# > A consequence is that, on macOS, if Go code that uses the net package is built with -buildmode=c-archive,
# linking the resulting archive into a C program requires passing -lresolv when linking the C code.
# So, properly link resolv library; also, we need foundation library.
if(APPLE)
    find_library(SECURITY_FRAMEWORK Security REQUIRED)
    find_library(RESOLV resolv REQUIRED)
    find_library(CORE CoreFoundation REQUIRED)
    set(WORKER_DEP ${SECURITY_FRAMEWORK} ${RESOLV} ${CORE})
endif()
set(WORKER_LIB ${CMAKE_SOURCE_DIR}/go-worker/libworker.a)
set(WORKER_INCLUDE ${CMAKE_SOURCE_DIR}/go-worker)

message(STATUS "Using worker library at '${WORKER_LIB}' with header in ${WORKER_INCLUDE}")