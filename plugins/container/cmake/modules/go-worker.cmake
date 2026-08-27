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
elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    # The same Go >= 1.20 cgo-resolver requirement applies on Linux: the net
    # package references res_search from libresolv. On glibc >= 2.34 the
    # symbol happens to resolve through libc's compat exports, which masks a
    # missing dependency; on older glibc (Debian 11, RHEL/Rocky/Alma 8,
    # Ubuntu 20.04) it lives only in libresolv.so.2, and without a DT_NEEDED
    # entry the plugin fails to dlopen with:
    #   undefined symbol: __res_search
    set(WORKER_DEP resolv)
endif()
set(WORKER_LIB ${CMAKE_SOURCE_DIR}/go-worker/libworker.a)
set(WORKER_INCLUDE ${CMAKE_SOURCE_DIR}/go-worker)

message(STATUS "Using worker library at '${WORKER_LIB}' with header in ${WORKER_INCLUDE}")