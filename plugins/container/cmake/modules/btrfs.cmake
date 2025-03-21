# NOTE: containerd go package does only depend on the
# header files from libbtrfs.
# Therefore we just fetch the repo and fixup the paths to the
# header files, without building the library.

set(BTRFS_SRC "${PROJECT_BINARY_DIR}/_deps/btrfs-src")
set(LIBBTRFS_SRC "${BTRFS_SRC}/libbtrfs")

include(FetchContent)

FetchContent_Declare(
        btrfs
        GIT_REPOSITORY https://github.com/kdave/btrfs-progs.git
        GIT_TAG v6.13
)
FetchContent_MakeAvailable(btrfs)

# Configure version.h.in with pre-defined values
# (same values of v6.13).
# See https://github.com/kdave/btrfs-progs/blob/devel/configure.ac#L18
set(LIBBTRFS_MAJOR 0)
set(LIBBTRFS_MINOR 1)
set(LIBBTRFS_PATCHLEVEL 4)
set(PACKAGE_VERSION v6.13)
configure_file(${LIBBTRFS_SRC}/version.h.in ${LIBBTRFS_SRC}/version.h)

# Create a `btrfs` folder and move required `*.h` there,
# since the includes will be <btrfs/foo.h>
file(GLOB LIBBTRFS_HEADERS "${LIBBTRFS_SRC}/*.h" "${BTRFS_SRC}/kernel-lib/*.h")
file(MAKE_DIRECTORY ${LIBBTRFS_SRC}/btrfs)
file(COPY ${LIBBTRFS_HEADERS} DESTINATION ${LIBBTRFS_SRC}/btrfs/)

set(BTRFS_CGO_CFLAG -e CGO_CFLAGS=-I${LIBBTRFS_SRC})