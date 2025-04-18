# Local testing

## Build

In order to use the test program, you have to compile it. You can decide to build it by using your host dependencies or
use a docker image built from the Dockerfile provided in the current directory.

### Method 1: use your host dependencies
This has been tested with `gcc 11` and `liburing 2.9`, so it is advised to use these versions on your host to correctly
compile it. Install the needed dependencies on your host and then run the following command from the current directory.

```shell
gcc test/test.c -o test/test -luring 
```

### Method 2: builder docker image
If you want to build the test program and link it statically with the right liburing version, without installing any
dependency on your host, you can use our docker image!

Run the following command to build the image:

```bash
docker build -t test-builder:latest .
```

Run the following command, from the current directory, to compile the test program using the built image:

```bash
docker run --rm -v "$PWD":/usr/src/test -w /usr/src/test test-builder:latest gcc test.c -o test /usr/lib/liburing.a
```

The compiled program, named `test`, will be available under the current directory.

## Usage

From the current directory, you can run the built test program in the following way:

```shell
sudo ./test/test {--use-syscalls|--use-file-indexes}
```

Without any flag, the program runs io_uring operations with traditional file descriptors. Using `--use-file-indexes`
instructs to use io_uring file indexes in place of traditional file descriptors. The `--use-syscalls` flag instructs the
program to use syscalls instead of io_uring operations.

