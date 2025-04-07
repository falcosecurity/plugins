#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#include <liburing.h>

// From the project root folder, compile and run it using the following command:
// gcc test/test.c -o test/test -luring && sudo ./test/test {--use-syscalls|--use-file-indexes}

static int submit_and_wait(struct io_uring *ring) {
    struct io_uring_cqe *cqe;
    int ret = io_uring_submit(ring);
    if (ret <= 0) {
        fprintf(stderr, "sqe submit failed: %d\n", ret);
        goto err;
    }

    ret = io_uring_wait_cqe(ring, &cqe);
    if (ret < 0) {
        fprintf(stderr, "wait completion %d\n", ret);
        goto err;
    }

    // The result contains the file descriptor
    ret = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    return ret;
err:
    return -1;
}

static int io_uring_openat(struct io_uring *ring, int dfd, const char *path, int flags, bool use_file_indexes) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        fprintf(stderr, "io_uring_openat: io_uring_get_sqe failed\n");
        return -1;
    }
    if (use_file_indexes) {
        io_uring_prep_openat_direct(sqe, dfd, path, flags, 0, IORING_FILE_INDEX_ALLOC);
    } else {
        io_uring_prep_openat(sqe, dfd, path, flags, 0);
    }

    return submit_and_wait(ring);
}

static int io_uring_connect(struct io_uring *ring, int fd, const struct sockaddr *addr, socklen_t addrlen, bool use_file_indexes) {
    struct io_uring_sqe *sqe;
    int ret;

    sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        fprintf(stderr, "io_uring_connect: io_uring_get_sqe failed\n");
        return -1;
    }

    io_uring_prep_connect(sqe, fd, addr, addrlen);
    if (use_file_indexes) {
        sqe->flags |= IOSQE_FIXED_FILE;
    }

    return submit_and_wait(ring);
}

static int io_uring_socket(struct io_uring *ring, int domain, int type, int protocol, int flags, bool use_file_indexes) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        fprintf(stderr, "io_uring_socket: io_uring_get_sqe failed\n");
        return -1;
    }

    if (use_file_indexes) {
        io_uring_prep_socket_direct_alloc(sqe, domain, type, protocol, flags);
    } else {
        io_uring_prep_socket(sqe, domain, type, protocol, flags);
    }
    return submit_and_wait(ring);
}

static int io_uring_symlinkat(struct io_uring *ring, char *target, int newdirfd, char *linkpath) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        fprintf(stderr, "io_uring_symlinkat: io_uring_get_sqe failed\n");
        return -1;
    }

    io_uring_prep_symlinkat(sqe, target, newdirfd, linkpath);
    return submit_and_wait(ring);
}

static int io_uring_linkat(struct io_uring *ring, int olddirfd, char *oldpath, int newdirfd, char *newpath, int flags) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        fprintf(stderr, "io_uring_linkat: io_uring_get_sqe failed\n");
        return -1;
    }

    io_uring_prep_linkat(sqe, olddirfd, oldpath, newdirfd, newpath, flags);
    return submit_and_wait(ring);
}

static int io_uring_unlinkat(struct io_uring *ring, int dirfd, char *path, int flags) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        fprintf(stderr, "io_uring_unlinkat: io_uring_get_sqe failed\n");
        return -1;
    }

    io_uring_prep_unlinkat(sqe, dirfd, path, flags);
    return submit_and_wait(ring);
}

static int io_uring_mkdirat(struct io_uring *ring, int dirfd, char *path, int mode) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        fprintf(stderr, "io_uring_mkdirat: io_uring_get_sqe failed\n");
        return -1;
    }

    io_uring_prep_mkdirat(sqe, dirfd, path, mode);
    return submit_and_wait(ring);
}

static int io_uring_read(struct io_uring *ring, int fd, char *buf, unsigned int nbytes, uint64_t offset, bool use_file_indexes) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        fprintf(stderr, "io_uring_read: io_uring_get_sqe failed\n");
        return -1;
    }

    io_uring_prep_read(sqe, fd, buf, nbytes, offset);
    if (use_file_indexes) {
        sqe->flags |= IOSQE_FIXED_FILE;
    }
    return submit_and_wait(ring);
}

static int io_uring_write(struct io_uring *ring, int fd, char *buf, unsigned int nbytes, uint64_t offset, bool use_file_indexes) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        fprintf(stderr, "io_uring_write: io_uring_get_sqe failed\n");
        return -1;
    }

    io_uring_prep_write(sqe, fd, buf, nbytes, offset);
    if (use_file_indexes) {
        sqe->flags |= IOSQE_FIXED_FILE;
    }
    return submit_and_wait(ring);
}

static int io_uring_close(struct io_uring *ring, int fd, bool use_file_indexes) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        fprintf(stderr, "io_uring_read: io_uring_get_sqe failed\n");
        return -1;
    }

	if (use_file_indexes) {
		io_uring_prep_close_direct(sqe, fd);
	} else {
		io_uring_prep_close(sqe, fd);
	}
    return submit_and_wait(ring);
}

static int do_openat(struct io_uring *ring, int dirfd, char *pathname, int flags, bool use_syscalls, bool use_file_indexes) {
    return use_syscalls ?
        openat(dirfd, pathname, flags) :
        io_uring_openat(ring, dirfd, pathname, flags, use_file_indexes);
}

static int do_connect(struct io_uring *ring, int fd, const struct sockaddr *addr, socklen_t addrlen, bool use_syscalls, bool use_file_indexes) {
    return use_syscalls ?
        connect(fd, addr, addrlen) :
        io_uring_connect(ring, fd, addr, addrlen, use_file_indexes);
}

static int do_socket(struct io_uring *ring, int domain, int type, int protocol, int flags, bool use_syscalls, bool use_file_indexes) {
    return use_syscalls ?
        socket(domain, type, protocol) :
        io_uring_socket(ring, domain, type, protocol, flags, use_file_indexes);
}

static int do_symlinkat(struct io_uring *ring, char *target, int newdirfd, char *linkpath, bool use_syscalls, bool use_file_indexes) {
    if (use_file_indexes) {
        printf("warning: do_symlinkat: file indexes not supported by IORING_OP_SYMLINKAT\n");
    }
    return use_syscalls ?
        symlinkat(target, newdirfd, linkpath) :
        io_uring_symlinkat(ring, target, newdirfd, linkpath);
}

static int do_linkat(struct io_uring *ring, int olddirfd, char *oldpath, int newdirfd, char *newpath, int flags, bool use_syscalls, bool use_file_indexes) {
    if (use_file_indexes) {
        printf("warning: do_linkat: file indexes not supported by IORING_OP_LINKAT\n");
    }
    return use_syscalls ?
        linkat(olddirfd, oldpath, newdirfd, newpath, flags) :
        io_uring_linkat(ring, olddirfd, oldpath, newdirfd, newpath, flags);
}

static int do_unlinkat(struct io_uring *ring, int dirfd, char *path, int flags, bool use_syscalls, bool use_file_indexes) {
    if (use_file_indexes) {
        printf("warning: do_unlinkat: file indexes not supported by IORING_OP_UNLINKAT\n");
    }
    return use_syscalls ?
        unlinkat(dirfd, path, flags) :
        io_uring_unlinkat(ring, dirfd, path, flags);
}

static int do_mkdirat(struct io_uring *ring, int dirfd, char *path, int mode, bool use_syscalls, bool use_file_indexes) {
    if (use_file_indexes) {
        printf("warning: do_mkdirat: file indexes not supported by IORING_OP_MKDIRAT\n");
    }
    return use_syscalls ?
        mkdirat(dirfd, path, mode) :
        io_uring_mkdirat(ring, dirfd, path, mode);
}

static int do_read(struct io_uring *ring, int fd, char *buf, unsigned int nbytes, uint64_t offset, bool use_syscalls, bool use_file_indexes) {
    return use_syscalls ?
        read(fd, buf, nbytes) :
        io_uring_read(ring, fd, buf, nbytes, offset, use_file_indexes);
}

static int do_write(struct io_uring *ring, int fd, char *buf, unsigned int nbytes, uint64_t offset, bool use_syscalls, bool use_file_indexes) {
    return use_syscalls ?
        write(fd, buf, nbytes) :
        io_uring_write(ring, fd, buf, nbytes, offset, use_file_indexes);
}

static int do_close(struct io_uring *ring, int fd, bool use_syscalls, bool use_file_indexes) {
    return use_syscalls ?
        close(fd) :
        io_uring_close(ring, fd, use_file_indexes);
}

static int test_openat(struct io_uring *ring, bool use_syscalls, bool use_file_indexes) {
    int dirfd = AT_FDCWD;
    char *pathname = "/etc/passwd";
    int flags = O_RDONLY;
    int fd = do_openat(ring, dirfd, pathname, flags, use_syscalls, use_file_indexes);
    if (fd < 0) {
        return fd;
    }
    do_close(ring, fd, use_syscalls, use_file_indexes);
    return 0;
}

int start_server() {
 	system("nc -lvnp 9001");
 }

static int test_connect(struct io_uring *ring, bool use_syscalls, bool use_file_indexes) {
	// Create a socket
	int sockfd = do_socket(ring, AF_INET, SOCK_STREAM, 0, 0, use_syscalls, use_file_indexes);
    if (sockfd < 0) {
        fprintf(stderr, "test_connect: do_socket failed with res=%d\n", sockfd);
        return -1;
    }

	// create a pipe to read from child process
	int pipefd[2];
	int ret = pipe(pipefd);
	if (ret < 0) {
		fprintf(stderr, "test_connect: pipe failed\n");
		return -1;
	}

	// spawn a server
	pid_t pid = fork();
	if (pid == 0) {
		close(pipefd[0]);
		dup2(pipefd[1], 1);
		start_server();
		exit(0);
	} else if (pid < 0) {
		fprintf(stderr, "test_connect: fork failed: %d\n", pid);
		return -1;
	} else {
		printf("test_connect: My pid: %d\n", getpid());
	}

	// Wait for the server to start
	sleep(2);
	close(pipefd[1]);
	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(9001);
	serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    ret = do_connect(ring, sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr), use_syscalls, use_file_indexes);
	if (ret < 0) {
		fprintf(stderr, "test_connect: connect failed: %d\n", ret);
		do_close(ring, sockfd, use_syscalls, use_file_indexes);
		return ret;
	}
	printf("test_connect: connected to server\n");
	ret = do_write(ring, sockfd, "Hello, world!\n", 14, -1, use_syscalls, use_file_indexes);
	if (ret < 0) {
        fprintf(stderr, "test_connect: writing to server failed: %d\n", ret);
        do_close(ring, sockfd, use_syscalls, use_file_indexes);
        return ret;
	}

	// Close the socket and connection
    do_close(ring, sockfd, use_syscalls, use_file_indexes);

	printf("test_connect: server response:\n");
	fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
    char buf[1024];
	while (1) {
		ret = read(pipefd[0], buf, sizeof(buf));
		if (ret <= 0) {
			break;
		}
		write(1, buf, ret);
	}

	// Kill the server
	printf("test_connect: killing server...\n");
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	return 0;
}

static int test_socket(struct io_uring *ring, bool use_syscalls, bool use_file_indexes) {
    int domain = AF_INET;
    int type = SOCK_STREAM;
    int protocol = 0;
    int fd = do_socket(ring, domain, type, protocol, 0, use_syscalls, use_file_indexes);
    if (fd < 0) {
        return fd;
    }
    do_close(ring, fd, use_syscalls, use_file_indexes);
    return 0;
}

static int test_symlinkat(struct io_uring *ring, bool use_syscalls, bool use_file_indexes) {
    // Create a symbolic link to /etc/passwd under /tmp/symlink_to_passwd.
    char *target = "/etc/passwd";
    int newdirfd = AT_FDCWD;
    char *linkpath = "/tmp/symlink_to_passwd";
    int ret = do_symlinkat(ring, target, newdirfd, linkpath, use_syscalls, use_file_indexes);
    if (ret < 0) {
        return ret;
    }
    do_unlinkat(ring, newdirfd, linkpath, 0, use_syscalls, use_file_indexes);
    return 0;
}

static int test_linkat(struct io_uring *ring, bool use_syscalls, bool use_file_indexes) {
    // Create a link to /etc/passwd under /tmp/link_to_passwd.
    int olddirfd = AT_FDCWD;
    char *oldpath = "/etc/passwd";
    int newdirfd = AT_FDCWD;
    char *newpath = "/tmp/link_to_passwd";
    int flags = AT_SYMLINK_FOLLOW;
    int ret = do_linkat(ring, olddirfd, oldpath, newdirfd, newpath, flags, use_syscalls, use_file_indexes);
    if (ret < 0) {
        return ret;
    }
    do_unlinkat(ring, newdirfd, newpath, 0, use_syscalls, use_file_indexes);
    return 0;
}

static int test_mkdirat(struct io_uring *ring, bool use_syscalls, bool use_file_indexes) {
    // Create a dir named tempdir under /tmp.
    int dirfd = AT_FDCWD;
    char *path = "/tmp/tempdir";
    int mode = S_IRWXU | S_IRWXG | S_IRWXO;
    int ret = do_mkdirat(ring, dirfd, path, mode, use_syscalls, use_file_indexes);
    if (ret < 0) {
        return ret;
    }
    do_unlinkat(ring, dirfd, path, AT_REMOVEDIR, use_syscalls, use_file_indexes);
    return 0;
}

static int test_read(struct io_uring *ring, bool use_syscalls, bool use_file_indexes) {
    int dirfd = AT_FDCWD;
    char *pathname = "/etc/passwd";
    int flags = O_RDONLY;
    int fd = do_openat(ring, dirfd, pathname, flags, use_syscalls, use_file_indexes);
    if (fd < 0) {
        return fd;
    }

    char buf[1024];
    int ret = do_read(ring, fd, buf, 1024, 0, use_syscalls, use_file_indexes);
    do_close(ring, fd, use_syscalls, use_file_indexes);
    return ret;
}

int main(int argc, char **argv) {
	struct io_uring ring;
	int ret;

    // Setup io_uring submission and completion queues.
	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed\n");
		return -1;
	}

    bool use_syscalls = argc > 1 && !strncmp(argv[1], "--use-syscalls", strlen("--use-syscalls"));
	bool use_file_indexes = argc > 1 && !strncmp(argv[1], "--use-file-indexes", strlen("--use-file-indexes"));
	// Enable file index usages.
	if (use_file_indexes) {
		ret = io_uring_register_files_sparse(&ring, 10);
	        if (ret) {
        	        fprintf(stderr, "file registration failed: %d\n", ret);
                	return -1;
        	}
	}

	struct test {
        char name[64];
        int (*test_func)(struct io_uring *ring, bool use_syscalls, bool use_file_indexes);
    };

#define TEST(test_name) {.name = #test_name, .test_func = test_name}
    struct test tests[] = {
        TEST(test_openat),
        TEST(test_connect),
        TEST(test_socket),
        TEST(test_symlinkat),
        TEST(test_linkat),
        {.name = "test_unlinkat", .test_func = test_linkat },
        TEST(test_mkdirat),
        TEST(test_read),
        {.name = "", .test_func = NULL},
    };
#undef TEST
    for (struct test *cur_test = &tests[0]; cur_test->test_func != NULL; cur_test++) {
        ret = cur_test->test_func(&ring, use_syscalls, use_file_indexes);
        if (ret < 0) {
            fprintf(stderr, "%s failed: %d\n", cur_test->name, ret);
            return -1;
        }
    }

    return 0;
}