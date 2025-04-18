FROM amd64/gcc:11

RUN apt update && \
    apt install -y curl tar gcc g++
RUN curl -L -o liburing.tar.gz https://github.com/axboe/liburing/archive/refs/tags/liburing-2.9.tar.gz
RUN tar -xvf liburing.tar.gz
WORKDIR liburing-liburing-2.9
RUN ./configure --cc=gcc --cxx=g++ && \
    make -j$(nproc) && \
    make liburing.pc && \
    make install
