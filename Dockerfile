FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    python3 \
    wget \
    pkg-config \
    ninja-build \
    libssl-dev \
    libgmp-dev \
    libboost-all-dev \
    libsodium-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

RUN rm -rf openfhe-development/build \
    && cmake -S openfhe-development -B openfhe-development/build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build openfhe-development/build -j"$(nproc)" \
    && cmake --install openfhe-development/build

RUN cmake -S emp-tool -B emp-tool/build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build emp-tool/build -j"$(nproc)" \
    && cmake --install emp-tool/build

RUN cmake -S emp-ot -B emp-ot/build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build emp-ot/build -j"$(nproc)" \
    && cmake --install emp-ot/build

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build -j"$(nproc)"

ENV LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}

CMD ["/bin/bash"]


