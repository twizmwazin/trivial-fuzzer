FROM mcr.microsoft.com/devcontainers/rust:1-bookworm

ADD https://apt.llvm.org/llvm-snapshot.gpg.key /etc/apt/trusted.gpg.d/apt.llvm.org.asc
RUN echo "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-18 main" >> /etc/apt/sources.list.d/llvm.list
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -

RUN export DEBIAN_FRONTEND=noninteractive  \
    && apt-get update  \
    && apt-get -y install --no-install-recommends \
      python3-venv ninja-build llvm-18 clang-18 lld-18 \
      ripgrep vim \
    && apt-get clean  \
    && rm -rf /var/lib/apt/lists/*
