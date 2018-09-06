FROM fedora:26

RUN dnf update -y && \
    dnf install -y git gcc ncurses-devel elfutils-libelf-devel bc \
      openssl-devel libcap-devel clang llvm kernel-devel && \
    dnf clean all

ENV GOLANG_VERSION 1.11

RUN curl -sL -o /usr/bin/gvm https://github.com/andrewkroh/gvm/releases/download/v0.1.0/gvm-linux-amd64 && \
    chmod +x /usr/bin/gvm && \
    gvm $GOLANG_VERSION && \
    ln -s /usr/local/go ~/.gvm/versions/go${GOLANG_VERSION}.linux.amd64

ENV GOPATH /go
ENV GOROOT /root/.gvm/versions/go${GOLANG_VERSION}.linux.amd64
ENV PATH $GOPATH/bin:$GOROOT/bin:$PATH

RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
WORKDIR $GOPATH
