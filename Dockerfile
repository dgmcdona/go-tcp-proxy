FROM golang:1.18-alpine as builder
WORKDIR /
RUN apk add --update-cache automake libtool make pkgconfig tar autoconf musl linux-headers build-base openssl-dev
RUN wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.2.1.tar.gz
RUN tar -zxf v4.2.1.tar.gz
WORKDIR /yara-4.2.1
RUN ./bootstrap.sh
RUN CC="/usr/bin/x86_64-alpine-linux-musl-gcc -static" ./configure --enable-static --disable-shared
RUN make
RUN make install
RUN make check
COPY . /go/src/gitlab.cs.uno.edu/dgmcdona/go-tcp-proxy
WORKDIR /go/src/gitlab.cs.uno.edu/dgmcdona/go-tcp-proxy
RUN go get ./... && \
    GOOS=linux CGO_ENABLED=1 CC=/usr/bin/x86_64-alpine-linux-musl-gcc go build -ldflags "-linkmode external -extldflags -static" -o tcp-proxy cmd/tcp-proxy/main.go

FROM scratch AS export
COPY --from=builder /go/src/gitlab.cs.uno.edu/dgmcdona/go-tcp-proxy/tcp-proxy .
