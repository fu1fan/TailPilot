FROM golang:1.26.6-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 curl git ca-certificates util-linux openssh-server \
    && rm -rf /var/lib/apt/lists/*
ENV GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly LANG=C.UTF-8
