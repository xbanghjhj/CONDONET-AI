FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    curl iproute2 iputils-ping nftables procps python3 tcpdump \
 && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
