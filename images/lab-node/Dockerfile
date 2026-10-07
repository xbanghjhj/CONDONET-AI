FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    iproute2 iputils-ping tcpdump procps \
 && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
