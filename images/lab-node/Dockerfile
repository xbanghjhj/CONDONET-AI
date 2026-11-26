FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    curl dnsmasq-base dnsutils iproute2 iputils-ping nftables nginx openssh-server \
    procps python3 supervisor tcpdump udhcpc \
 && rm -f /etc/ssh/ssh_host_* \
 && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
