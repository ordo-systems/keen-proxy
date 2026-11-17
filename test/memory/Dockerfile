FROM debian:bookworm-slim

# Runtime networking is disabled; package downloads occur only while building.
RUN apt-get -qq update && apt-get -qq install -y --no-install-recommends \
    iproute2 iptables procps curl python3 dnsmasq-base wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["python3", "-B", "/fixture/scenario.py"]
