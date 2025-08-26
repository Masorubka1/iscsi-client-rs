FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y targetcli-fb python3-rtslib-fb iproute2 kmod && \
    rm -rf /var/lib/apt/lists/*

ENV LIO_IQN=iqn.2025-08.example:disk0 \
    LIO_SIZE_MB=1000 \
    LIO_LUN=1 \
    LIO_PORT=3260 \
    LIO_INITIATORS= \
    LIO_CHAP_USER= \
    LIO_CHAP_PASS= \
    LIO_MUTUAL_USER= \
    LIO_MUTUAL_PASS=

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
