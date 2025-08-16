# ./docker/iscsi-target/Dockerfile
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y tgt tgt-rbd tgt-glusterfs iproute2 && \
    mkdir -p /run/tgtd /usr/lib/tgt/backing-store && \
    rm -rf /var/lib/apt/lists/*

ENV TGT_IQN=iqn.2025-08.example:disk0 \
    TGT_SIZE_MB=1000 \
    TGT_LUN=1 \
    TGT_PGT=1

# CHAP (optional). Leave empty to disable auth.
ENV TGT_CHAP_USER= \
    TGT_CHAP_PASS= \
    TGT_MUTUAL_USER= \
    TGT_MUTUAL_PASS=

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3260/tcp
ENTRYPOINT ["/entrypoint.sh"]
