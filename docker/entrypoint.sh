#!/bin/sh
set -e

sock=/run/tgtd/socket.0
mkdir -p "$(dirname "$sock")"
max_wait=50

if [ ! -f /backing.img ]; then
  dd if=/dev/zero of=/backing.img bs=1M count="${TGT_SIZE_MB}"
fi

tgtd --foreground --debug 1 &
TGTD_PID=$!

i=0
printf '⏳  waiting tgtd…'
while [ ! -S "$sock" ]; do
    i=$((i+1))
    [ $i -ge $max_wait ] && { echo " ❌  tgtd unable create on socket $sock"; exit 1; }
    sleep 0.1
done
echo " ✅"

tgtadm --lld iscsi --op new    --mode target      --tid 1 --targetname "${TGT_IQN}"
tgtadm --lld iscsi --op new    --mode logicalunit --tid 1 --lun "${TGT_LUN:-1}" \
       --backing-store /backing.img
tgtadm --lld iscsi --op bind   --mode target      --tid 1 --initiator-address ALL

echo "✅ iSCSI target ${TGT_IQN} ready on port 3260"

wait "${TGTD_PID}"
