#!/usr/bin/env bash
set -euo pipefail

readonly BASE_IMAGE="${1:?usage: start-qemu.sh BASE_IMAGE}"
readonly TEST_MODE="${2:-plain}"
readonly WORK_DIR="${RUNNER_TEMP:-/tmp}/iscsi-lio-qemu"
readonly VM_IMAGE="${WORK_DIR}/lio.qcow2"
readonly SEED_IMAGE="${WORK_DIR}/seed.img"
readonly VENDOR_DATA="${WORK_DIR}/vendor-data"
readonly QEMU_LOG="${WORK_DIR}/qemu.log"
readonly PID_FILE="${WORK_DIR}/qemu.pid"

case "${TEST_MODE}" in
  plain|chap|crc) ;;
  *)
    echo "unsupported LIO test mode: ${TEST_MODE}" >&2
    exit 2
    ;;
esac

mkdir -p "${WORK_DIR}"
qemu-img create -q -f qcow2 -F qcow2 -b "${BASE_IMAGE}" "${VM_IMAGE}" 8G
printf '#cloud-config\nwrite_files:\n  - path: /etc/lio-test-mode\n    content: %s\n' \
  "${TEST_MODE}" > "${VENDOR_DATA}"
cloud-localds --vendor-data "${VENDOR_DATA}" \
  "${SEED_IMAGE}" ci/lio/user-data ci/lio/meta-data

qemu-system-x86_64 \
  -accel tcg \
  -machine q35 \
  -cpu max \
  -smp 2 \
  -m 2048 \
  -drive "file=${VM_IMAGE},if=virtio,format=qcow2" \
  -drive "file=${SEED_IMAGE},if=virtio,format=raw" \
  -device virtio-net-pci,netdev=net0 \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:3261-:3260 \
  -display none \
  -serial "file:${QEMU_LOG}" \
  -daemonize \
  -pidfile "${PID_FILE}"

for _ in $(seq 1 360); do
  if nc -z 127.0.0.1 3261; then
    sleep 2
    echo "LIO is accepting connections on 127.0.0.1:3261"
    exit 0
  fi

  if ! kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
    cat "${QEMU_LOG}"
    echo "QEMU exited before LIO became ready" >&2
    exit 1
  fi
  sleep 2
done

cat "${QEMU_LOG}"
echo "Timed out waiting for LIO" >&2
exit 1
