#!/usr/bin/env bash
set -euo pipefail

readonly BASE_IMAGE_XZ="${1:?usage: start-qemu.sh BASE_IMAGE_XZ HOST_PORT}"
readonly HOST_PORT="${2:-3264}"
readonly WORK_DIR="${RUNNER_TEMP:-/tmp}/iscsi-freebsd-qemu"
readonly VM_IMAGE="${WORK_DIR}/freebsd.qcow2"
readonly BASE_IMAGE="${WORK_DIR}/base.qcow2"
readonly SEED_IMAGE="${WORK_DIR}/seed.img"
readonly USER_DATA="${WORK_DIR}/user-data"
readonly QEMU_LOG="${WORK_DIR}/qemu.log"
readonly PID_FILE="${WORK_DIR}/qemu.pid"
readonly QEMU_ACCEL="${FREEBSD_QEMU_ACCEL:-tcg}"

case "${QEMU_ACCEL}" in
  kvm)
    if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
      echo "KVM requested, but /dev/kvm is not accessible" >&2
      exit 1
    fi
    readonly QEMU_CPU="host"
    ;;
  tcg)
    readonly QEMU_CPU="max"
    ;;
  *)
    echo "unsupported QEMU accelerator: ${QEMU_ACCEL}" >&2
    exit 2
    ;;
esac

mkdir -p "${WORK_DIR}"
xz -dc "${BASE_IMAGE_XZ}" > "${BASE_IMAGE}"
qemu-img create -q -f qcow2 -F qcow2 -b "${BASE_IMAGE}" "${VM_IMAGE}" 8G
cp ci/freebsd/user-data "${USER_DATA}"
cloud-localds "${SEED_IMAGE}" "${USER_DATA}" ci/freebsd/meta-data

qemu-system-x86_64 \
  -accel "${QEMU_ACCEL}" \
  -machine q35 \
  -cpu "${QEMU_CPU}" \
  -smp 2 \
  -m 2048 \
  -drive "file=${VM_IMAGE},if=virtio,format=qcow2" \
  -cdrom "${SEED_IMAGE}" \
  -device virtio-net-pci,netdev=net0 \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:${HOST_PORT}-:3260 \
  -display none \
  -serial "file:${QEMU_LOG}" \
  -daemonize \
  -pidfile "${PID_FILE}"

for attempt in $(seq 1 300); do
  if grep -q "FREEBSD_CTLD_READY" "${QEMU_LOG}"; then
    if ! nc -z 127.0.0.1 "${HOST_PORT}"; then
      cat "${QEMU_LOG}"
      echo "cloud-init completed, but ctld is not accepting connections" >&2
      exit 1
    fi
    echo "FreeBSD ctld is accepting connections on 127.0.0.1:${HOST_PORT}"
    exit 0
  fi

  if ! kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
    cat "${QEMU_LOG}"
    echo "QEMU exited before FreeBSD ctld became ready" >&2
    exit 1
  fi

  if (( attempt % 15 == 0 )); then
    echo "Waiting for FreeBSD cloud-init (${attempt}/300)..."
  fi
  sleep 2
done

cat "${QEMU_LOG}"
echo "Timed out waiting for FreeBSD ctld" >&2
exit 1
