#!/usr/bin/env bash

set -euo pipefail

readonly ISO_PATH="${1:-}"
readonly HOST_PORT="${2:?usage: start-qemu.sh ISO_PATH HOST_PORT [full|prepared]}"
readonly START_MODE="${3:-full}"

readonly WORK_DIR="${RUNNER_TEMP:-/tmp}/iscsi-truenas-qemu"
readonly SYSTEM_DISK="${WORK_DIR}/system.qcow2"
readonly DATA_DISK="${WORK_DIR}/data.qcow2"
readonly QEMU_LOG="${WORK_DIR}/qemu.log"
readonly PID_FILE="${WORK_DIR}/qemu.pid"
readonly MONITOR_SOCKET="${WORK_DIR}/monitor.sock"
readonly API_PORT="${TRUENAS_API_PORT:-8084}"
readonly ROOT_PASSWORD="${TRUENAS_ROOT_PASSWORD:-truenasRoot123}"
readonly QEMU_ACCEL="${TRUENAS_QEMU_ACCEL:-tcg}"

case "${START_MODE}" in
  full|prepared) ;;
  *)
    echo "unsupported start mode: ${START_MODE}" >&2
    exit 1
    ;;
esac

if [[ "${START_MODE}" == "full" && -z "${ISO_PATH}" ]]; then
  echo "usage: start-qemu.sh ISO_PATH HOST_PORT [full|prepared]" >&2
  exit 1
fi

case "${QEMU_ACCEL}" in
  kvm)
    readonly QEMU_CPU="host"
    ;;
  tcg)
    readonly QEMU_CPU="max"
    ;;
  *)
    echo "unsupported QEMU accelerator: ${QEMU_ACCEL}" >&2
    exit 1
    ;;
esac

wait_for_port() {
  local port="$1"
  local label="$2"

  for attempt in $(seq 1 240); do
    if nc -z 127.0.0.1 "${port}" >/dev/null 2>&1; then
      echo "${label} is reachable on 127.0.0.1:${port}"
      return 0
    fi

    if [[ -f "${PID_FILE}" ]] && ! kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
      cat "${QEMU_LOG}" || true
      echo "QEMU exited before ${label} became ready" >&2
      return 1
    fi

    if (( attempt % 6 == 0 )); then
      echo "Waiting for ${label} (${attempt}/240)..."
    fi
    sleep 5
  done

  cat "${QEMU_LOG}" || true
  echo "Timed out waiting for ${label}" >&2
  return 1
}

wait_for_ws() {
  local url="$1"
  local label="$2"

  for attempt in $(seq 1 240); do
    if python3 ci/truenas/probe_ws.py --url "${url}" --timeout 5 >/dev/null 2>&1; then
      echo "${label} is reachable via websocket"
      return 0
    fi

    if [[ -f "${PID_FILE}" ]] && ! kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
      cat "${QEMU_LOG}" || true
      echo "QEMU exited before ${label} became ready" >&2
      return 1
    fi

    if (( attempt % 6 == 0 )); then
      echo "Waiting for ${label} websocket (${attempt}/240)..."
    fi
    sleep 5
  done

  cat "${QEMU_LOG}" || true
  echo "Timed out waiting for ${label} websocket" >&2
  return 1
}

wait_for_exit() {
  local label="$1"
  for attempt in $(seq 1 120); do
    if [[ ! -f "${PID_FILE}" ]]; then
      return 0
    fi
    if ! kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
      rm -f "${PID_FILE}"
      return 0
    fi
    if (( attempt % 6 == 0 )); then
      echo "Waiting for ${label} to exit (${attempt}/120)..."
    fi
    sleep 5
  done

  cat "${QEMU_LOG}" || true
  echo "Timed out waiting for ${label} to exit" >&2
  return 1
}

start_vm() {
  local mode="$1"

  : > "${QEMU_LOG}"
  rm -f "${PID_FILE}"
  rm -f "${MONITOR_SOCKET}"

  local cdrom_args=()
  if [[ "${mode}" == "installer" ]]; then
    cdrom_args=(-cdrom "${ISO_PATH}" -boot order=d)
  else
    cdrom_args=(-boot order=c)
  fi

  qemu-system-x86_64 \
    -accel "${QEMU_ACCEL}" \
    -m 8192 \
    -cpu "${QEMU_CPU}" \
    -smp 4 \
    -display none \
    -daemonize \
    -pidfile "${PID_FILE}" \
    -monitor "unix:${MONITOR_SOCKET},server,nowait" \
    -serial "file:${QEMU_LOG}" \
    -drive "if=virtio,format=qcow2,file=${SYSTEM_DISK}" \
    -drive "if=virtio,format=qcow2,file=${DATA_DISK}" \
    "${cdrom_args[@]}" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${API_PORT}-:80,hostfwd=tcp:127.0.0.1:${HOST_PORT}-:3260" \
    -device virtio-net-pci,netdev=net0
}

bash ci/truenas/stop-qemu.sh >/dev/null 2>&1 || true

mkdir -p "${WORK_DIR}"
rm -f "${QEMU_LOG}" "${PID_FILE}"

if [[ "${START_MODE}" == "prepared" ]]; then
  if [[ ! -f "${SYSTEM_DISK}" || ! -f "${DATA_DISK}" ]]; then
    echo "prepared mode requires existing ${SYSTEM_DISK} and ${DATA_DISK}" >&2
    exit 1
  fi

  start_vm system
  wait_for_port "${API_PORT}" "TrueNAS middleware API"
  wait_for_ws "ws://127.0.0.1:${API_PORT}/api/current" "TrueNAS middleware API"
  wait_for_port "${HOST_PORT}" "TrueNAS iSCSI target"
  exit 0
fi

rm -f "${SYSTEM_DISK}" "${DATA_DISK}"
qemu-img create -q -f qcow2 "${SYSTEM_DISK}" 32G
qemu-img create -q -f qcow2 "${DATA_DISK}" 8G

start_vm installer
wait_for_port "${API_PORT}" "TrueNAS installer API"
wait_for_ws "ws://127.0.0.1:${API_PORT}/ws" "TrueNAS installer API"

python3 ci/truenas/install_truenas.py \
  --url "ws://127.0.0.1:${API_PORT}/ws" \
  --password "${ROOT_PASSWORD}"

wait_for_exit "TrueNAS installer VM"

start_vm system
wait_for_port "${API_PORT}" "TrueNAS middleware API"
wait_for_ws "ws://127.0.0.1:${API_PORT}/api/current" "TrueNAS middleware API"

python3 ci/truenas/bootstrap_truenas.py \
  --url "ws://127.0.0.1:${API_PORT}/api/current" \
  --password "${ROOT_PASSWORD}"

wait_for_port "${HOST_PORT}" "TrueNAS iSCSI target"
