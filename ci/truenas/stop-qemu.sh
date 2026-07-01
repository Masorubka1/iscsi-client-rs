#!/usr/bin/env bash

set -euo pipefail

readonly WORK_DIR="${RUNNER_TEMP:-/tmp}/iscsi-truenas-qemu"
readonly PID_FILE="${WORK_DIR}/qemu.pid"
readonly MONITOR_SOCKET="${WORK_DIR}/monitor.sock"

wait_for_pid_exit() {
  local pid="$1"
  for _ in $(seq 1 24); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
    sleep 5
  done
  return 1
}

if [[ -f "${PID_FILE}" ]]; then
  pid="$(cat "${PID_FILE}")"
  if [[ -S "${MONITOR_SOCKET}" ]]; then
    printf 'system_powerdown\n' | nc -U "${MONITOR_SOCKET}" >/dev/null 2>&1 || true
    wait_for_pid_exit "${pid}" || true
  fi

  kill "${pid}" 2>/dev/null || true
  wait "${pid}" 2>/dev/null || true
  rm -f "${PID_FILE}"
fi

if pids="$(pgrep -f "qemu-system-x86_64.*iscsi-truenas-qemu" || true)"; then
  if [[ -n "${pids}" ]]; then
    while read -r pid; do
      kill "${pid}" 2>/dev/null || true
    done <<< "${pids}"
  fi
fi

if [[ -f "${WORK_DIR}/qemu.log" ]]; then
  cat "${WORK_DIR}/qemu.log"
fi
