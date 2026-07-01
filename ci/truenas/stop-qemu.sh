#!/usr/bin/env bash

set -euo pipefail

readonly WORK_DIR="${RUNNER_TEMP:-/tmp}/iscsi-truenas-qemu"
readonly PID_FILE="${WORK_DIR}/qemu.pid"

if [[ -f "${PID_FILE}" ]]; then
  pid="$(cat "${PID_FILE}")"
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
