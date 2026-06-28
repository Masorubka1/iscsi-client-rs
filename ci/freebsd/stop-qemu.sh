#!/usr/bin/env bash
set -euo pipefail

readonly WORK_DIR="${RUNNER_TEMP:-/tmp}/iscsi-freebsd-qemu"
readonly PID_FILE="${WORK_DIR}/qemu.pid"

if [[ -f "${PID_FILE}" ]]; then
  kill "$(cat "${PID_FILE}")" 2>/dev/null || true
fi

if [[ -f "${WORK_DIR}/qemu.log" ]]; then
  cat "${WORK_DIR}/qemu.log"
fi
