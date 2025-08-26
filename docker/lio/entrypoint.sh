#!/bin/sh
set -e

# --- Ensure configfs exists & is mounted ---
if ! grep -q '^configfs' /proc/filesystems; then
  echo "❌ Kernel has no configfs support."
  exit 1
fi
# Mount configfs if not mounted yet
if [ ! -d /sys/kernel/config ]; then
  mkdir -p /sys/kernel/config
fi
if ! mountpoint -q /sys/kernel/config; then
  mount -t configfs none /sys/kernel/config || {
    echo "❌ Failed to mount configfs at /sys/kernel/config"
    exit 1
  }
fi

# --- Verify LIO kernel modules availability (or built-in) ---
# Dry-run first (works if module present), then try to load (ok if built-in).
if ! modprobe -n -v target_core_mod >/dev/null 2>&1 || \
   ! modprobe -n -v iscsi_target_mod >/dev/null 2>&1; then
  echo "❌ LIO modules (target_core_mod, iscsi_target_mod) are not available for this kernel."
  echo "   On Docker Desktop (linuxkit) LIO is not supported."
  exit 1
fi
modprobe target_core_mod || true
modprobe iscsi_target_mod || true

# --- Params ---
IQN="${LIO_IQN:-iqn.2025-08.example:disk0}"
SIZE_MB="${LIO_SIZE_MB:-1000}"
LUN="${LIO_LUN:-1}"
PORT="${LIO_PORT:-3261}"

# --- Backing file ---
if [ ! -f /data/backing.img ]; then
  mkdir -p /data
  dd if=/dev/zero of=/data/backing.img bs=1M count="${SIZE_MB}"
fi

echo "📦 Backstore: /data/backing.img (${SIZE_MB} MiB)"
echo "🎯 Target:    ${IQN}, LUN=${LUN}, PORT=${PORT}"

# --- targetcli config (idempotent) ---
targetcli /backstores/fileio create name=backing file_or_dev=/data/backing.img 2>/dev/null || true
targetcli /iscsi create "${IQN}" 2>/dev/null || true
targetcli /iscsi/"${IQN}"/tpg1/portals create 0.0.0.0 ${PORT} 2>/dev/null || true
targetcli /iscsi/"${IQN}"/tpg1/luns create /backstores/fileio/backing lun=${LUN} 2>/dev/null || true

AUTH_ENABLED=0
if [ -n "${LIO_CHAP_USER}" ] && [ -n "${LIO_CHAP_PASS}" ]; then
  [ -n "${LIO_INITIATORS}" ] || { echo "❌ Set LIO_INITIATORS for CHAP."; exit 1; }
  AUTH_ENABLED=1
  targetcli /iscsi/"${IQN}"/tpg1 set attribute authentication=1
  targetcli /iscsi/"${IQN}"/tpg1 set attribute generate_node_acls=0
  IFS=','; for inq in $LIO_INITIATORS; do
    inq="$(echo "$inq" | xargs)"; [ -z "$inq" ] && continue
    targetcli /iscsi/"${IQN}"/tpg1/acls create "$inq" 2>/dev/null || true
    targetcli /iscsi/"${IQN}"/tpg1/acls/"$inq" set auth userid="${LIO_CHAP_USER}" password="${LIO_CHAP_PASS}"
    if [ -n "${LIO_MUTUAL_USER}" ] && [ -n "${LIO_MUTUAL_PASS}" ]; then
      targetcli /iscsi/"${IQN}"/tpg1/acls/"$inq" set auth mutual_userid="${LIO_MUTUAL_USER}" mutual_password="${LIO_MUTUAL_PASS}"
    fi
  done
else
  targetcli /iscsi/"${IQN}"/tpg1 set attribute authentication=0
  targetcli /iscsi/"${IQN}"/tpg1 set attribute generate_node_acls=1
  targetcli /iscsi/"${IQN}"/tpg1 set attribute demo_mode_write_protect=0
fi

echo "🔒 Auth: $([ "$AUTH_ENABLED" -eq 1 ] && echo 'CHAP' || echo 'disabled')"
mkdir -p /etc/target
targetcli saveconfig /etc/target/saveconfig.json || true

# mark ready for healthcheck
touch /tmp/lio-ready
echo "✅ LIO target ${IQN} is up (port ${PORT})."
tail -f /dev/null
