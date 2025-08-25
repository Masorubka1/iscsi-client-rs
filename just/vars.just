# just/vars.just
set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# --- target defaults ---
TGT_IQN      := "iqn.2025-08.example:disk0"
TGT_SIZE_MB  := "200"
TGT_LUN      := "1"
TGT_PGT      := "1"

# --- target address (docker) ---
ISCSI_ADDR   := "127.0.0.1"
ISCSI_PORT   := "3260"

# --- CHAP creds (optional) ---
ISCSI_USER   := "chapuser"
ISCSI_PASS   := "chapsecret"

# --- mapper (proxy) ---
MAPPER_ADDR  := "127.0.0.1"
MAPPER_PORT  := "36260"
LOG_FILE     := "/tmp/iscsi-mapper.log"
