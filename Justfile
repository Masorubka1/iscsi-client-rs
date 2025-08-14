set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

TGT_IQN      := "iqn.2025-08.example:disk0"
TGT_SIZE_MB  := "200"
TGT_LUN      := "1"
TGT_PGT      := "1"

ISCSI_ADDR   := "127.0.0.1"
ISCSI_PORT   := "3260"

ISCSI_USER   := "chapuser"
ISCSI_PASS   := "chapsecret"

@default:
	just --list

# ===== Docker Compose lifecycle =====
up:
	docker compose up -d --build --wait --wait-timeout 60

down:
	docker compose down -v

logs:
	docker compose logs -f

ps:
	docker compose ps

rebuild:
	docker compose build --no-cache

# ===== Tests =====
test: up
	ISCSI_ADDR={{ISCSI_ADDR}} ISCSI_PORT={{ISCSI_PORT}} ISCSI_TARGET={{TGT_IQN}} \
	cargo test --tests integration -- --nocapture
	just down

test-chap:
	TGT_CHAP_USER={{ISCSI_USER}} TGT_CHAP_PASS={{ISCSI_PASS}} \
	TGT_IQN={{TGT_IQN}} TGT_SIZE_MB={{TGT_SIZE_MB}} TGT_LUN={{TGT_LUN}} TGT_PGT={{TGT_PGT}} \
	docker compose up -d --build --wait --wait-timeout 60
	ISCSI_USER={{ISCSI_USER}} ISCSI_PASS={{ISCSI_PASS}} \
	ISCSI_ADDR={{ISCSI_ADDR}} ISCSI_PORT={{ISCSI_PORT}} ISCSI_TARGET={{TGT_IQN}} \
	cargo test --tests integration -- --nocapture
	just down

nuke:
	just down || true
	docker system prune -f
