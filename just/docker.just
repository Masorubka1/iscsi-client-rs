# Docker Compose runs the userspace TGT server. LIO requires its own kernel and
# is tested in QEMU by the GitHub Actions workflow.

up services="iscsi-target-plain iscsi-target-chap iscsi-target-crc":
	docker compose --profile tgt up -d --build --wait --wait-timeout 60 {{services}}

down:
	docker compose --profile tgt down -v

logs services="iscsi-target-plain iscsi-target-chap iscsi-target-crc":
	docker compose logs -f {{services}}

ps:
	docker compose ps

rebuild services="iscsi-target-plain iscsi-target-chap iscsi-target-crc":
	docker compose build --no-cache {{services}}
