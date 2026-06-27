# Docker Compose runs the userspace TGT server. LIO requires its own kernel and
# is tested in QEMU by the GitHub Actions workflow.

up:
	docker compose --profile tgt up -d --build --wait --wait-timeout 60

down:
	docker compose --profile tgt down -v

logs:
	docker compose logs -f iscsi-target

ps:
	docker compose ps

rebuild:
	docker compose build --no-cache iscsi-target
