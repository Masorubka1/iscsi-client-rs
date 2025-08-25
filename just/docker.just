# just/docker.just

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
