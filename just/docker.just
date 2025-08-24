# just/docker.just
#
# Control Docker Compose profiles:
# - impl: which target to run: tgt | lio | both
# - lio_port: TCP port for LIO (kernel target), default 3261
#
# Notes:
# - TGT runs in userspace and exposes 3260 via `ports`.
# - LIO runs in the host network namespace; set LIO_PORT to avoid clashes.
# - `--wait` waits for healthchecks defined in your compose file.

up impl="tgt" lio_port="3261":
	@case "{{impl}}" in \
	  tgt) \
	    echo "▶️  up: tgt (3260)"; \
	    docker compose --profile tgt up -d --build --wait --wait-timeout 60 \
	    ;; \
	  lio) \
	    echo "▶️  up: lio ({{lio_port}})"; \
	    LIO_PORT={{lio_port}} docker compose --profile lio up -d --build --wait --wait-timeout 60 \
	    ;; \
	  both) \
	    echo "▶️  up: tgt(3260) + lio({{lio_port}})"; \
	    LIO_PORT={{lio_port}} docker compose --profile tgt --profile lio up -d --build --wait --wait-timeout 60 \
	    ;; \
	  *) echo "unknown impl='{{impl}}' (use: tgt|lio|both)"; exit 1 ;; \
	esac

down impl="tgt":
	@case "{{impl}}" in \
	  tgt)  docker compose --profile tgt down -v ;; \
	  lio)  docker compose --profile lio down -v ;; \
	  both) docker compose --profile tgt --profile lio down -v ;; \
	  *) echo "unknown impl='{{impl}}' (use: tgt|lio|both)"; exit 1 ;; \
	esac

logs impl="tgt":
	@case "{{impl}}" in \
	  tgt)  docker compose logs -f iscsi-target ;; \
	  lio)  docker compose logs -f iscsi-lio ;; \
	  both) docker compose logs -f ;; \
	  *) echo "unknown impl='{{impl}}' (use: tgt|lio|both)"; exit 1 ;; \
	esac

ps:
	docker compose ps

rebuild impl="both":
	@case "{{impl}}" in \
	  tgt)  docker compose build --no-cache iscsi-target ;; \
	  lio)  docker compose build --no-cache iscsi-lio ;; \
	  both) docker compose build --no-cache ;; \
	  *) echo "unknown impl='{{impl}}' (use: tgt|lio|both)"; exit 1 ;; \
	esac
