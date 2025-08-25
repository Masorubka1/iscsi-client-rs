# just/util.just

# Ждём, пока порт станет доступным
wait-port host port:
	#!/usr/bin/env bash
	set -eu -o pipefail
	for i in {1..200}; do
	if nc -z {{host}} {{port}} >/dev/null 2>&1; then
	echo "✅ {{host}}:{{port}} is up"
	exit 0
	fi
	sleep 0.1
	done
	echo "❌ timeout waiting {{host}}:{{port}}" >&2
	exit 1
