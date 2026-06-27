# Integration tests against the userspace TGT Docker server.

test cfg="":
	@set -euo pipefail; \
	CFG="{{cfg}}"; \
	[ -z "$CFG" ] && { [ -f tests/config.tgt.yaml ] && CFG=tests/config.tgt.yaml || CFG=tests/config.yaml; }; \
	trap 'just -f just/docker.just down' EXIT; \
	echo "Up TGT..."; \
	just -f just/docker.just up; \
	echo "Run integration tests with $CFG"; \
	TEST_CONFIG="$CFG" cargo test --test integration -- --nocapture

test-chap cfg="":
	@set -euo pipefail; \
	CFG="{{cfg}}"; \
	[ -z "$CFG" ] && CFG=tests/config.yaml; \
	trap 'just -f just/docker.just down' EXIT; \
	just -f just/docker.just up; \
	TEST_CONFIG="$CFG" cargo test --test integration -- --nocapture
