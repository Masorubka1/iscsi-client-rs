# Integration tests against the userspace TGT Docker server.

test cfg="":
	@set -euo pipefail; \
	CFG="{{cfg}}"; \
	[ -z "$CFG" ] && CFG=tests/configs/tgt/plain.yaml; \
	trap 'just -f just/docker.just down' EXIT; \
	echo "Up TGT..."; \
	just -f just/docker.just up iscsi-target-plain; \
	echo "Run integration tests with $CFG"; \
	TEST_CONFIG="$CFG" cargo test --test integration -- --nocapture --test-threads=1

test-chap cfg="":
	@set -euo pipefail; \
	CFG="{{cfg}}"; \
	[ -z "$CFG" ] && CFG=tests/configs/tgt/chap.yaml; \
	trap 'just -f just/docker.just down' EXIT; \
	just -f just/docker.just up iscsi-target-chap; \
	TEST_CONFIG="$CFG" cargo test --test integration -- --nocapture --test-threads=1

test-crc cfg="":
	@set -euo pipefail; \
	CFG="{{cfg}}"; \
	[ -z "$CFG" ] && CFG=tests/configs/tgt/crc.yaml; \
	trap 'just -f just/docker.just down' EXIT; \
	just -f just/docker.just up iscsi-target-crc; \
	TEST_CONFIG="$CFG" cargo test --test integration -- --nocapture --test-threads=1
