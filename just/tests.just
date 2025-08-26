# just/tests.just
#
# Integration tests that rely solely on TEST_CONFIG.
# We auto-pick a config per target if cfg=... is not provided:
#   tgt -> tests/config.tgt.yaml (if present) else tests/config.yaml
#   lio -> tests/config.lio.yaml (if present) else tests/config.yaml

# ---- Regular integration tests (sequential) ----
test impl="tgt" cfg="":
	@set -euo pipefail; \
	case "{{impl}}" in \
	  tgt) \
	    CFG="{{cfg}}"; [ -z "$$CFG" ] && { [ -f tests/config.tgt.yaml ] && CFG=tests/config.tgt.yaml || CFG=tests/config.yaml; }; \
	    echo "▶️  Up tgt..."; \
	    just -f just/docker.just up tgt; \
	    echo "🧪 Run tests (tgt) with $$CFG"; \
	    TEST_CONFIG="$$CFG" cargo test --tests integration -- --nocapture; \
	    echo "⬇️  Down tgt..."; \
	    just -f just/docker.just down tgt ;; \
	  lio) \
	    CFG="{{cfg}}"; [ -z "$$CFG" ] && { [ -f tests/config.lio.yaml ] && CFG=tests/config.lio.yaml || CFG=tests/config.yaml; }; \
	    echo "▶️  Up lio..."; \
	    just -f just/docker.just up lio; \
	    echo "🧪 Run tests (lio) with $$CFG"; \
	    TEST_CONFIG="$$CFG" cargo test --tests integration -- --nocapture; \
	    echo "⬇️  Down lio..."; \
	    just -f just/docker.just down lio ;; \
	  both) \
	    CFG_TGT="{{cfg}}"; [ -z "$$CFG_TGT" ] && { [ -f tests/config.tgt.yaml ] && CFG_TGT=tests/config.tgt.yaml || CFG_TGT=tests/config.yaml; }; \
	    CFG_LIO="{{cfg}}"; [ -z "$$CFG_LIO" ] && { [ -f tests/config.lio.yaml ] && CFG_LIO=tests/config.lio.yaml || CFG_LIO=tests/config.yaml; }; \
	    echo "▶️  Up tgt + lio..."; \
	    just -f just/docker.just up both; \
	    echo "🧪 Run tests (tgt) with $$CFG_TGT"; \
	    TEST_CONFIG="$$CFG_TGT" cargo test --tests integration -- --nocapture; \
	    echo "🧪 Run tests (lio) with $$CFG_LIO"; \
	    TEST_CONFIG="$$CFG_LIO" cargo test --tests integration -- --nocapture; \
	    echo "⬇️  Down both..."; \
	    just -f just/docker.just down both ;; \
	  *) echo "unknown '{{impl}}' (use: tgt|lio|both)"; exit 1 ;; \
	esac

# ---- Parallel run against both targets (two cargo processes) ----
# Uses distinct CARGO_TARGET_DIRs to avoid build-lock collisions.
test-par cfg_tgt="" cfg_lio="":
	@set -euo pipefail; \
	CT="{{cfg_tgt}}"; [ -z "$$CT" ] && { [ -f docker/tgt/config.tgt.yaml ] && CT=docker/tgt/config.tgt.yaml || CT=docker/tgt/config.tgt.yaml; }; \
	CL="{{cfg_lio}}"; [ -z "$$CL" ] && { [ -f docker/lio/config.lio.yaml ] && CL=docker/lio/config.lio.yaml || CL=docker/lio/config.lio.yaml; }; \
	echo "▶️  Up tgt + lio..."; \
	just -f just/docker.just up both; \
	echo "🧪 Parallel: tgt($$CT) & lio($$CL)"; \
	( CARGO_TARGET_DIR=target-tgt TEST_CONFIG="$$CT" cargo test --tests integration -- --nocapture ) & PID1=$$!; \
	( CARGO_TARGET_DIR=target-lio TEST_CONFIG="$$CL" cargo test --tests integration -- --nocapture ) & PID2=$$!; \
	set +e; wait $$PID1; S1=$$?; wait $$PID2; S2=$$?; set -e; \
	echo "⬇️  Down both..."; \
	just -f just/docker.just down both; \
	test $$S1 -eq 0 -a $$S2 -eq 0

# ---- CHAP-enabled tests ----
# Assumes both the target-side CHAP and the initiator creds live in TEST_CONFIG.
test-chap impl="tgt" cfg="":
	@set -euo pipefail; \
	case "{{impl}}" in \
	  tgt) \
	    CFG="{{cfg}}"; [ -z "$$CFG" ] && { [ -f tests/config.tgt.yaml ] && CFG=tests/config.tgt.yaml || CFG=tests/config.yaml; }; \
	    echo "▶️  Up tgt (CHAP)..."; \
	    just -f just/docker.just up tgt; \
	    echo "🧪 Tests (tgt, CHAP) with $$CFG"; \
	    TEST_CONFIG="$$CFG" cargo test --tests integration -- --nocapture; \
	    echo "⬇️  Down tgt..."; \
	    just -f just/docker.just down tgt ;; \
	  lio) \
	    CFG="{{cfg}}"; [ -z "$$CFG" ] && { [ -f tests/config.lio.yaml ] && CFG=tests/config.lio.yaml || CFG=tests/config.yaml; }; \
	    echo "▶️  Up lio (CHAP)..."; \
	    just -f just/docker.just up lio; \
	    echo "🧪 Tests (lio, CHAP) with $$CFG"; \
	    TEST_CONFIG="$$CFG" cargo test --tests integration -- --nocapture; \
	    echo "⬇️  Down lio..."; \
	    just -f just/docker.just down lio ;; \
	  *) echo "unknown '{{impl}}' (use: tgt|lio)"; exit 1 ;; \
	esac
