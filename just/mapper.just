# just/mapper.just

mapper-up: up
	#!/usr/bin/env bash
	set -eu -o pipefail
	just wait-port {{ISCSI_ADDR}} {{ISCSI_PORT}}
	echo "▶️  starting mapper on {{MAPPER_ADDR}}:{{MAPPER_PORT}} → {{ISCSI_ADDR}}:{{ISCSI_PORT}}"
	RUST_LOG=debug \
	MAPPER_LISTEN={{MAPPER_ADDR}}:{{MAPPER_PORT}} TARGET_ADDR={{ISCSI_ADDR}}:{{ISCSI_PORT}} \
	  nohup cargo run --bin iscsi_mapper >"{{LOG_FILE}}" 2>&1 &
	echo $! > .mapper.pid
	just wait-port {{MAPPER_ADDR}} {{MAPPER_PORT}}

mapper-down:
	@[ -f .mapper.pid ] && { echo "⏹  stopping mapper (pid $(cat .mapper.pid))"; kill "$(cat .mapper.pid)" || true; rm -f .mapper.pid; } || true

mapper-logs:
	@tail -n +1 -f {{LOG_FILE}}

cu-list:
	@iscsi-test-cu --list

cu TEST_PATTERN="SCSI.TestUnitReady.*" CU_ARGS="":
	#!/usr/bin/env bash
	set -eu -o pipefail
	trap 'if [ -f .tail.pid ]; then kill "$(cat .tail.pid)" || true; rm -f .tail.pid; fi; just mapper-down; just down' EXIT
	just mapper-up
	tail -n +1 -f "{{LOG_FILE}}" &
	echo $! > .tail.pid

	TP="{{TEST_PATTERN}}"; TP="${TP#TEST_PATTERN=}"
	ARGS="{{CU_ARGS}}";   ARGS="${ARGS#CU_ARGS=}"

	echo "▶️  iscsi-test-cu: TEST_PATTERN=${TP} CU_ARGS=${ARGS}"
	iscsi-test-cu ${ARGS} \
	  -i "{{TGT_IQN}}-initiator" \
	  --test="${TP}" \
	  "iscsi://{{MAPPER_ADDR}}:{{MAPPER_PORT}}/{{TGT_IQN}}/{{TGT_LUN}}"

cu-chap TEST_PATTERN="SCSI.TestUnitReady.*" CU_ARGS="":
	#!/usr/bin/env bash
	set -eu -o pipefail
	trap 'if [ -f .tail.pid ]; then kill "$(cat .tail.pid)" || true; rm -f .tail.pid; fi; just mapper-down; just down' EXIT
	just mapper-up
	tail -n +1 -f "{{LOG_FILE}}" &
	echo $! > .tail.pid

	TP="{{TEST_PATTERN}}"; TP="${TP#TEST_PATTERN=}"
	ARGS="{{CU_ARGS}}";   ARGS="${ARGS#CU_ARGS=}"

	echo "🔐  iscsi-test-cu (CHAP): TEST_PATTERN=${TP} CU_ARGS=${ARGS}"
	LIBISCSI_CHAP_USERNAME="{{ISCSI_USER}}" \
	LIBISCSI_CHAP_PASSWORD="{{ISCSI_PASS}}" \
	iscsi-test-cu ${ARGS} \
	  -i "{{TGT_IQN}}-initiator" \
	  --test="${TP}" \
	  "iscsi://{{MAPPER_ADDR}}:{{MAPPER_PORT}}/{{TGT_IQN}}/{{TGT_LUN}}"
