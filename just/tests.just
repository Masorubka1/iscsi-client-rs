# just/tests.just

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
