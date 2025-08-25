# just/cleanup.just

nuke:
	just mapper-down || true
	just down || true
	docker system prune -f
