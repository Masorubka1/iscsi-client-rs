# Release notes are generated from Conventional Commit messages via git-cliff.

release-notes-preview:
	@command -v git-cliff >/dev/null || { echo "git-cliff is required: cargo install git-cliff --locked"; exit 1; }
	git-cliff --unreleased

release-notes tag="":
	@command -v git-cliff >/dev/null || { echo "git-cliff is required: cargo install git-cliff --locked"; exit 1; }
	@if [ -n "{{tag}}" ]; then \
	  git-cliff --tag "{{tag}}" -o RELEASE_NOTES.md; \
	else \
	  git-cliff --unreleased -o RELEASE_NOTES.md; \
	fi
