# Justfile (root)
import "just/vars.just"
import "just/util.just"
import "just/docker.just"
import "just/tests.just"
import "just/mapper.just"
import "just/cleanup.just"

@default:
  just --list
