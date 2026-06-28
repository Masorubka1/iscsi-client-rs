TrueNAS is intentionally not wired into the default PR CI yet.

What is already confirmed:
- official downloads currently expose installer ISOs
- unlike the current LIO and FreeBSD jobs, there is no ready cloud-init image

What is missing before enabling it in CI:
- unattended install flow or a reproducible prebuilt VM image
- post-install iSCSI target bootstrap automation
- validation that the boot/install time is acceptable for GitHub-hosted runners

Once that exists, it should follow the same pattern as `ci/lio` and `ci/freebsd`:
- cache the upstream artifact
- boot with QEMU
- wait for an explicit readiness marker on the serial console
- run the normal integration suite with a dedicated `tests/configs/truenas/*.yaml`
