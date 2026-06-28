TrueNAS runs differently from LIO because there is no ready cloud image.

Current local plan:
- boot the official ISO in QEMU
- drive the installer over `/ws`
- reboot into the installed system
- bootstrap pool + zvol + iSCSI target over `/api/current`
- reuse `tests/configs/truenas/*.yaml`

Files in this directory:
- `start-qemu.sh`: two-phase install + bootstrap flow
- `stop-qemu.sh`: stop helper
- `install_truenas.py`: installer-side automation
- `bootstrap_truenas.py`: middleware-side iSCSI bootstrap
- `ws_client.py`: tiny dependency-free websocket client

Tracked first mode:
- `plain`
