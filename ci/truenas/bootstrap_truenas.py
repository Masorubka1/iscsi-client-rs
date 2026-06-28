#!/usr/bin/env python3

import argparse
import time

from ws_client import JsonRpcClient, WebSocketError


IQN_PREFIX = "iqn.2025-08.com.example"
TARGET_NAME = "disk0"
POOL_NAME = "tank"
ZVOL_NAME = f"{POOL_NAME}/lun0"
PORTAL_COMMENT = "truenas-ci"
EXTENT_NAME = "lun0"


class TrueNasBootstrap:
    def __init__(self, url: str, password: str):
        self.client = JsonRpcClient(url, timeout=30.0)
        self.password = password

    def connect(self) -> None:
        self.client.connect()
        response = self.client.call(
            "auth.login_ex",
            [
                {
                    "mechanism": "PASSWORD_PLAIN",
                    "username": "root",
                    "password": self.password,
                }
            ],
        )
        if not isinstance(response, dict) or response.get("response_type") != "SUCCESS":
            raise WebSocketError(f"auth.login_ex failed: {response!r}")

    def close(self) -> None:
        self.client.close()

    def call(self, method: str, *params):
        return self.client.call(method, list(params))

    def first(self, method: str, filters: list) -> dict | None:
        result = self.call(method, filters, {"limit": 1})
        if not isinstance(result, list):
            raise WebSocketError(f"{method} returned unexpected value: {result!r}")
        return result[0] if result else None

    def call_job(self, method: str, *params):
        job_id = self.call(method, *params)
        if not isinstance(job_id, int):
            raise WebSocketError(f"{method} did not return job id: {job_id!r}")

        deadline = time.time() + 300
        while time.time() < deadline:
            jobs = self.call("core.get_jobs", [["id", "=", job_id]], {"get": True})
            state = jobs["state"]
            if state == "SUCCESS":
                return jobs.get("result")
            if state in ("FAILED", "ABORTED"):
                raise WebSocketError(f"{method} job failed: {jobs!r}")
            time.sleep(2)

        raise WebSocketError(f"{method} job {job_id} timed out")

    def ensure_basename(self) -> None:
        global_cfg = self.call("iscsi.global.config")
        if global_cfg["basename"] != IQN_PREFIX:
            self.call("iscsi.global.update", {"basename": IQN_PREFIX})

    def ensure_pool(self) -> None:
        pool = self.first("pool.query", [["name", "=", POOL_NAME]])
        if pool:
            return

        unused = self.call("disk.get_unused")
        if not unused:
            raise WebSocketError("disk.get_unused returned no disks for pool creation")

        disk_name = unused[0]["devname"]
        self.call_job(
            "pool.create",
            {
                "name": POOL_NAME,
                "encryption": False,
                "allow_duplicate_serials": True,
                "topology": {
                    "data": [
                        {
                            "type": "STRIPE",
                            "disks": [disk_name],
                        }
                    ]
                },
            },
        )

    def ensure_zvol(self) -> None:
        zvol = self.first("pool.dataset.query", [["id", "=", ZVOL_NAME]])
        if zvol:
            return

        self.call(
            "pool.dataset.create",
            {
                "name": ZVOL_NAME,
                "type": "VOLUME",
                "volsize": 2 * 1024 * 1024 * 1024,
                "force_size": True,
            },
        )

    def ensure_portal(self) -> int:
        portal = self.first("iscsi.portal.query", [["comment", "=", PORTAL_COMMENT]])
        if portal:
            return portal["id"]

        portal = self.call(
            "iscsi.portal.create",
            {
                "comment": PORTAL_COMMENT,
                "listen": [{"ip": "0.0.0.0"}],
            },
        )
        return portal["id"]

    def ensure_target(self, portal_id: int) -> int:
        target = self.first("iscsi.target.query", [["name", "=", TARGET_NAME]])
        if target:
            return target["id"]

        target = self.call(
            "iscsi.target.create",
            {
                "name": TARGET_NAME,
                "groups": [
                    {
                        "portal": portal_id,
                        "initiator": None,
                        "authmethod": "NONE",
                        "auth": None,
                    }
                ],
                "auth_networks": [],
            },
        )
        return target["id"]

    def ensure_extent(self) -> int:
        extent = self.first("iscsi.extent.query", [["name", "=", EXTENT_NAME]])
        if extent:
            return extent["id"]

        extent = self.call(
            "iscsi.extent.create",
            {
                "name": EXTENT_NAME,
                "type": "DISK",
                "disk": f"zvol/{ZVOL_NAME}",
                "serial": "TRUENASCI0001",
                "blocksize": 512,
                "pblocksize": False,
                "insecure_tpc": True,
                "xen": False,
                "rpm": "SSD",
                "ro": False,
                "enabled": True,
            },
        )
        return extent["id"]

    def ensure_mapping(self, target_id: int, extent_id: int) -> None:
        mapping = self.first(
            "iscsi.targetextent.query",
            [["target", "=", target_id], ["extent", "=", extent_id]],
        )
        if mapping:
            return

        self.call(
            "iscsi.targetextent.create",
            {
                "target": target_id,
                "extent": extent_id,
                "lunid": 0,
            },
        )

    def ensure_service_started(self) -> None:
        if self.call("service.started", "iscsitarget"):
            return
        self.call_job("service.control", "START", "iscsitarget")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--password", required=True)
    args = parser.parse_args()

    bootstrap = TrueNasBootstrap(args.url, args.password)
    bootstrap.connect()
    try:
        bootstrap.ensure_basename()
        bootstrap.ensure_pool()
        bootstrap.ensure_zvol()
        portal_id = bootstrap.ensure_portal()
        target_id = bootstrap.ensure_target(portal_id)
        extent_id = bootstrap.ensure_extent()
        bootstrap.ensure_mapping(target_id, extent_id)
        bootstrap.ensure_service_started()
    finally:
        bootstrap.close()


if __name__ == "__main__":
    main()
