#!/usr/bin/env python3

import argparse
import time

from ws_client import WebSocketClient, WebSocketError


def wait_for_message(ws: WebSocketClient, request_id: int) -> object:
    while True:
        message = ws.recv_json()
        method = message.get("method")
        if method == "installation_progress":
            payload = (message.get("params") or [{}])[0]
            progress = payload.get("progress")
            description = payload.get("message", "")
            print(f"[install] {progress}% {description}", flush=True)
            continue

        if message.get("id") != request_id:
            continue

        if "error" in message:
            raise WebSocketError(f"install failed: {message['error']}")
        return message.get("result")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--password", required=True)
    args = parser.parse_args()

    ws = WebSocketClient(args.url, timeout=300.0)
    ws.connect()
    try:
        request_id = 1
        ws.send_json({"jsonrpc": "2.0", "id": request_id, "method": "list_disks", "params": []})
        disks = wait_for_message(ws, request_id)
        if not isinstance(disks, list) or len(disks) < 2:
            raise WebSocketError(f"expected at least 2 disks, got: {disks!r}")

        disk_names = sorted(disk["name"] for disk in disks if not disk.get("removable"))
        if len(disk_names) < 2:
            raise WebSocketError(f"expected at least 2 non-removable disks, got: {disk_names!r}")

        request_id += 1
        ws.send_json({"jsonrpc": "2.0", "id": request_id, "method": "list_network_interfaces", "params": []})
        interfaces = wait_for_message(ws, request_id)
        if not isinstance(interfaces, list) or not interfaces:
            raise WebSocketError(f"expected at least 1 network interface, got: {interfaces!r}")

        interface_name = interfaces[0]["name"]
        install_payload = {
            "disks": [disk_names[0]],
            "set_pmbr": False,
            "authentication": {
                "username": "root",
                "password": args.password,
            },
            "post_install": {
                "network_interfaces": [
                    {
                        "name": interface_name,
                        "ipv4_dhcp": True,
                    }
                ]
            },
        }

        request_id += 1
        ws.send_json(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "install",
                "params": [install_payload],
            }
        )
        wait_for_message(ws, request_id)
        print("[install] installation completed", flush=True)

        request_id += 1
        ws.send_json({"jsonrpc": "2.0", "id": request_id, "method": "shutdown", "params": []})
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                message = ws.recv_json()
            except WebSocketError:
                break
            if message.get("id") == request_id:
                break
    finally:
        ws.close()


if __name__ == "__main__":
    main()
