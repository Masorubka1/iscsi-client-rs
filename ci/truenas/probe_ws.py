#!/usr/bin/env python3

import argparse

from ws_client import WebSocketClient


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    client = WebSocketClient(args.url, timeout=args.timeout)
    client.connect()
    client.close()


if __name__ == "__main__":
    main()
