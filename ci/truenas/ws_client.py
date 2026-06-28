#!/usr/bin/env python3

import base64
import hashlib
import json
import os
import socket
import struct
from urllib.parse import urlparse


class WebSocketError(RuntimeError):
    pass


class WebSocketClient:
    def __init__(self, url: str, timeout: float = 10.0):
        self.url = url
        self.timeout = timeout
        self.sock: socket.socket | None = None

    def connect(self) -> None:
        parsed = urlparse(self.url)
        if parsed.scheme != "ws":
            raise WebSocketError(f"unsupported websocket scheme: {parsed.scheme}")

        host = parsed.hostname
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        if not host:
            raise WebSocketError("websocket URL is missing host")

        key = base64.b64encode(os.urandom(16)).decode()
        self.sock = socket.create_connection((host, port), self.timeout)
        self.sock.settimeout(self.timeout)

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        ).encode()
        self.sock.sendall(request)

        response = self._read_http_response()
        if "101" not in response.splitlines()[0]:
            raise WebSocketError(f"websocket handshake failed: {response.splitlines()[0]}")

        headers = {}
        for line in response.split("\r\n")[1:]:
            if not line or ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

        accept = headers.get("sec-websocket-accept")
        expected = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        if accept != expected:
            raise WebSocketError("invalid Sec-WebSocket-Accept in handshake")

    def close(self) -> None:
        if self.sock is None:
            return
        try:
            self._send_frame(0x8, b"")
        except OSError:
            pass
        try:
            self.sock.close()
        finally:
            self.sock = None

    def send_json(self, payload: dict) -> None:
        self.send_text(json.dumps(payload))

    def send_text(self, text: str) -> None:
        self._send_frame(0x1, text.encode())

    def recv_json(self) -> dict:
        return json.loads(self.recv_text())

    def recv_text(self) -> str:
        while True:
            opcode, payload = self._recv_frame()
            if opcode == 0x1:
                return payload.decode()
            if opcode == 0x8:
                raise WebSocketError("websocket closed by peer")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            raise WebSocketError(f"unsupported websocket opcode: {opcode}")

    def _read_http_response(self) -> str:
        assert self.sock is not None
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise WebSocketError("connection closed during handshake")
            data.extend(chunk)
        return data.decode(errors="replace")

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        assert self.sock is not None
        fin_and_opcode = 0x80 | opcode
        mask_bit = 0x80
        length = len(payload)

        header = bytearray([fin_and_opcode])
        if length < 126:
            header.append(mask_bit | length)
        elif length < (1 << 16):
            header.append(mask_bit | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(mask_bit | 127)
            header.extend(struct.pack("!Q", length))

        mask = os.urandom(4)
        masked = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        self.sock.sendall(bytes(header) + mask + masked)

    def _recv_frame(self) -> tuple[int, bytes]:
        assert self.sock is not None
        header = self._recv_exact(2)
        first, second = header[0], header[1]
        fin = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F

        if not fin:
            raise WebSocketError("fragmented websocket frames are not supported")

        if length == 126:
            length = struct.unpack("!H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recv_exact(8))[0]

        mask = self._recv_exact(4) if masked else b""
        payload = self._recv_exact(length)
        if masked:
            payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))

        return opcode, payload

    def _recv_exact(self, size: int) -> bytes:
        assert self.sock is not None
        data = bytearray()
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise WebSocketError("connection closed while reading websocket frame")
            data.extend(chunk)
        return bytes(data)


class JsonRpcClient:
    def __init__(self, url: str, timeout: float = 10.0):
        self.ws = WebSocketClient(url, timeout=timeout)
        self.next_id = 1

    def connect(self) -> None:
        self.ws.connect()

    def close(self) -> None:
        self.ws.close()

    def call(self, method: str, params: list | None = None) -> object:
        request_id = self.next_id
        self.next_id += 1
        self.ws.send_json(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params or [],
            }
        )

        while True:
            message = self.ws.recv_json()
            if message.get("id") != request_id:
                continue
            if "error" in message:
                raise WebSocketError(f"{method} failed: {message['error']}")
            return message.get("result")
