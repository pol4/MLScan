#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Минимальный клиент PostgreSQL на stdlib: SCRAM-SHA-256 + simple query.

Только для внутренних нужд MLScan (без внешних зависимостей). Поддерживает подключение,
SCRAM-аутентификацию и выполнение простых SQL-запросов (execute/query).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import socket
import struct

PROTOCOL_V3 = 196608


class PgError(Exception):
    pass


class Pg:
    def __init__(self, host: str, port: int = 5432, user: str = "mlscan",
                 password: str = "", dbname: str = "mlscan", timeout: int = 30):
        self.host, self.port = host, port
        self.user, self.password, self.dbname = user, password, dbname
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self._buf = b""

    # --- низкий уровень ---
    def _send(self, mtype: bytes, payload: bytes) -> None:
        assert self.sock
        self.sock.sendall(mtype + struct.pack("!i", len(payload) + 4) + payload)

    def _recv_exact(self, n: int) -> bytes:
        assert self.sock
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise PgError("connection closed")
            data += chunk
        return data

    def _recv_msg(self):
        t = self._recv_exact(1)
        (length,) = struct.unpack("!i", self._recv_exact(4))
        payload = self._recv_exact(length - 4)
        return t, payload

    # --- аутентификация ---
    @staticmethod
    def _cstrs(payload: bytes):
        return [s for s in payload.split(b"\x00") if s != b""]

    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        body = struct.pack("!i", PROTOCOL_V3)
        for k, v in (("user", self.user), ("database", self.dbname),
                     ("client_encoding", "UTF8"), ("application_name", "mlscan")):
            body += k.encode() + b"\x00" + v.encode() + b"\x00"
        body += b"\x00"
        self.sock.sendall(struct.pack("!i", len(body) + 4) + body)

        while True:
            t, payload = self._recv_msg()
            if t == b"R":
                (code,) = struct.unpack("!i", payload[:4])
                if code == 0:
                    continue
                if code == 10:  # SASL
                    self._auth_sasl()   # вычитывает до ReadyForQuery
                    return
                if code == 11 or code == 12:
                    continue
                raise PgError(f"unsupported auth code {code}")
            if t == b"E":
                raise PgError(self._error(payload))
            if t == b"Z":
                return

    def _auth_sasl(self) -> None:
        nonce = base64.b64encode(os.urandom(18)).decode()
        client_first_bare = f"n=,r={nonce}"
        client_first = "n,," + client_first_bare
        payload = b"SCRAM-SHA-256\x00" + struct.pack("!i", len(client_first)) + client_first.encode()
        self._send(b"p", payload)

        t, resp = self._recv_msg()
        if t == b"E":
            raise PgError(self._error(resp))
        if t != b"R":
            raise PgError(f"unexpected msg {t}")
        (code,) = struct.unpack("!i", resp[:4])
        if code != 11:
            raise PgError(f"expected SASLContinue, got {code}")
        server_first = resp[4:].decode()
        attrs = dict(kv.split("=", 1) for kv in server_first.split(","))
        salt = base64.b64decode(attrs["s"])
        iterations = int(attrs["i"])

        salted = hashlib.pbkdf2_hmac("sha256", self.password.encode(), salt, iterations)
        client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
        stored_key = hashlib.sha256(client_key).digest()
        client_final_no_proof = f"c=biws,r={attrs['r']}"
        auth_message = f"{client_first_bare},{server_first},{client_final_no_proof}"
        client_sig = hmac.new(stored_key, auth_message.encode(), hashlib.sha256).digest()
        proof = bytes(a ^ b for a, b in zip(client_key, client_sig))
        client_final = client_final_no_proof + ",p=" + base64.b64encode(proof).decode()
        self._send(b"p", client_final.encode())

        t, resp = self._recv_msg()
        if t == b"E":
            raise PgError(self._error(resp))
        # SASLFinal (code 12) затем AuthenticationOk (0) и далее ReadyForQuery
        if t == b"R":
            (c,) = struct.unpack("!i", resp[:4])
            if c == 12:
                server_final = resp[4:]
                _ = server_final  # серверную подпись (v=...) можно проверить при необходимости
        while True:
            t, payload = self._recv_msg()
            if t == b"E":
                raise PgError(self._error(payload))
            if t == b"Z":
                return

    @staticmethod
    def _error(payload: bytes) -> str:
        fields = {}
        for part in payload.split(b"\x00"):
            if part:
                fields[part[:1].decode()] = part[1:].decode(errors="replace")
        return f"{fields.get('S', 'ERROR')}: {fields.get('M', '')}"

    # --- запросы ---
    def query(self, sql: str, params: list | None = None):
        """Простой запрос (Simple Query). Параметры подставлять нельзя — только доверенный SQL."""
        if params:
            raise PgError("params not supported in simple query")
        assert self.sock
        self._send(b"Q", sql.encode() + b"\x00")
        rows: list[list] = []
        cols: list[str] = []
        while True:
            t, payload = self._recv_msg()
            if t == b"T":  # RowDescription
                (n,) = struct.unpack("!h", payload[:2])
                off = 2
                cols = []
                for _ in range(n):
                    end = payload.index(b"\x00", off)
                    cols.append(payload[off:end].decode())
                    off = end + 1 + 18  # skip table oid/attr, type oid/size/mod/format
                continue
            if t == b"D":  # DataRow
                (n,) = struct.unpack("!h", payload[:2])
                off = 2
                row = []
                for _ in range(n):
                    (ln,) = struct.unpack("!i", payload[off:off + 4])
                    off += 4
                    if ln == -1:
                        row.append(None)
                    else:
                        row.append(payload[off:off + ln].decode(errors="replace"))
                        off += ln
                rows.append(row)
                continue
            if t == b"C":  # CommandComplete
                continue
            if t == b"N":  # Notice
                continue
            if t == b"E":
                raise PgError(self._error(payload))
            if t == b"Z":
                return cols, rows

    def execute(self, sql: str):
        return self.query(sql)

    def close(self) -> None:
        try:
            if self.sock:
                self._send(b"X", b"")
                self.sock.close()
        except Exception:  # noqa: BLE001
            pass
        self.sock = None
