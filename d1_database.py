"""Small synchronous DB-API compatibility layer over Cloudflare D1.

The Flask app is synchronous (WSGI), while the Workers D1 binding is async.
run_sync bridges the binding calls from the synchronous Flask request handler.
"""
from __future__ import annotations

import sqlite3
from flask import request
from pyodide.ffi import run_sync, to_py


def _plain(value):
    try:
        return to_py(value)
    except Exception:
        return value


class D1Cursor:
    def __init__(self, binding):
        self.binding = binding
        self._rows = []
        self._index = 0
        self.lastrowid = None
        self.rowcount = -1

    def execute(self, sql, params=()):
        statement = self.binding.prepare(sql)
        if params:
            statement = statement.bind(*tuple(params))
        try:
            raw = run_sync(statement.run())
            result = _plain(raw) or {}
        except Exception as exc:
            message = str(exc)
            if "UNIQUE constraint failed" in message or "constraint failed" in message:
                raise sqlite3.IntegrityError(message) from exc
            raise
        if not isinstance(result, dict):
            result = _plain(result) or {}
        self._rows = list(result.get("results") or [])
        self._index = 0
        meta = result.get("meta") or {}
        self.lastrowid = meta.get("last_row_id")
        self.rowcount = int(meta.get("changes") or 0)
        return self

    def fetchone(self):
        if self._index >= len(self._rows):
            return None
        row = _plain(self._rows[self._index])
        self._index += 1
        return dict(row) if row is not None else None

    def fetchall(self):
        rows = [dict(_plain(row)) for row in self._rows[self._index:]]
        self._index = len(self._rows)
        return rows

    def __iter__(self):
        while True:
            row = self.fetchone()
            if row is None:
                break
            yield row


class D1Connection:
    def __init__(self):
        env = request.environ.get("workers.env")
        if env is None or getattr(env, "DB", None) is None:
            raise RuntimeError("Cloudflare D1 binding DB is not available in this request.")
        self.binding = env.DB

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        # D1 commits each successful statement. Multi-statement workflows
        # should use D1 batch transactions when atomicity is required.
        return False

    def execute(self, sql, params=()):
        return D1Cursor(self.binding).execute(sql, params)

    def executescript(self, script):
        cursor = None
        for statement in script.split(";"):
            if statement.strip():
                cursor = self.execute(statement)
        return cursor

    def close(self):
        return None
