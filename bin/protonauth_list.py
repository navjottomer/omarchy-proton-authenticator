#!/usr/bin/env python3
"""Emit Proton Authenticator TOTP codes from the local vault (labels+codes only).

Forked from io.github.mapski.proton-authenticator. Instead of one code per
run, each entry carries a window of upcoming codes so the panel can tick
locally and only re-run this helper when the window runs out."""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import selectors
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

__version__ = "2.0.0"

try:
    import pyotp
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError as _imp_err:  # reported as JSON by main()
    _IMPORT_ERROR: ImportError | None = _imp_err
else:
    _IMPORT_ERROR = None

DATA_DIR = Path.home() / ".local/share/me.proton.authenticator"
HKDF_INFO = b"authenticator;storage-key"
ITEM_AAD = b"authenticator;item"
SERVICE = "com.proton.authenticator"
# Absolute path first so a PATH entry can't substitute the keyring client.
SECRET_TOOL = "/usr/bin/secret-tool" if os.path.exists("/usr/bin/secret-tool") else "secret-tool"
ADAPTER_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$")

# Prefix of the private temp dir holding each run's copy of the vault.
TMP_PREFIX = "navauth-idb-"

# Bounds on everything this helper reads from other programs or writes to the
# shell (omarchy-shell buffers our whole stdout, so it must stay small).
HELPER_TIMEOUT_SEC = 20        # whole run; SIGALRM -> HELPER_TIMEOUT JSON
SECRET_TOOL_TIMEOUT_SEC = 10   # a keyring unlock prompt left open, etc.
SECRET_MAX_BYTES = 64          # the vault key is 32 bytes; more is refused
MAX_ENTRIES = 1000
MAX_LABEL_CHARS = 256          # issuer / account, truncated for display
MAX_ID_CHARS = 128
MAX_MESSAGE_CHARS = 200
MAX_OUTPUT_BYTES = 1024 * 1024
# Codes per entry: the current one plus the ones after it. Seeds never leave
# this process; only these short-lived codes do.
DEFAULT_WINDOW = 10
MAX_WINDOW = 20


class Err(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def find_idb() -> Path:
    root = DATA_DIR / "databases" / "indexeddb"
    if not root.exists():
        raise Err("VAULT_UNREADABLE", f"missing IndexedDB under {root}")
    candidates: list[Path] = []
    for p in root.rglob("IndexedDB.sqlite3"):
        try:
            con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
            con.create_collation("IDBKEY", lambda a, b: (a > b) - (a < b))
            names = {r[0] for r in con.execute("SELECT name FROM ObjectStoreInfo")}
            con.close()
            if {"items", "storageKey"} <= names:
                candidates.append(p)
        except (sqlite3.Error, OSError):
            continue
    if not candidates:
        raise Err("VAULT_UNREADABLE", "no IndexedDB with items/storageKey stores")
    return max(candidates, key=lambda p: p.stat().st_mtime)


@contextlib.contextmanager
def vault_snapshot(src: Path):
    """Private read-only copy of the vault DB in a fresh mkdtemp() dir.

    The dir is removed (only that exact path) when the block exits, even on
    errors.
    """
    tmpdir = Path(tempfile.mkdtemp(prefix=TMP_PREFIX))  # unique, 0700, ours
    try:
        tmp = tmpdir / "idb.sqlite3"
        os.close(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))  # 0600 before any data
        src_con = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
        dst_con = sqlite3.connect(tmp)
        try:
            src_con.backup(dst_con)
        finally:
            dst_con.close()
            src_con.close()
        yield tmp
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def extract_arraybuffer_after(marker: bytes, blob: bytes) -> bytes:
    i = blob.find(marker)
    if i < 0:
        raise Err("UNSUPPORTED_SCHEMA", f"missing marker {marker!r}")
    j = i + len(marker)
    if j >= len(blob) or blob[j] != 0x16:
        raise Err("UNSUPPORTED_SCHEMA", "expected ArrayBuffer tag after marker")
    j += 1
    if blob[j] != 0x02:
        raise Err("UNSUPPORTED_SCHEMA", "unexpected ArrayBuffer header")
    j += 1
    a, b = struct.unpack_from("<QQ", blob, j)
    j += 16
    if a != 0 or blob[j] != 0x15:
        raise Err("UNSUPPORTED_SCHEMA", "unexpected ArrayBuffer view header")
    j += 1
    (c,) = struct.unpack_from("<Q", blob, j)
    j += 8
    if c != b:
        raise Err("UNSUPPORTED_SCHEMA", "ArrayBuffer length mismatch")
    return blob[j : j + b]


def extract_hb_string_after(key: bytes, blob: bytes) -> str | None:
    pat = struct.pack("<I", 0x80000000 | len(key)) + key
    i = blob.find(pat)
    if i < 0:
        return None
    j = i + len(pat)
    if blob[j] != 0x10:
        return None
    j += 1
    (raw,) = struct.unpack_from("<I", blob, j)
    j += 4
    if raw in (0xFFFFFFFE, 0xFFFFFFFF):
        return ""
    if not (raw & 0x80000000):
        return None
    n = raw & 0xFFFFFF
    return blob[j : j + n].decode("utf-8")


def extract_i32_after(key: bytes, blob: bytes) -> int | None:
    pat = struct.pack("<I", 0x80000000 | len(key)) + key
    i = blob.find(pat)
    if i < 0:
        return None
    j = i + len(pat)
    if blob[j] != 0x05:
        return None
    j += 1
    return struct.unpack_from("<i", blob, j)[0]


def load_rows(db: Path, store: str) -> list[bytes]:
    con = sqlite3.connect(db)
    con.create_collation("IDBKEY", lambda a, b: (a > b) - (a < b))
    oid = dict(con.execute("SELECT name, id FROM ObjectStoreInfo"))[store]
    out: list[bytes] = []
    for (val,) in con.execute("SELECT value FROM Records WHERE objectStoreID=?", (oid,)):
        out.append(val if isinstance(val, bytes) else val.encode("latin1"))
    con.close()
    return out


def run_bounded(argv: list[str], limit: int, timeout: float) -> tuple[int | None, bytes]:
    """Run argv (no shell) and read at most limit+1 bytes of its stdout.

    Returns (returncode, data). If the program writes more than `limit` bytes
    it is killed and returncode is None; if it doesn't finish within `timeout`
    seconds it is killed and TimeoutExpired is raised. stderr is discarded.
    """
    deadline = time.monotonic() + timeout
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    try:
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        buf = b""
        with selectors.DefaultSelector() as sel:
            sel.register(fd, selectors.EVENT_READ)
            while len(buf) <= limit:
                left = deadline - time.monotonic()
                if left <= 0 or not sel.select(left):
                    raise subprocess.TimeoutExpired(argv, timeout)
                chunk = os.read(fd, limit + 1 - len(buf))
                if not chunk:
                    break
                buf += chunk
        if len(buf) > limit:
            return None, buf[: limit + 1]
        return proc.wait(timeout=max(0.1, deadline - time.monotonic())), buf
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if proc.stdout is not None:
            proc.stdout.close()


def read_keyring(adapter_key_id: str) -> bytes:
    # Comes from the vault; refuse anything that could be read as an option.
    if not ADAPTER_ID_RE.match(adapter_key_id):
        raise Err("UNSUPPORTED_SCHEMA", "unexpected adapterKeyId format")
    try:
        rc, secret = run_bounded(  # fixed argv, no shell
            [SECRET_TOOL, "lookup", "service", SERVICE, "username", adapter_key_id],
            SECRET_MAX_BYTES, SECRET_TOOL_TIMEOUT_SEC,
        )
    except FileNotFoundError as e:
        raise Err("DEPS_MISSING", "secret-tool not found (install package: libsecret)") from e
    except subprocess.TimeoutExpired as e:
        raise Err("HELPER_TIMEOUT", "secret-tool did not answer (keyring prompt open?)") from e
    if rc is None:
        raise Err("DECRYPT_FAILED", "unexpected key length (too long)")
    if rc != 0:
        raise Err("KEY_MISSING", f"no Secret Service item for {adapter_key_id}")
    if not secret:
        raise Err("KEYRING_LOCKED", "empty secret — unlock the session keyring")
    if len(secret) != 32:
        raise Err("DECRYPT_FAILED", f"unexpected key length {len(secret)}")
    return secret


def list_entries(window: int) -> dict:
    with vault_snapshot(find_idb()) as idb:
        sk_rows = load_rows(idb, "storageKey")
        if not sk_rows:
            raise Err("VAULT_UNREADABLE", "storageKey store empty")
        sk = sk_rows[0]
        salt = extract_arraybuffer_after(b"salt", sk)
        adapter = extract_hb_string_after(b"adapterKeyId", sk)
        if not adapter:
            raise Err("UNSUPPORTED_SCHEMA", "adapterKeyId missing")
        secret = read_keyring(adapter)
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=HKDF_INFO,
        ).derive(secret)
        aesgcm = AESGCM(aes_key)

        now = int(time.time())
        entries: list[dict] = []
        items = load_rows(idb, "items")
        if len(items) > MAX_ENTRIES:
            raise Err("OUTPUT_TOO_LARGE", f"more than {MAX_ENTRIES} entries")
        for vb in items:
            issuer = extract_hb_string_after(b"issuer", vb) or ""
            name = extract_hb_string_after(b"name", vb)
            if name is None:
                name = ""
            order = extract_i32_after(b"order", vb)
            entry_id = extract_hb_string_after(b"id", vb) or ""
            ct = extract_arraybuffer_after(b"__encryptedData", vb)
            obj = None
            for ivlen in (12, 16):
                try:
                    pt = aesgcm.decrypt(ct[:ivlen], ct[ivlen:], ITEM_AAD)
                    obj = json.loads(pt.decode())
                    break
                except (InvalidTag, ValueError):  # wrong IV length / not JSON
                    continue
            if obj is None:
                raise Err("DECRYPT_FAILED", f"AES-GCM failed for {issuer or entry_id}")

            seed = obj.get("secret")
            if not seed and obj.get("uri"):
                seed = pyotp.parse_uri(obj["uri"]).secret
            if not seed:
                raise Err("DECRYPT_FAILED", f"no secret for {issuer or entry_id}")
            period = int(obj.get("period") or 30)
            digits = int(obj.get("digits") or 6)
            # Codes must stay short digit strings (the clipboard check relies
            # on 1-10 digits) and the period must be usable.
            if not (1 <= digits <= 10 and 1 <= period <= 86400):
                raise Err("UNSUPPORTED_SCHEMA", f"unsupported digits/period for {issuer or entry_id}")
            totp = pyotp.TOTP(seed, digits=digits, interval=period)
            entries.append(
                {
                    "id": str(entry_id)[:MAX_ID_CHARS],
                    "issuer": str(issuer or obj.get("issuer") or "")[:MAX_LABEL_CHARS],
                    "account": str(name if name != "" else (obj.get("name") or ""))[:MAX_LABEL_CHARS],
                    "period": period,
                    "digits": digits,
                    "order": order if order is not None else 0,
                    **code_window(totp, period, now, window),
                }
            )
        entries.sort(key=lambda e: (-e["order"], e["issuer"].lower(), e["account"].lower()))
        return {
            "ok": True,
            "updatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "entries": entries,
            "error": None,
        }


def code_window(totp, period: int, now: int, window: int) -> dict:
    """Codes for `window` consecutive periods, starting at the current one."""
    counter = now // period
    return {
        "counter": counter,
        "codes": [totp.at((counter + k) * period) for k in range(window)],
    }


def fail(code: str, message: str) -> dict:
    return {
        "ok": False,
        "updatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "entries": [],
        "error": {"code": code, "message": str(message)[:MAX_MESSAGE_CHARS]},
    }


def check() -> dict:
    """Diagnose the setup without decrypting anything or printing codes."""
    if shutil.which(SECRET_TOOL) is None:
        raise Err("DEPS_MISSING", "secret-tool not found (install package: libsecret)")
    idb = find_idb()
    with vault_snapshot(idb) as tmp:
        sk_rows = load_rows(tmp, "storageKey")
        if not sk_rows:
            raise Err("VAULT_UNREADABLE", "storageKey store empty")
        adapter = extract_hb_string_after(b"adapterKeyId", sk_rows[0])
        if not adapter:
            raise Err("UNSUPPORTED_SCHEMA", "adapterKeyId missing")
        read_keyring(adapter)
        items = len(load_rows(tmp, "items"))
    return {
        "ok": True,
        "updatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "entries": [],
        "error": None,
        "check": {"vault": str(idb), "items": items, "keyring": "unlocked"},
    }


# Fake accounts for screenshots/demos. The secrets are well-known public test
# values (RFC 4226/6238 style), not anyone's real seeds.
DEMO_ACCOUNTS = [
    ("GitHub", "octocat@example.com", "JBSWY3DPEHPK3PXP", 30, 6),
    ("Proton", "demo@proton.me", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 30, 6),
    ("Google", "jane.doe@example.com", "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ", 30, 6),
    ("AWS", "root@example.org", "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U", 30, 6),
    ("Discord", "jane#0001", "ONSWG4TFORZWK3DUMVZXG5DFON2A", 30, 6),
    ("Tailscale", "jane@example.net", "OBQXG43XN5ZGIZLYMFWXA3DF", 30, 8),
]


def demo(window: int) -> dict:
    now = int(time.time())
    entries = []
    for i, (issuer, account, seed, period, digits) in enumerate(DEMO_ACCOUNTS):
        totp = pyotp.TOTP(seed, digits=digits, interval=period)
        entries.append({
            "id": f"demo-{i}", "issuer": issuer, "account": account,
            "period": period, "digits": digits, "order": 0,
            **code_window(totp, period, now, window),
        })
    return {"ok": True, "demo": True,
            "updatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "entries": entries, "error": None}


def _exit_on_signal(signum, _frame):
    # Turn SIGTERM/SIGHUP/SIGINT into SystemExit so every `finally` (temp dir
    # removal) still runs when omarchy-shell stops the helper.
    raise SystemExit(128 + signum)


def _on_alarm(_signum, _frame):
    # Whole-run deadline: unwinds like any other error (finally blocks run,
    # a running secret-tool is killed) and is reported as JSON.
    raise Err("HELPER_TIMEOUT", f"helper took longer than {HELPER_TIMEOUT_SEC} s")


def emit(payload: dict) -> None:
    """Print payload as one JSON line, never more than MAX_OUTPUT_BYTES."""
    out = json.dumps(payload, separators=(",", ":"))
    if len(out.encode("utf-8")) > MAX_OUTPUT_BYTES:
        out = json.dumps(fail("OUTPUT_TOO_LARGE", f"output over {MAX_OUTPUT_BYTES} bytes"),
                         separators=(",", ":"))
    print(out)


def main() -> int:
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(sig, _exit_on_signal)
    signal.signal(signal.SIGALRM, _on_alarm)
    signal.alarm(HELPER_TIMEOUT_SEC)
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="verify dependencies, vault and keyring access; prints no codes")
    ap.add_argument("--demo", action="store_true",
                    help="print fake demo accounts (for screenshots); never touches the vault")
    ap.add_argument("--window", type=int, default=DEFAULT_WINDOW,
                    help=f"codes per entry, current one first (1-{MAX_WINDOW})")
    ap.add_argument("--version", action="version", version=f"protonauth-list {__version__}")
    args = ap.parse_args()
    window = max(1, min(MAX_WINDOW, args.window))
    if _IMPORT_ERROR is not None:
        emit(fail("DEPS_MISSING", f"{_IMPORT_ERROR} (install: python-cryptography python-pyotp)"))
        return 1
    try:
        if args.demo:
            emit(demo(window))
            return 0
        if args.check:
            emit(check())
            return 0
        payload = list_entries(window)
        for e in payload["entries"]:
            if "secret" in e:
                raise Err("DECRYPT_FAILED", "refusing to emit secret field")
        emit(payload)
        return 0
    except Err as e:
        emit(fail(e.code, e.message))
        return 1
    except Exception as e:  # noqa: BLE001 - fail closed with a JSON error
        # Only the exception type: its text could quote vault/decrypted data.
        emit(fail("DECRYPT_FAILED", f"internal error ({type(e).__name__})"))
        return 1
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
