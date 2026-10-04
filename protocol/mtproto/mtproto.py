import asyncio
import os
import platform
import re
import resource
import secrets
import shutil
import socket
import stat
import hashlib
import subprocess
import tarfile
import time
import traceback
import logging
from pathlib import Path
from typing import Awaitable, Callable, Optional

import httpx

logger = logging.getLogger("RVG-Gateway")

MTG_VERSION = "2.1.7"
# SHA-256 آرشیوها (مطابق mtg-2.1.7-checksums.txt در ریلیز رسمی). نسخه‌ی MTG_VERSION که
# عوض شد باید این مقادیر هم عوض شوند؛ آرشیو بدون تطابق هرگز اکسترکت/اجرا نمی‌شود.
MTG_SHA256 = {
    "amd64": "af6e0cba65abe8e4e63f6e534cd6f23cc235ff987155a8a7e43e0f5b481a96e2",
    "arm64": "ca1897c13fbacb4a671b872ff7dad7bc5dc2b09a7d7ed8cac7034df74b5b195a",
}
MTG_DIR = Path(os.environ.get("DATA_DIR", "/data")) / "mtg"
MTG_BIN = MTG_DIR / "mtg"
CONFIG_DIR = MTG_DIR / "configs"

DEFAULT_FAKE_TLS_DOMAIN = "www.cloudflare.com"

MTPROTO_PORT_RANGE_START = int(os.environ.get("MTPROTO_PORT_START", 8500))
MTPROTO_PORT_RANGE_END = int(os.environ.get("MTPROTO_PORT_END", 8600))

STATS_PORT_RANGE_START = 20000
STATS_PORT_RANGE_END = 30000

MAX_LOG_LINES = 300
USAGE_POLL_INTERVAL = 5.0
STARTUP_VERIFY_DELAY = 0.5
PORT_RETRY_ATTEMPTS = 20
PORT_RETRY_DELAY = 0.3
POST_KILL_RETRY_ATTEMPTS = 15
POST_KILL_RETRY_DELAY = 0.3
STOP_PORT_FREE_ATTEMPTS = 20
STOP_PORT_FREE_DELAY = 0.3

MTG_NICE = int(os.environ.get("MTG_NICE", -10))
MTG_NOFILE_LIMIT = int(os.environ.get("MTG_NOFILE_LIMIT", 65535))
MTG_GOMAXPROCS = os.environ.get("MTG_GOMAXPROCS") or str(os.cpu_count() or 1)

_instances: dict = {}
_instances_lock = asyncio.Lock()
_used_ports: set[int] = set()
_used_stats_ports: set[int] = set()

_usage_callback: Optional[Callable[[str, int], Awaitable[bool]]] = None


def set_usage_callback(cb: Callable[[str, int], Awaitable[bool]]):
    global _usage_callback
    _usage_callback = cb
    logger.info("MTG: usage_callback ثبت شد؛ ردیابی مصرف ترافیک MTProto فعال است")


def _mask_secret(secret: str) -> str:
    if not secret or len(secret) <= 12:
        return "***"
    return f"{secret[:8]}…{secret[-6:]}"


def _mtg_release_asset() -> str:
    arch = platform.machine().lower()
    if arch in ("x86_64", "amd64"):
        arch_tag = "amd64"
    elif arch in ("aarch64", "arm64"):
        arch_tag = "arm64"
    else:
        raise RuntimeError(f"معماری پشتیبانی‌نشده برای mtg: {arch}")
    return f"mtg-{MTG_VERSION}-linux-{arch_tag}.tar.gz"


async def ensure_mtg_binary() -> bool:
    if MTG_BIN.exists() and os.access(MTG_BIN, os.X_OK):
        return True
    t0 = time.monotonic()
    logger.info("MTG: باینری mtg پیدا نشد، شروع دانلود...")
    MTG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        asset = _mtg_release_asset()
    except Exception as exc:
        logger.error(f"MTG: خطا در تشخیص asset: {exc}\n{traceback.format_exc()}")
        return False

    url = f"https://github.com/9seconds/mtg/releases/download/v{MTG_VERSION}/{asset}"
    tmp_tar = MTG_DIR / asset
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            arch_key = asset.split("-linux-")[1].split(".")[0]
            expected = MTG_SHA256.get(arch_key)
            actual = hashlib.sha256(resp.content).hexdigest()
            if not expected or actual != expected:
                raise RuntimeError(f"عدم تطابق sha256 آرشیو mtg ({actual})")
            tmp_tar.write_bytes(resp.content)
        with tarfile.open(tmp_tar, "r:gz") as tf:
            member = next((m for m in tf.getmembers() if m.name.endswith("mtg") and m.isfile()), None)
            if member is None:
                raise RuntimeError("باینری mtg در آرشیو پیدا نشد")
            member.name = "mtg"
            tf.extract(member, MTG_DIR)
        tmp_tar.unlink(missing_ok=True)
        st = MTG_BIN.stat()
        MTG_BIN.chmod(st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        logger.info(f"✅ MTG: باینری نصب شد ({time.monotonic()-t0:.2f}s)")
        return True
    except Exception as exc:
        logger.error(f"MTG: دانلود/نصب شکست خورد: {exc}\n{traceback.format_exc()}")
        return False


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False


def _kill_process_on_port(port: int, uuid: str = "") -> bool:
    tag = uuid[:8] if uuid else "?"
    killed_any = False
    try:
        import psutil
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr and conn.laddr.port == port and conn.pid:
                try:
                    p = psutil.Process(conn.pid)
                    name = p.name()
                    p.kill()
                    logger.warning(f"MTG[{tag}]: پروسه‌ی اشغال‌کننده‌ی پورت {port} کشته شد (PID={conn.pid}, name={name})")
                    killed_any = True
                except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
                    logger.warning(f"MTG[{tag}]: کشتن پروسه‌ی روی پورت {port} ناموفق: {exc}")
        if killed_any:
            return True
    except ImportError:
        logger.debug(f"MTG[{tag}]: psutil نصب نیست، از fallback سیستمی استفاده می‌شود")
    except Exception as exc:
        logger.warning(f"MTG[{tag}]: خطا در استفاده از psutil برای پورت {port}: {exc}")

    for cmd in (
        ["fuser", "-k", "-n", "tcp", str(port)],
        ["bash", "-c", f"lsof -ti tcp:{port} | xargs -r kill -9"],
    ):
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=5, text=True)
            if result.returncode == 0:
                logger.warning(f"MTG[{tag}]: پورت {port} با دستور «{' '.join(cmd)}» آزاد شد")
                killed_any = True
                break
        except FileNotFoundError:
            continue
        except Exception as exc:
            logger.debug(f"MTG[{tag}]: دستور «{' '.join(cmd)}» شکست خورد: {exc}")
    return killed_any


async def allocate_port_async(preferred: int | None = None, force: bool = False, uuid: str = "") -> int | None:
    tag = uuid[:8] if uuid else "?"
    if preferred is not None:
        for attempt in range(PORT_RETRY_ATTEMPTS):
            if preferred not in _used_ports and _port_free(preferred):
                return preferred
            await asyncio.sleep(PORT_RETRY_DELAY)

        if force:
            logger.warning(
                f"MTG[{tag}]: پورت {preferred} بعد از {PORT_RETRY_ATTEMPTS} تلاش هنوز آزاد نشد — "
                f"تلاش برای kill کردن پروسه‌ی اشغال‌کننده..."
            )
            _used_ports.discard(preferred)
            killed = _kill_process_on_port(preferred, uuid)
            if killed:
                for attempt in range(POST_KILL_RETRY_ATTEMPTS):
                    if _port_free(preferred):
                        logger.info(f"MTG[{tag}]: پورت {preferred} بعد از kill کردن آزاد شد")
                        return preferred
                    await asyncio.sleep(POST_KILL_RETRY_DELAY)
            logger.warning(f"MTG[{tag}]: پورت {preferred} حتی بعد از تلاش برای kill هم آزاد نشد")
            return None

        logger.warning(f"MTG[{tag}]: پورت قبلی {preferred} آزاد نشد، پورت جایگزین جستجو می‌شود")

    for port in range(MTPROTO_PORT_RANGE_START, MTPROTO_PORT_RANGE_END):
        if port in _used_ports:
            continue
        if _port_free(port):
            return port
    logger.error(f"MTG[{tag}]: هیچ پورت آزادی در بازه‌ی {MTPROTO_PORT_RANGE_START}-{MTPROTO_PORT_RANGE_END} نیست")
    return None


def allocate_port(preferred: int | None = None, force: bool = False) -> int | None:
    if preferred is not None:
        ok = preferred not in _used_ports and _port_free(preferred)
        if ok:
            return preferred
        if force:
            return None
    for port in range(MTPROTO_PORT_RANGE_START, MTPROTO_PORT_RANGE_END):
        if port in _used_ports:
            continue
        if _port_free(port):
            return port
    return None


def get_instance_connections(uuid: str) -> list[dict]:
    inst = _instances.get(uuid)
    if not inst or inst["proc"].returncode is not None:
        return []
    port = inst["port"]
    result = []
    try:
        import psutil
        for conn in psutil.net_connections(kind="inet"):
            if (
                conn.laddr and conn.laddr.port == port
                and conn.status == "ESTABLISHED"
                and conn.raddr
            ):
                result.append({"ip": conn.raddr.ip, "port": conn.raddr.port})
    except ImportError:
        logger.debug(f"MTG[{uuid[:8]}]: psutil نصب نیست، IP اتصالات قابل خواندن نیست")
    except Exception as exc:
        logger.debug(f"MTG[{uuid[:8]}]: خطا در خواندن اتصالات: {exc}")
    return result


async def _allocate_stats_port_async() -> int:
    for attempt in range(PORT_RETRY_ATTEMPTS):
        for port in range(STATS_PORT_RANGE_START, STATS_PORT_RANGE_END):
            if port in _used_stats_ports:
                continue
            if _port_free(port):
                return port
        await asyncio.sleep(PORT_RETRY_DELAY)
    raise RuntimeError("پورت آزادی برای stats server مِتریک mtg پیدا نشد")


def generate_secret(domain: str = DEFAULT_FAKE_TLS_DOMAIN) -> str:
    raw = secrets.token_hex(16)
    domain_hex = domain.encode().hex()
    return f"ee{raw}{domain_hex}"


def secret_domain(secret: str) -> str | None:
    if not secret.startswith("ee") or len(secret) <= 34:
        return None
    try:
        return bytes.fromhex(secret[34:]).decode()
    except Exception:
        return None


def _write_config(uuid: str, port: int, secret: str, stats_port: int, ad_tag: str = None) -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    cfg_path = CONFIG_DIR / f"{uuid}.toml"

    # ساختار کانفیگ با ad-tag در صورت وجود
    toml_lines = [
        f'secret = "{secret}"',
        f'bind-to = "0.0.0.0:{port}"',
        'prefer-ip = "prefer-ipv4"',
    ]

    # اگر ad_tag داده شده، آن را به فایل اضافه کن
    if ad_tag:
        toml_lines.append(f'ad-tag = "{ad_tag}"')

    toml_lines.extend([
        "",
        "[stats]",
        "",
        "[stats.prometheus]",
        "enabled = true",
        f'bind-to = "127.0.0.1:{stats_port}"',
    ])

    toml = "\n".join(toml_lines)
    cfg_path.write_text(toml, encoding="utf-8")
    logger.debug(f"MTG[{uuid[:8]}]: کانفیگ نوشته شد -> port={port} stats_port={stats_port} ad_tag={ad_tag}")
    return cfg_path


_METRIC_RE = re.compile(
    r'^mtg_telegram_traffic\{[^}]*\}\s+([\d.eE+]+)\s*$'
    r'|^mtg_domain_fronting_traffic\{[^}]*\}\s+([\d.eE+]+)\s*$',
    re.MULTILINE,
)
_warned_metric_format = False
_warned_metric_connect_fail: set[str] = set()


async def _read_total_bytes(stats_port: int, uuid: str) -> int | None:
    global _warned_metric_format
    url = f"http://127.0.0.1:{stats_port}/metrics"
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            text = resp.text
    except Exception as exc:
        if uuid not in _warned_metric_connect_fail:
            _warned_metric_connect_fail.add(uuid)
            logger.warning(
                f"MTG[{uuid[:8]}]: اتصال به /metrics (پورت {stats_port}) شکست خورد: "
                f"{type(exc).__name__}: {exc} — این پیام فقط یک‌بار نمایش داده می‌شه"
            )
        else:
            logger.debug(f"MTG[{uuid[:8]}]: خواندن /metrics شکست خورد: {type(exc).__name__}: {exc}")
        return None

    _warned_metric_connect_fail.discard(uuid)

    matches = _METRIC_RE.findall(text)
    if not matches:
        if not _warned_metric_format:
            _warned_metric_format = True
            logger.warning(
                f"MTG[{uuid[:8]}]: هیچ متریک ترافیکی با الگوی شناخته‌شده در /metrics پیدا نشد؛ "
                f"نمونه‌ی خروجی (۵۰۰ کاراکتر اول):\n{text[:500]}"
            )
        return None

    try:
        total = 0.0
        for g1, g2 in matches:
            total += float(g1 or g2)
        return int(total)
    except ValueError:
        return None


async def _usage_poller(uuid: str, stats_port: int, inst: dict):
    last_total = 0
    await asyncio.sleep(2.0)
    while True:
        try:
            await asyncio.sleep(USAGE_POLL_INTERVAL)
            total = await _read_total_bytes(stats_port, uuid)
            if total is None:
                continue
            delta = max(0, total - last_total)
            last_total = total
            if delta == 0:
                continue
            inst["used_bytes_reported"] = inst.get("used_bytes_reported", 0) + delta
            if _usage_callback is not None:
                allowed = await _usage_callback(uuid, delta)
                if not allowed:
                    logger.warning(f"MTG[{uuid[:8]}]: کوتای ترافیک تمام شده، در حال توقف پروسه...")
                    asyncio.create_task(stop_instance(uuid))
                    return
            else:
                logger.debug(f"MTG[{uuid[:8]}]: usage_callback ثبت نشده، دلتای {delta} بایت فقط لاگ شد")
        except asyncio.CancelledError:
            return
        except Exception as exc:
            logger.error(f"MTG[{uuid[:8]}]: خطا در usage poller: {type(exc).__name__}: {exc}\n{traceback.format_exc()}")


async def _stream_process_output(uuid: str, proc: asyncio.subprocess.Process, inst: dict):
    assert proc.stdout is not None
    try:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="ignore").rstrip()
            if not text:
                continue
            inst["logs"].append(text)
            if len(inst["logs"]) > MAX_LOG_LINES:
                del inst["logs"][: len(inst["logs"]) - MAX_LOG_LINES]
            low = text.lower()
            if "error" in low or "fatal" in low or "panic" in low:
                logger.error(f"MTG[{uuid[:8]}] stdout: {text}")
            elif "warn" in low:
                logger.warning(f"MTG[{uuid[:8]}] stdout: {text}")
            else:
                logger.debug(f"MTG[{uuid[:8]}] stdout: {text}")
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error(f"MTG[{uuid[:8]}]: خطا در خواندن stdout: {exc}\n{traceback.format_exc()}")


def _mtg_preexec(uuid_tag: str):
    try:
        os.nice(MTG_NICE)
    except Exception:
        pass
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = min(MTG_NOFILE_LIMIT, hard) if hard != resource.RLIM_INFINITY else MTG_NOFILE_LIMIT
        if target > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass


async def start_instance(
    uuid: str,
    secret: str | None = None,
    domain: str = DEFAULT_FAKE_TLS_DOMAIN,
    preferred_port: int | None = None,
    force_port: bool = False,
    ad_tag: str | None = None,  # <-- پارامتر جدید
) -> dict:
    t0 = time.monotonic()
    logger.info(f"MTG[{uuid[:8]}]: start_instance (preferred_port={preferred_port}, force={force_port}, ad_tag={ad_tag})")

    async with _instances_lock:
        existing = _instances.get(uuid)
        if existing and existing["proc"].returncode is None:
            logger.info(f"MTG[{uuid[:8]}]: از قبل در حال اجراست روی پورت {existing['port']}")
            return existing

        if not await ensure_mtg_binary():
            raise RuntimeError("باینری mtg در دسترس نیست")

        port = await allocate_port_async(preferred_port, force=force_port, uuid=uuid)
        if port is None:
            if force_port and preferred_port is not None:
                raise RuntimeError(f"پورت {preferred_port} در حال حاضر اشغال است")
            raise RuntimeError("پورت آزادی برای MTProto باقی نمانده")

        if secret is None:
            secret = generate_secret(domain)

        stats_port = await _allocate_stats_port_async()
        _used_stats_ports.add(stats_port)
        cfg_path = _write_config(uuid, port, secret, stats_port, ad_tag)

        child_env = os.environ.copy()
        child_env["GOMAXPROCS"] = MTG_GOMAXPROCS

        try:
            proc = await asyncio.create_subprocess_exec(
                str(MTG_BIN), "run", str(cfg_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=child_env,
                preexec_fn=lambda: _mtg_preexec(uuid[:8]),
            )
        except Exception as exc:
            _used_stats_ports.discard(stats_port)
            logger.error(f"MTG[{uuid[:8]}]: اجرای پروسه شکست خورد: {exc}\n{traceback.format_exc()}")
            raise

        _used_ports.add(port)
        inst = {
            "proc": proc, "port": port, "secret": secret, "domain": domain,
            "cfg_path": str(cfg_path), "stats_port": stats_port,
            "logs": [], "started_at": time.time(), "used_bytes_reported": 0,
        }
        _instances[uuid] = inst
        inst["log_task"] = asyncio.create_task(_stream_process_output(uuid, proc, inst))

        await asyncio.sleep(STARTUP_VERIFY_DELAY)
        if proc.returncode is not None:
            _used_ports.discard(port)
            _used_stats_ports.discard(stats_port)
            _instances.pop(uuid, None)
            t = inst.get("log_task")
            if t:
                t.cancel()
            last_logs = "\n".join(inst.get("logs", [])[-8:]) or "(لاگی ثبت نشد)"
            logger.error(f"MTG[{uuid[:8]}]: پروسه فوراً با کد {proc.returncode} خارج شد. لاگ:\n{last_logs}")
            raise RuntimeError(f"mtg بلافاصله بعد از اجرا متوقف شد (کد {proc.returncode}): {last_logs[:300]}")

        logger.info(
            f"✅ MTG[{uuid[:8]}]: PID={proc.pid} port={port} stats_port={stats_port} "
            f"secret={_mask_secret(secret)} GOMAXPROCS={MTG_GOMAXPROCS} nice={MTG_NICE} "
            f"ad_tag={ad_tag} ({time.monotonic()-t0:.2f}s)"
        )

        inst["usage_task"] = asyncio.create_task(_usage_poller(uuid, stats_port, inst))
        asyncio.create_task(_watch_process(uuid, proc))
        return inst


async def _watch_process(uuid: str, proc: asyncio.subprocess.Process):
    rc = await proc.wait()
    async with _instances_lock:
        cur = _instances.get(uuid)
        if cur and cur["proc"] is proc:
            _used_ports.discard(cur["port"])
            _used_stats_ports.discard(cur["stats_port"])
            for tkey in ("log_task", "usage_task"):
                t = cur.get(tkey)
                if t:
                    t.cancel()
            last_logs = cur.get("logs", [])[-10:]
            del _instances[uuid]
        else:
            last_logs = []

    if rc not in (0, None, -15, -9):
        logger.warning(f"⚠️ MTG[{uuid[:8]}]: پروسه با کد {rc} متوقف شد")
        if last_logs:
            logger.warning(f"MTG[{uuid[:8]}]: آخرین لاگ‌ها:\n" + "\n".join(last_logs))
    else:
        logger.info(f"MTG[{uuid[:8]}]: پروسه با کد {rc} خاتمه یافت")


async def stop_instance(uuid: str):
    logger.info(f"MTG[{uuid[:8]}]: stop_instance")
    async with _instances_lock:
        inst = _instances.pop(uuid, None)
    if not inst:
        return
    _used_ports.discard(inst["port"])
    _used_stats_ports.discard(inst["stats_port"])
    for tkey in ("log_task", "usage_task"):
        t = inst.get(tkey)
        if t:
            t.cancel()
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass

    proc = inst["proc"]
    if proc.returncode is None:
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except (asyncio.TimeoutError, ProcessLookupError):
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass

    for _ in range(STOP_PORT_FREE_ATTEMPTS):
        if _port_free(inst["port"]):
            break
        await asyncio.sleep(STOP_PORT_FREE_DELAY)

    try:
        Path(inst["cfg_path"]).unlink(missing_ok=True)
    except Exception:
        pass
    logger.info(f"🔌 MTG[{uuid[:8]}]: متوقف شد (پورت {inst['port']} آزاد شد)")


def get_instance_info(uuid: str) -> dict | None:
    inst = _instances.get(uuid)
    if not inst:
        return None
    return {
        "port": inst["port"], "secret": inst["secret"], "domain": inst["domain"],
        "running": inst["proc"].returncode is None, "pid": inst["proc"].pid,
        "started_at": inst.get("started_at"),
        "logs": inst.get("logs", [])[-50:],
    }


def get_instance_logs(uuid: str, tail: int = 50) -> list[str]:
    inst = _instances.get(uuid)
    if not inst:
        return []
    return inst.get("logs", [])[-tail:]


def generate_mtproto_link(host: str, port: int, secret: str) -> str:
    return f"tg://proxy?server={host}&port={port}&secret={secret}"


def generate_mtproto_web_link(host: str, port: int, secret: str) -> str:
    return f"https://t.me/proxy?server={host}&port={port}&secret={secret}"


async def stop_all():
    async with _instances_lock:
        uuids = list(_instances.keys())
    logger.info(f"MTG: shutdown — {len(uuids)} instance در حال توقف")
    for uid in uuids:
        try:
            await stop_instance(uid)
        except Exception as exc:
            logger.error(f"MTG[{uid[:8]}]: خطا حین shutdown: {exc}\n{traceback.format_exc()}")


_SYSCTL_TUNING = {
    "net.core.default_qdisc": "fq",
    "net.ipv4.tcp_congestion_control": "bbr",
    "net.core.rmem_max": "134217728",
    "net.core.wmem_max": "134217728",
    "net.ipv4.tcp_rmem": "4096 87380 67108864",
    "net.ipv4.tcp_wmem": "4096 65536 67108864",
    "net.ipv4.tcp_fastopen": "3",
    "net.ipv4.tcp_slow_start_after_idle": "0",
    "net.ipv4.tcp_notsent_lowat": "16384",
}


def apply_host_network_tuning() -> dict:
    result = {"applied": [], "failed": [], "reason": None}
    if os.geteuid() != 0:
        result["reason"] = "پروسه root نیست؛ تنظیمات کرنل نادیده گرفته شد (نیاز به دسترسی روت روی هاست)"
        logger.warning(f"MTG tuning: {result['reason']}")
        return result
    if shutil.which("sysctl") is None:
        result["reason"] = "دستور sysctl روی این سیستم پیدا نشد"
        logger.warning(f"MTG tuning: {result['reason']}")
        return result
    try:
        subprocess.run(["modprobe", "tcp_bbr"], capture_output=True, timeout=5)
    except Exception:
        pass
    for key, value in _SYSCTL_TUNING.items():
        try:
            r = subprocess.run(
                ["sysctl", "-w", f"{key}={value}"],
                capture_output=True, timeout=5, text=True,
            )
            if r.returncode == 0:
                result["applied"].append(key)
            else:
                result["failed"].append((key, r.stderr.strip()))
                logger.debug(f"MTG tuning: {key} اعمال نشد: {r.stderr.strip()}")
        except Exception as exc:
            result["failed"].append((key, str(exc)))
    if result["applied"]:
        logger.info(
            f"✅ MTG tuning: {len(result['applied'])} پارامتر کرنل اعمال شد "
            f"({', '.join(result['applied'])})"
        )
    if result["failed"]:
        logger.warning(
            f"⚠️ MTG tuning: {len(result['failed'])} پارامتر اعمال نشد "
            f"({', '.join(k for k, _ in result['failed'])})"
        )
    return result