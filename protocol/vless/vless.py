# relay_vless.py
# بخش VLESS Relay — جدا شده از main.py (منطق اصلی دست‌نخورده)
# تغییر: ثبت IP واقعی کلاینت (با احتساب هدر x-forwarded-for پشت پراکسی) در connections
#
# بهینه‌سازی سرعت/تاخیر (هماهنگ با همون سطح تیونینگ که Trojan/Shadowsocks دارن):
#   1. RELAY_BUF: 256KB → 1MB (همون مقدار Trojan/Shadowsocks/XHTTP)
#   2. WRITE_HIGH_WATER جدا از RELAY_BUF: drain فقط وقتی واقعاً بافر پر باشه
#   3. _QuotaGate تطبیقی به‌جای check_and_use روی هر فریم WS به‌تنهایی —
#      قبلاً هر فریم یک بار LINKS_LOCK می‌گرفت که روی ترافیک پرسرعت گلوگاه
#      و منبع تاخیر اضافه بود؛ الان مثل Trojan/Shadowsocks batched/adaptive شد.
#   4. _tune_socket: TCP_NODELAY + بافر ۴MB سطح OS (قبلاً فقط TCP_NODELAY ست
#      می‌شد و SO_SNDBUF/SO_RCVBUF اصلاً تنظیم نمی‌شدن)

import asyncio
import ipaddress
import socket
import time

from fastapi import WebSocket, WebSocketDisconnect

from main import (
    LINKS,
    LINKS_LOCK,
    stats,
    hourly_traffic,
    connections,
    logger,
    is_link_allowed,
    now_ir,
)

# ══════════════════════════════════════════════════════════════════════════════
# VLESS Relay — بهینه‌شده برای حداکثر throughput و کمترین تاخیر
# ══════════════════════════════════════════════════════════════════════════════

RELAY_BUF = 1024 * 1024          # 1 MB — هماهنگ با Trojan/Shadowsocks/XHTTP
SOCK_BUF = 4 * 1024 * 1024       # 4 MB بافر سوکت سطح OS
WRITE_HIGH_WATER = 512 * 1024    # drain فقط وقتی بیشتر از 512KB در بافر باشه

# تنظیمات QuotaGate تطبیقی (batched quota check به‌جای per-frame lock)
QUOTA_MIN_BATCH = 32 * 1024
QUOTA_MAX_BATCH = 2 * 1024 * 1024
QUOTA_START_BATCH = 128 * 1024
QUOTA_CHECK_INTERVAL = 0.25


def _tune_socket(writer: asyncio.StreamWriter):
    """TCP_NODELAY + بافرهای بزرگ سوکت برای کاهش overhead سیستم‌عامل و تاخیر."""
    try:
        sock = writer.transport.get_extra_info("socket")
        if sock is None:
            return
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF)
        if hasattr(socket, "TCP_QUICKACK"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
    except Exception as e:
        logger.warning(f"VLESS _tune_socket failed: {e}")


class _QuotaGate:
    """
    batch quota check تطبیقی بر اساس EWMA نرخ ترافیک هر اتصال — به‌جای گرفتن
    LINKS_LOCK روی هر فریم WS، هر QUOTA_CHECK_INTERVAL ثانیه یا هر QUOTA حجم
    batch شده یک بار چک می‌کنه. همون الگویی که Trojan/Shadowsocks استفاده می‌کنن.
    """
    __slots__ = ("uuid", "pending", "last_check", "ok", "batch_bytes", "rate_ewma")

    def __init__(self, uuid: str):
        self.uuid = uuid
        self.pending = 0
        self.last_check = time.monotonic()
        self.ok = True
        self.batch_bytes = QUOTA_START_BATCH
        self.rate_ewma = 0.0

    async def add(self, nbytes: int) -> bool:
        if not self.ok:
            return False
        self.pending += nbytes
        now = time.monotonic()
        elapsed = now - self.last_check
        if self.pending >= self.batch_bytes or elapsed >= QUOTA_CHECK_INTERVAL:
            flush, self.pending = self.pending, 0
            if elapsed > 0:
                inst_rate = flush / elapsed
                self.rate_ewma = inst_rate if self.rate_ewma == 0 else (0.7 * self.rate_ewma + 0.3 * inst_rate)
                target = int(self.rate_ewma * QUOTA_CHECK_INTERVAL)
                self.batch_bytes = max(QUOTA_MIN_BATCH, min(QUOTA_MAX_BATCH, target or QUOTA_MIN_BATCH))
            self.last_check = now
            try:
                self.ok = await check_and_use(self.uuid, flush)
            except Exception as exc:
                logger.error(f"VLESS QuotaGate.add failed uuid={self.uuid[:8]}: {type(exc).__name__}: {exc}")
                self.ok = False
            return self.ok
        return True

    async def flush(self) -> bool:
        if self.pending:
            flush, self.pending = self.pending, 0
            try:
                self.ok = self.ok and await check_and_use(self.uuid, flush)
            except Exception as exc:
                logger.error(f"VLESS QuotaGate.flush failed uuid={self.uuid[:8]}: {type(exc).__name__}: {exc}")
                self.ok = False
        return self.ok


def _ws_client_ip(ws: WebSocket) -> str:
    from main import ip_from_headers
    return ip_from_headers(ws.headers, ws.client)



async def parse_vless_header(chunk: bytes):
    """هدر درخواست VLESS: ver(1) uuid(16) addon_len(1) addon cmd(1) port(2) atyp(1) addr.
    همه‌ی طول‌ها قبل از خواندن چک می‌شوند و فقط دستور TCP (1) پذیرفته می‌شود."""
    if len(chunk) < 24:
        raise ValueError("chunk too small")
    if chunk[0] != 0:
        raise ValueError(f"unsupported vless version: {chunk[0]}")
    pos = 17
    addon_len = chunk[pos]; pos += 1 + addon_len
    if len(chunk) < pos + 4:
        raise ValueError("truncated vless header")
    command = chunk[pos]; pos += 1
    if command != 1:
        raise ValueError(f"unsupported vless command {command} (only TCP is supported)")
    port = int.from_bytes(chunk[pos:pos+2], "big"); pos += 2
    if port == 0:
        raise ValueError("invalid port 0")
    addr_type = chunk[pos]; pos += 1
    if addr_type == 1:
        if len(chunk) < pos + 4:
            raise ValueError("truncated ipv4 address")
        address = ".".join(str(b) for b in chunk[pos:pos+4]); pos += 4
    elif addr_type == 2:
        dlen = chunk[pos] if len(chunk) > pos else 0; pos += 1
        if dlen == 0 or len(chunk) < pos + dlen:
            raise ValueError("bad domain length")
        address = chunk[pos:pos+dlen].decode("utf-8"); pos += dlen
    elif addr_type == 3:
        if len(chunk) < pos + 16:
            raise ValueError("truncated ipv6 address")
        address = str(ipaddress.IPv6Address(chunk[pos:pos+16])); pos += 16
    else:
        raise ValueError(f"unknown addr type: {addr_type}")
    return command, address, port, chunk[pos:]

async def check_and_use(uid: str, n: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            return False
        if not is_link_allowed(link):
            return False
        link["used_bytes"] += n
        stats["total_bytes"] += n
        hourly_traffic[now_ir().strftime("%H:00")] += n
    return True

async def relay_ws_to_tcp(ws: WebSocket, writer: asyncio.StreamWriter, conn_id: str, uid: str):
    gate = _QuotaGate(uid)
    conn = connections.get(conn_id)
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            if not await gate.add(len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            stats["total_requests"] += 1
            if conn is not None:
                conn["bytes"] += len(data)
            writer.write(data)
            # drain فقط وقتی واقعاً بافر پر باشه، نه هر بار (کاهش تاخیر)
            if writer.transport.get_write_buffer_size() > WRITE_HIGH_WATER:
                await writer.drain()
    except (WebSocketDisconnect, ConnectionError, RuntimeError):
        pass  # قطع عادی (کلاینت/مقصد اتصال را بست)
    except Exception as exc:
        logger.warning(f"VLESS relay ws→tcp [{conn_id}]: {type(exc).__name__}: {exc}")
    finally:
        await gate.flush()
        try:
            writer.write_eof()
        except Exception:
            pass

async def relay_tcp_to_ws(ws: WebSocket, reader: asyncio.StreamReader, conn_id: str, uid: str, vless_prefix: bool = True):
    gate = _QuotaGate(uid)
    conn = connections.get(conn_id)
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            if not await gate.add(len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            if conn is not None:
                conn["bytes"] += len(data)
            if vless_prefix and first:
                payload = b"\x00\x00" + data
                first = False
            else:
                payload = data
            await ws.send_bytes(payload)
    except (WebSocketDisconnect, ConnectionError, RuntimeError):
        pass  # قطع عادی (کلاینت/مقصد اتصال را بست)
    except Exception as exc:
        logger.warning(f"VLESS relay tcp→ws [{conn_id}]: {type(exc).__name__}: {exc}")
    finally:
        await gate.flush()

# اندپوینت websocket_tunnel به protocol/vless/websocket.py منتقل شد.