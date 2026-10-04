# xhttshadpacketup.py (trojan)
# ══════════════════════════════════════════════════════════════════════════════
# XHTTP — آپلینک packet-up (با seq) اختصاصی Trojan.
# مستقل از موتور VLESS، مسیر با پیشوند /txhttp-siz10.
# ══════════════════════════════════════════════════════════════════════════════

import time
import traceback
from datetime import datetime

from fastapi import APIRouter, Request, HTTPException
from starlette.requests import ClientDisconnect

from main import stats, connections, error_logs, logger
from protocol.vless.vless import check_and_use
from protocol.trojan.xhttp_core import (
    TROJAN_PACKET_UP_HIGH_WATER,
    ensure_reaper,
    _get_or_create_session,
    _open_tcp_for_session,
    _req_client_ip,
    _teardown,
)

router = APIRouter()

# سقف بافر بسته‌های خارج از ترتیب برای هر session (جلوگیری از پر شدن حافظه با seq های بزرگ)
SEQ_BUF_MAX_PACKETS = 256
SEQ_BUF_MAX_BYTES = 16 * 1024 * 1024


def _buffer_packet(sess: dict, seq: int, body: bytes):
    buf = sess["seq_buf"]
    old = len(buf.get(seq, b""))
    if (len(buf) >= SEQ_BUF_MAX_PACKETS and seq not in buf) or \
            sum(len(v) for v in buf.values()) - old + len(body) > SEQ_BUF_MAX_BYTES:
        raise ValueError("packet-up reorder buffer limit exceeded")
    buf[seq] = body


@router.post("/txhttp-siz10/packet-up/{uuid}/{session_id}/{seq}")
async def trojan_packet_up_upload(uuid: str, session_id: str, seq: int, request: Request):
    ensure_reaper()
    sess = await _get_or_create_session(uuid, "packet-up", session_id, _req_client_ip(request))
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    sess["last_seen"] = time.time()
    try:
        body = await request.body()
    except ClientDisconnect:
        logger.info(f"Trojan-XHTTP[packet-up] [{session_id[:8]}] client disconnected mid-body (seq={seq}), session kept alive")
        return {"ok": True, "aborted": True}

    if not body:
        return {"ok": True}

    if not await check_and_use(uuid, len(body)):
        await _teardown(session_id, reason="quota/disabled/unknown")
        raise HTTPException(status_code=403, detail="quota/disabled/unknown")

    stats["total_requests"] += 1
    connections[sess["conn_id"]]["bytes"] += len(body)

    try:
        if sess["writer"] is None:
            if seq != 0:
                _buffer_packet(sess, seq, body)
                return {"ok": True, "buffered": True}
            await _open_tcp_for_session(session_id, uuid, sess, body)
            nxt = 1
            while nxt in sess["seq_buf"]:
                pending = sess["seq_buf"].pop(nxt)
                if sess["writer"].is_closing():
                    raise ConnectionError("transport closing")
                sess["writer"].write(pending)
                nxt += 1
            sess["next_seq"] = nxt
            return {"ok": True, "connected": True}

        if seq == sess["next_seq"]:
            if sess["writer"].is_closing():
                raise ConnectionError("transport closing")
            sess["writer"].write(body)
            sess["next_seq"] += 1
            while sess["next_seq"] in sess["seq_buf"]:
                pending = sess["seq_buf"].pop(sess["next_seq"])
                if sess["writer"].is_closing():
                    raise ConnectionError("transport closing")
                sess["writer"].write(pending)
                sess["next_seq"] += 1
        else:
            _buffer_packet(sess, seq, body)

        if sess["writer"].transport.get_write_buffer_size() > TROJAN_PACKET_UP_HIGH_WATER:
            await sess["writer"].drain()
    except Exception as exc:
        tb = traceback.format_exc()
        logger.error(f"Trojan-XHTTP[packet-up] [{session_id[:8]}] upload FAILED seq={seq}: {type(exc).__name__}: {exc}\n{tb}")
        error_logs.append({"error": f"trojan packet-up write failed: {type(exc).__name__}: {exc}", "time": datetime.now().isoformat()})
        await _teardown(session_id, reason=f"write-failed: {type(exc).__name__}")
        raise HTTPException(status_code=502, detail="write failed")

    return {"ok": True}