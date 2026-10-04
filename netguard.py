# netguard.py — اتصال خروجی تونل‌ها فقط به مقصدهای عمومی.
# بدون این، دارنده‌ی هر لینک می‌تواند از طریق تونل به localhost (خود پنل، mtg)،
# شبکه‌ی خصوصی کانتینر یا metadata ابر (169.254.169.254) وصل شود.
# نام دامنه یک‌بار resolve می‌شود و به همان IP تأییدشده وصل می‌شویم، تا DNS rebinding
# (جواب عمومی در بررسی، جواب داخلی در اتصال) ممکن نباشد.
# ALLOW_PRIVATE_DESTINATIONS=1 همه‌ی این محدودیت‌ها را خاموش می‌کند.
import asyncio
import ipaddress
import os
import socket

ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE_DESTINATIONS", "") == "1"


class BlockedDestination(ConnectionError):
    pass


def _is_public(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


async def open_public_connection(host: str, port: int, timeout: float = 10.0):
    """مثل asyncio.open_connection ولی فقط به آدرس‌های عمومی؛ وگرنه BlockedDestination."""
    if ALLOW_PRIVATE:
        return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    if not 0 < port < 65536:
        raise BlockedDestination(f"invalid port {port}")
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=timeout
        )
    except socket.gaierror as exc:
        raise ConnectionError(f"dns failed for {host}: {exc}") from exc
    addrs = []
    for _fam, _t, _p, _c, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0].split("%")[0])
        except ValueError:
            continue
        if not _is_public(ip):
            raise BlockedDestination(f"destination {host} resolves to non-public address {ip}")
        addrs.append(sockaddr[0])
    if not addrs:
        raise ConnectionError(f"no address for {host}")
    last_exc: Exception | None = None
    for addr in addrs:
        try:
            return await asyncio.wait_for(asyncio.open_connection(addr, port), timeout=timeout)
        except (OSError, asyncio.TimeoutError) as exc:
            last_exc = exc
    raise last_exc  # type: ignore[misc]
