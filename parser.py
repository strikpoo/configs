# -*- coding: utf-8 -*-
"""
Парсер и сериализатор ссылок VPN-протоколов (VLESS, VMess).
"""

import json
import base64
import socket
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, Optional, Any

_DNS_CACHE: Dict[str, str] = {}

def resolve_to_ip(hostname: str) -> str:
    """Резолвит доменное имя в прямой IPv4 для обхода мобильных DNS-блокировок (МТС)."""
    if not hostname:
        return hostname
    parts = hostname.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return hostname
    if hostname in _DNS_CACHE:
        return _DNS_CACHE[hostname]
    try:
        ip = socket.gethostbyname(hostname)
        # Отсекаем локальные и фейковые NXDOMAIN-заглушки провайдеров
        if ip.startswith(("127.", "0.", "10.", "192.168.")) or ip == "76.223.54.146":
            _DNS_CACHE[hostname] = hostname
            return hostname
        _DNS_CACHE[hostname] = ip
        return ip
    except Exception:
        _DNS_CACHE[hostname] = hostname
        return hostname

@dataclass
class ProxyNode:
    raw_uri: str
    protocol: str
    uuid: str
    host: str
    port: int
    params: Dict[str, str] = field(default_factory=dict)
    name: str = ""
    sni: str = ""
    security: str = ""
    is_reality: bool = False
    is_whitelist_source: bool = False
    is_blacklist_source: bool = False
    gemini_ok: bool = False
    gemini_delay: float = 0.0
    tcp_ping: float = 0.0

    @property
    def unique_key(self) -> str:
        """Уникальный ключ для дедупликации серверов (строго физический сервер + учетные данные, без fp)."""
        pbk = self.params.get("pbk", "").strip().replace(" ", "+")
        net = self.params.get("type", "tcp").strip().lower()
        auth = self.uuid.strip().lower() if self.uuid else pbk
        return f"{self.protocol}@{self.host.lower()}:{self.port}@{auth}@{net}"

    def build_uri(self, new_name: Optional[str] = None) -> str:
        """Сборка нормализованной ссылки (vless:// или vmess://) с обновленным именем."""
        tag = new_name if new_name is not None else self.name

        if self.protocol == "vless":
            # Очистка мусорных и несовместимых параметров для мобильных клиентов
            clean_params = {}
            allowed_keys = {
                "security", "encryption", "pbk", "sid", "sni", "fp",
                "type", "flow", "path", "headerType", "host", "serviceName",
                "mode", "packetEncoding", "alpn", "allowInsecure", "insecure", "authority", "extra"
            }
            for k, v in self.params.items():
                if k not in allowed_keys:
                    continue
                if k in ("pbk", "sid") and not v.strip():
                    continue
                if k == "extra":
                    try:
                        json.loads(v)
                    except Exception:
                        continue
                # Чистим рекламный спам Telegram и битые значения host (напр. "/?")
                val_low = v.lower()
                if any(spam in val_low for spam in ("telegram.me", "telegram.org", "t.me/", "@")):
                    continue
                if k == "host" and ("/" in v or "?" in v):
                    continue
                clean_params[k] = v

            # Универсальный вид транспорта для всех клиентов (Sing-Box / Xray / INCY / Happ): raw -> tcp
            if clean_params.get("type", "").strip().lower() in ("raw", ""):
                clean_params["type"] = "tcp"

            # Не ломаем рабочий отпечаток сервера (firefox/ios/edge/safari/chrome); заменяем только пустой или qq/360
            fp_cur = (clean_params.get("fp") or "").strip().lower()
            valid_keep_fps = {"chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"}
            if fp_cur not in valid_keep_fps:
                clean_params["fp"] = "chrome"

            # Резолвим домен хоста в прямой IPv4 для обхода DNS-блокировок МТС
            host_ip = resolve_to_ip(self.host)
            # Сохраняем оригинальный домен в SNI и в HTTP Host (для WS/HTTP/xHTTP), если он не был явно задан
            if host_ip != self.host:
                if not clean_params.get("sni"):
                    clean_params["sni"] = self.host
                net_type = clean_params.get("type", "tcp").strip().lower()
                if net_type in ("ws", "http", "h2", "xhttp", "splithttp") and not clean_params.get("host"):
                    clean_params["host"] = self.host

            query = urllib.parse.urlencode(clean_params)
            fragment = urllib.parse.quote(tag) if tag else ""
            return f"vless://{self.uuid}@{host_ip}:{self.port}?{query}#{fragment}"
        elif self.protocol == "vmess":
            vmess_dict = {
                "v": "2",
                "ps": tag,
                "add": self.host,
                "port": str(self.port),
                "id": self.uuid,
                "aid": str(self.params.get("aid", "0")),
                "net": self.params.get("type", "ws"),
                "type": "none",
                "host": self.params.get("host", ""),
                "path": self.params.get("path", ""),
                "tls": self.security or "",
                "sni": self.sni or "",
                "scy": self.params.get("scy", "auto"),
                "fp": self.params.get("fp", "")
            }
            dumped = json.dumps(vmess_dict, ensure_ascii=False)
            encoded = base64.b64encode(dumped.encode("utf-8")).decode("utf-8")
            return f"vmess://{encoded}"

        return self.raw_uri

    def to_singbox_outbound(self, tag: str) -> Optional[Dict[str, Any]]:
        """Конвертация ProxyNode в sing-box outbound dictionary."""
        clean_uuid = self.uuid.strip()
        if len(clean_uuid) not in (32, 36) or not all(c in "0123456789abcdefABCDEF-" for c in clean_uuid):
            return None

        # --- 1. VMess Outbound ---
        if self.protocol == "vmess":
            outbound = {
                "type": "vmess",
                "tag": tag,
                "server": self.host,
                "server_port": self.port,
                "uuid": clean_uuid,
                "security": self.params.get("scy", "auto") or "auto",
                "alter_id": int(self.params.get("aid", "0") or "0")
            }
            if self.security == "tls" or self.sni:
                tls = {
                    "enabled": True,
                    "server_name": self.sni or self.params.get("host", "") or self.host
                }
                if self.params.get("allowInsecure") == "1" or self.params.get("insecure") == "1":
                    tls["insecure"] = True
                fp = self.params.get("fp", "chrome")
                if fp:
                    tls["utls"] = {"enabled": True, "fingerprint": fp}
                outbound["tls"] = tls

            net_type = self.params.get("type", "ws")
            if net_type == "ws":
                ws_cfg = {"type": "ws", "path": self.params.get("path", "/")}
                if self.params.get("host"):
                    ws_cfg["headers"] = {"Host": self.params["host"]}
                outbound["transport"] = ws_cfg
            elif net_type == "grpc":
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": self.params.get("serviceName", "") or self.params.get("path", "")
                }
            return outbound

        # --- 2. VLESS Outbound ---
        if self.protocol != "vless":
            return None

        outbound = {
            "type": "vless",
            "tag": tag,
            "server": self.host,
            "server_port": self.port,
            "uuid": clean_uuid
        }

        flow = self.params.get("flow", "").strip().lower()
        if "vision" in flow:
            outbound["flow"] = "xtls-rprx-vision"
            outbound["packet_encoding"] = "xudp"

        pbk_raw = self.params.get("pbk", "").strip().replace(" ", "+")
        sid = "".join(c for c in self.params.get("sid", "").strip() if c in "0123456789abcdefABCDEF")
        valid_fps = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}
        fp_raw = self.params.get("fp", "").strip().lower()
        fp = fp_raw if fp_raw in valid_fps else "chrome"

        if self.security in ("tls", "reality") or pbk_raw or self.is_reality:
            tls = {
                "enabled": True,
                "server_name": self.sni or self.host
            }
            if self.params.get("allowInsecure") == "1" or self.params.get("insecure") == "1":
                tls["insecure"] = True
            if fp:
                tls["utls"] = {"enabled": True, "fingerprint": fp}
            if pbk_raw or self.security == "reality":
                if len(pbk_raw) < 42 or len(pbk_raw) > 45:
                    return None
                padded = pbk_raw + "=" * ((4 - len(pbk_raw) % 4) % 4)
                valid_key = False
                for decoder in (base64.urlsafe_b64decode, base64.b64decode):
                    try:
                        raw_bytes = decoder(padded.encode("ascii"))
                        if len(raw_bytes) == 32:
                            valid_key = True
                            break
                    except Exception:
                        continue
                if not valid_key:
                    return None

                tls["reality"] = {
                    "enabled": True,
                    "public_key": pbk_raw,
                    "short_id": sid
                }
            outbound["tls"] = tls

        net_type = self.params.get("type", "tcp")
        if net_type == "grpc":
            service_name = self.params.get("serviceName", "") or self.params.get("path", "")
            outbound["transport"] = {
                "type": "grpc",
                "service_name": service_name
            }
        elif net_type == "ws":
            path = self.params.get("path", "/")
            ws_host = self.params.get("host", "")
            ws_cfg = {"type": "ws", "path": path}
            if ws_host:
                ws_cfg["headers"] = {"Host": ws_host}
            outbound["transport"] = ws_cfg
        elif net_type in ("http", "h2", "xhttp", "splithttp"):
            path = self.params.get("path", "/")
            h_host = self.params.get("host", "")
            outbound["transport"] = {
                "type": "http",
                "path": path,
                "host": [h_host] if h_host else []
            }

        return outbound


def decode_base64_content(data: str) -> str:
    """Безопасное декодирование строк Base64 с автодобавлением паддинга."""
    cleaned = data.strip().replace("\r\n", "").replace("\n", "")
    missing_padding = len(cleaned) % 4
    if missing_padding:
        cleaned += "=" * (4 - missing_padding)

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(cleaned.encode("utf-8"))
            return decoded.decode("utf-8", errors="ignore")
        except Exception:
            continue
    return data


def parse_vless_uri(uri: str, is_whitelist_source: bool = False, is_blacklist_source: bool = False) -> Optional[ProxyNode]:
    """Парсинг ссылки vless:// в объект ProxyNode."""
    uri = uri.strip()
    if not uri.startswith("vless://"):
        return None

    try:
        parsed = urllib.parse.urlparse(uri)
        userinfo = parsed.netloc
        if "@" not in userinfo:
            return None

        uuid, host_port = userinfo.split("@", 1)
        
        # Обработка IPv6 в скобках [2001:db8::1]:443
        if host_port.startswith("["):
            end_bracket = host_port.find("]")
            if end_bracket == -1:
                return None
            host = host_port[1:end_bracket]
            port_str = host_port[end_bracket+2:]
            port = int(port_str)
        else:
            if ":" not in host_port:
                return None
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)

        name = urllib.parse.unquote(parsed.fragment).strip()
        query_str = parsed.query
        if "#" in query_str:
            query_str, embedded_frag = query_str.split("#", 1)
            if not name:
                name = urllib.parse.unquote(embedded_frag).strip()
        query_dict = urllib.parse.parse_qs(query_str)
        params: Dict[str, str] = {k: v[0].split("#")[0].strip() for k, v in query_dict.items() if v}
        sni = params.get("sni", "").strip().lower()
        security = params.get("security", "").strip().lower()
        pbk = params.get("pbk", "").strip().replace(" ", "+")
        params["pbk"] = pbk

        is_reality = (security == "reality") or bool(pbk)

        return ProxyNode(
            raw_uri=uri,
            protocol="vless",
            uuid=uuid,
            host=host.strip(),
            port=port,
            params=params,
            name=name,
            sni=sni,
            security=security,
            is_reality=is_reality,
            is_whitelist_source=is_whitelist_source,
            is_blacklist_source=is_blacklist_source
        )
    except Exception:
        return None


def parse_vmess_uri(uri: str, is_whitelist_source: bool = False) -> Optional[ProxyNode]:
    """Парсинг ссылки vmess:// в объект ProxyNode."""
    uri = uri.strip()
    if not uri.startswith("vmess://"):
        return None

    try:
        raw_b64 = uri[8:].strip()
        decoded_str = decode_base64_content(raw_b64)
        data = json.loads(decoded_str)

        uuid = str(data.get("id", "")).strip()
        host = str(data.get("add", "")).strip()
        port_raw = data.get("port", 0)
        port = int(port_raw)
        if not uuid or not host or not port:
            return None

        name = str(data.get("ps", "")).strip()
        net = str(data.get("net", "ws")).strip().lower()
        sec = str(data.get("tls", "")).strip().lower()
        sni = str(data.get("sni", "")).strip().lower()
        ws_host = str(data.get("host", "")).strip()
        path = str(data.get("path", "")).strip()
        fp = str(data.get("fp", "")).strip()
        scy = str(data.get("scy", "auto")).strip()
        aid = str(data.get("aid", "0")).strip()

        if sec == "tls" and not sni and ws_host:
            sni = ws_host.lower()

        params = {
            "type": net,
            "security": sec,
            "sni": sni,
            "host": ws_host,
            "path": path,
            "fp": fp or "chrome",
            "scy": scy,
            "aid": aid
        }

        return ProxyNode(
            raw_uri=uri,
            protocol="vmess",
            uuid=uuid,
            host=host,
            port=port,
            params=params,
            name=name,
            sni=sni,
            security=sec,
            is_reality=False,
            is_whitelist_source=is_whitelist_source
        )
    except Exception:
        return None


def parse_proxy_uri(uri: str, is_whitelist_source: bool = False, is_blacklist_source: bool = False) -> Optional[ProxyNode]:
    """Универсальный парсер ссылок vless:// и vmess://."""
    uri = uri.strip()
    if uri.startswith("vless://"):
        return parse_vless_uri(uri, is_whitelist_source=is_whitelist_source, is_blacklist_source=is_blacklist_source)
    elif uri.startswith("vmess://"):
        return parse_vmess_uri(uri, is_whitelist_source=is_whitelist_source)
    return None
