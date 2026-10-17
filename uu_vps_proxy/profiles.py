"""Proxy parsing and private file storage; no application-specific auth state."""
import json
import os
import tempfile
from urllib.parse import unquote, urlsplit


class Error(Exception):
    pass


PROXY_TYPES = {"socks", "http", "shadowsocks", "trojan", "vless", "vmess", "anytls", "hysteria2", "tuic"}


def proxy_from_url(url):
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https", "socks5", "socks5h"}:
            raise ValueError()
        if not parsed.hostname or not parsed.port or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError()
        outbound = {"type": "socks" if parsed.scheme.startswith("socks") else "http",
                    "server": parsed.hostname, "server_port": parsed.port}
        if outbound["type"] == "socks":
            outbound["version"] = "5"
        if parsed.username is not None:
            outbound["username"] = unquote(parsed.username)
        if parsed.password is not None:
            outbound["password"] = unquote(parsed.password)
        if parsed.scheme == "https":
            outbound["tls"] = {"enabled": True, "server_name": parsed.hostname}
        return outbound
    except (ValueError, TypeError):
        raise Error("代理地址须为 http(s):// 或 socks5(h)://主机:端口（可含认证）") from None


def validate(profile):
    if not isinstance(profile, dict):
        raise Error("出口配置必须是 JSON 对象")
    outbound = profile.get("outbound", {})
    if not isinstance(outbound, dict) or outbound.get("type") not in PROXY_TYPES or not isinstance(outbound.get("server"), str) or not outbound["server"]:
        raise Error("须提供单个固定代理 outbound，不支持 direct 或自动回退")
    port = outbound.get("server_port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise Error("代理端口须为 1–65535")
    if any(key in outbound for key in ("detour", "netns", "network_namespace", "bind_interface")):
        raise Error("代理配置不允许 detour/netns/bind_interface")
    tls = outbound.get("tls", {})
    if not isinstance(tls, dict) or tls.get("insecure"):
        raise Error("TLS 配置须有效且不能关闭证书验证")
    return profile


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise Error("配置目录不安全")
    os.chmod(path.parent, 0o700)
    fd, name = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)
