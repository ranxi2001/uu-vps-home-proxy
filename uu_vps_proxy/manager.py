"""Root-managed, UID-scoped desktop TUN; independent of session namespaces."""
import argparse
import getpass
import ipaddress
import json
import os
import pwd
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from zoneinfo import ZoneInfo

from .profiles import Error, atomic_json, proxy_from_url, validate
from . import __version__

BASE = Path("/etc/uu-vps-home-proxy/users")
TOOL = Path("/usr/local/bin/uu-vps-proxy")
ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


def command(args, *, data=None, allow_failure=False, timeout=35):
    result = subprocess.run(args, input=data, env=ENV, text=True, capture_output=True, timeout=timeout)
    if result.returncode and not allow_failure:
        raise Error(f"{Path(args[0]).name} 失败（{result.returncode}）；未输出可能包含认证的日志")
    return result


def username(value):
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", value):
        raise Error("用户名须为普通 Linux 登录用户名")
    account = pwd.getpwnam(value)
    if account.pw_uid == 0:
        raise Error("不能为 root 配置桌面用户 TUN")
    return account


def load(user):
    account = username(user)
    state = json.loads((BASE / user / "state.json").read_text())
    if state["uid"] != account.pw_uid or state["user"] != user:
        raise Error("用户 UID 已变化，停止以避免影响其他用户")
    return state


def save(state):
    atomic_json(BASE / state["user"] / "state.json", state)


def table_name(state):
    return f"uuvps_uid_{state['uid']}"


def cgroup_path(state, unit):
    return f"user.slice/user-{state['uid']}.slice/user@{state['uid']}.service/app.slice/{unit}"


def guard_rules(state, cgroups):
    table = table_name(state)
    uid, mark, interface, port = state["uid"], state["mark"], state["interface"], state["dns_port"]
    subnet = str(ipaddress.IPv4Network(state["address"], strict=False))
    marking = "\n".join(f'  meta skuid {uid} socket cgroupv2 level {len(path.split("/"))} {json.dumps(path)} meta mark set {mark}' for path in cgroups)
    addresses = state.get("bypass_ipv4", [])
    bypass_set = (' set control_v4 { type ipv4_addr; flags interval; elements = { ' + ', '.join(addresses) + ' } }\n') if addresses else ''
    bypass_rule = f'  meta skuid {uid} ip daddr @control_v4 tcp dport 443 meta mark set {mark}\n' if addresses else ''
    tcp_ports = ', '.join(map(str, state.get('bypass_tcp_ports', [])))
    udp_ports = ', '.join(map(str, state.get('bypass_udp_ports', [])))
    tcp_elements = f'elements = {{ {tcp_ports} }}' if tcp_ports else ''
    udp_elements = f'elements = {{ {udp_ports} }}' if udp_ports else ''
    return f'''table inet {table} {{
{bypass_set}
 set control_tcp_ports {{ type inet_service; {tcp_elements} }}
 set control_udp_ports {{ type inet_service; {udp_elements} }}
 chain route_out {{
  type route hook output priority mangle; policy accept;
  ct mark {mark} meta mark set {mark}
{bypass_rule}
  meta skuid {uid} tcp sport @control_tcp_ports meta mark set {mark}
  meta skuid {uid} udp sport @control_udp_ports meta mark set {mark}
{marking}
  meta mark {mark} ct mark set {mark}
 }}
 chain dns_out {{
  type nat hook output priority dstnat; policy accept;
  meta skuid {uid} meta mark != {mark} udp dport 53 counter redirect to :{port}
  meta skuid {uid} meta mark != {mark} tcp dport 53 counter redirect to :{port}
 }}
 chain protect_out {{
  type filter hook output priority -5; policy accept;
  meta skuid {uid} meta mark {mark} counter accept
  meta skuid {uid} oifname "lo" accept
  meta skuid {uid} meta nfproto ipv6 counter reject
  meta skuid {uid} oifname "{interface}" counter accept
  meta skuid {uid} counter reject
 }}
 chain source_fix {{
  type nat hook postrouting priority srcnat; policy accept;
  meta mark {mark} ip saddr {subnet} oifname != "{interface}" oifname != "lo" counter masquerade
 }}
}}
'''


def config_for(state, outbound):
    proxy = dict(outbound, tag="home")
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {"servers": [{"type": "https", "tag": "remote", "server": "1.1.1.1", "server_port": 443,
                              "tls": {"enabled": True, "server_name": "cloudflare-dns.com"}, "path": "/dns-query", "detour": "home"},
                             {"type": "local", "tag": "bootstrap"}], "final": "remote", "strategy": "ipv4_only"},
        "inbounds": [{"type": "tun", "tag": "desktop", "interface_name": state["interface"],
                      "address": [state["address"]], "mtu": 1500, "include_uid": [state["uid"]],
                      "auto_route": True, "auto_redirect": False, "strict_route": True, "dns_mode": "disabled",
                      "iproute2_table_index": state["route_table"], "iproute2_rule_index": state["priority"] + 1,
                      "auto_redirect_iproute2_fallback_rule_index": state["priority"] + 16},
                     {"type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": state["dns_port"]}],
        "outbounds": [proxy, {"type": "direct", "tag": "direct"}],
        "route": {"auto_detect_interface": True, "default_domain_resolver": "bootstrap", "final": "home",
                  "rules": [{"inbound": "dns-in", "action": "hijack-dns"},
                            {"port": 53, "action": "hijack-dns"},
                            {"process_name": ["uuremote-server"], "outbound": "direct"},
                            {"ip_version": 6, "action": "reject"},
                            {"ip_is_private": True, "outbound": "direct"}]}}


def checked_rule(state, family):
    rules = json.loads(command(["ip", family, "-j", "rule", "show"]).stdout)
    found = [rule for rule in rules if rule.get("priority") == state["priority"]]
    if found and (len(found) != 1 or int(str(found[0].get("fwmark", "0")), 0) != state["mark"] or found[0].get("table") != "main"):
        raise Error("策略路由优先级被其他程序占用；未覆盖")
    return bool(found)


def refresh(state):
    if not state["enabled"]:
        return
    # Keep already-established remote-control connections on their original
    # route even if socket/cgroup lookup is unavailable for later packets.
    addresses = set(state.get("bypass_ipv4", []))
    if state["bypass_units"]:
        # Public STUN servers must NOT be globally bypassed: a browser may use
        # the same server. UDP exceptions below are scoped to UU's live sockets.
        for host in ("api.nrd.nie.163.com",):
            try:
                addresses.update(item[4][0] for item in socket.getaddrinfo(host, None, socket.AF_INET))
            except OSError:
                pass
        sockets = command(["ss", "-Hntup"], allow_failure=True).stdout
        for line in sockets.splitlines():
            if '"uuremote-server"' not in line:
                continue
            fields = line.split()
            if len(fields) < 6:
                continue
            try:
                addresses.add(str(ipaddress.IPv4Address(fields[5].rsplit(":", 1)[0])))
            except ValueError:
                pass
    state["bypass_ipv4"] = sorted(addresses, key=ipaddress.IPv4Address)
    state["bypass_tcp_ports"], state["bypass_udp_ports"] = control_ports(state)
    # OUTPUT marks run after the initial source-address choice. Preserve the
    # existing remote desktop's UDP source before installing the UID TUN rule.
    # New sockets created with TUN already active use source_fix below.
    if not Path(f"/sys/class/net/{state['interface']}").exists():
        for port in state.get("native_udp_ports", []):
            command(["ip", "-4", "rule", "delete", "priority", str(state["priority"] - 1),
                     "uidrange", f"{state['uid']}-{state['uid']}", "ipproto", "udp", "sport", str(port), "lookup", "main"], allow_failure=True)
        state["native_udp_ports"] = state["bypass_udp_ports"]
        for port in state["native_udp_ports"]:
            command(["ip", "-4", "rule", "add", "priority", str(state["priority"] - 1),
                     "uidrange", f"{state['uid']}-{state['uid']}", "ipproto", "udp", "sport", str(port), "lookup", "main"])
    save(state)
    groups = [cgroup_path(state, unit) for unit in state["bypass_units"]
              if (Path("/sys/fs/cgroup") / cgroup_path(state, unit)).exists()]
    rules = guard_rules(state, groups)
    if command(["nft", "list", "table", "inet", table_name(state)], allow_failure=True).returncode == 0:
        rules = f"delete table inet {table_name(state)}\n" + rules
    present = {family: checked_rule(state, family) for family in ("-4", "-6")}
    command(["nft", "--check", "-f", "-"], data=rules)
    # Bypass policy exists before turning on the kill switch, so an established
    # UU Remote TCP/UDP connection never moves into a fresh TUN TCP stack.
    for family in ("-4", "-6"):
        if not present[family]:
            command(["ip", family, "rule", "add", "priority", str(state["priority"]),
                     "fwmark", str(state["mark"]), "lookup", "main"])
    command(["nft", "-f", "-"], data=rules)


def control_ports(state):
    if not state["bypass_units"]:
        return [], []
    pids = set()
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            if process.stat().st_uid == state["uid"] and (process / "comm").read_text().strip() == "uuremote-server":
                pids.add(process.name)
        except OSError:
            pass
    tcp, udp = set(), set()
    if not pids:
        return [], []
    for line in command(["ss", "-Hantup"], allow_failure=True).stdout.splitlines():
        if not any(f"pid={pid}," in line for pid in pids):
            continue
        fields = line.split()
        if len(fields) < 5:
            continue
        try:
            port = int(fields[4].rsplit(":", 1)[1])
            if 0 < port < 65536:
                (udp if fields[0] == "udp" else tcp).add(port)
        except (ValueError, IndexError):
            pass
    return sorted(tcp), sorted(udp)


def watch(user):
    last = None
    while True:
        state = load(user)
        if not state["enabled"]:
            return
        ports = control_ports(state)
        if ports != last:
            table = table_name(state)
            commands = []
            for kind, values in zip(("tcp", "udp"), ports):
                name = f"control_{kind}_ports"
                commands.append(f"flush set inet {table} {name}")
                if values:
                    commands.append(f"add element inet {table} {name} {{ " + ', '.join(map(str, values)) + " }")
            command(["nft", "-f", "-"], data='\n'.join(commands) + '\n')
            last = ports
        time.sleep(0.5)


def guard_off(state):
    if command(["nft", "list", "table", "inet", table_name(state)], allow_failure=True).returncode == 0:
        command(["nft", "delete", "table", "inet", table_name(state)])
    for family in ("-4", "-6"):
        if checked_rule(state, family):
            command(["ip", family, "rule", "delete", "priority", str(state["priority"]), "fwmark", str(state["mark"]), "lookup", "main"])
    for port in state.get("native_udp_ports", []):
        command(["ip", "-4", "rule", "delete", "priority", str(state["priority"] - 1),
                 "uidrange", f"{state['uid']}-{state['uid']}", "ipproto", "udp", "sport", str(port), "lookup", "main"], allow_failure=True)


def write_text(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".uu-vps-proxy-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(content)
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def user_systemctl(state, *arguments, allow_failure=False):
    uid = state["uid"]
    return command(["runuser", "-u", state["user"], "--", "env", f"XDG_RUNTIME_DIR=/run/user/{uid}",
                    f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus", "systemctl", "--user", *arguments],
                   allow_failure=allow_failure)


def trusted_tool():
    # Automatic service refresh grants only this fixed operation. Never point
    # its sudo rule or root services at a user's writable installation.
    if not TOOL.is_file():
        raise Error("请先执行 sudo python3 install.py --prefix /usr/local 安装系统管理入口")
    paths = [TOOL, Path(__file__), Path(__file__).with_name("entry.py")]
    for path in paths:
        for component in (path.resolve(), *path.resolve().parents):
            info = component.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise Error("请先以 root 将启动器安装到 /usr/local；特权入口不得位于用户可写目录")


def install_units(state):
    trusted_tool()
    write_text(Path("/etc/systemd/system/uuvps-guard@.service"), '''[Unit]
Description=Per-user TUN DNS and egress guard for %i
Before=uuvps-tun@%i.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/uu-vps-proxy refresh %i
ExecStop=/usr/local/bin/uu-vps-proxy guard-off %i
''')
    write_text(Path("/etc/systemd/system/uuvps-tun@.service"), '''[Unit]
Description=Residential TUN for Linux user %i
Wants=network-online.target uuvps-bypass@%i.service
After=network-online.target uuvps-guard@%i.service
Requires=uuvps-guard@%i.service
[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/uu-vps-home-proxy/users/%i/sing-box.json
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=read-only
UMask=0077
[Install]
WantedBy=multi-user.target
''')
    write_text(Path("/etc/systemd/system/uuvps-bypass@.service"), '''[Unit]
Description=Keep remote-control socket bypasses current for %i
After=uuvps-guard@%i.service
Requires=uuvps-guard@%i.service
PartOf=uuvps-tun@%i.service
[Service]
ExecStart=/usr/local/bin/uu-vps-proxy watch %i
Restart=on-failure
RestartSec=1
NoNewPrivileges=yes
''')
    if state["bypass_units"]:
        helper = Path("/usr/local/sbin") / f"uu-vps-proxy-refresh-{state['user']}"
        write_text(helper, f'#!/bin/sh\n[ "$#" -eq 0 ] || exit 2\nexec /usr/local/bin/uu-vps-proxy refresh {shlex.quote(state["user"])}\n', 0o755)
        sudoers = Path("/etc/sudoers.d") / f"uu-vps-proxy-{state['user']}"
        text = f'{state["user"]} ALL=(root) NOPASSWD: {helper} ""\n'
        fd, candidate = tempfile.mkstemp(prefix="uu-vps-proxy-sudoers-", dir="/run")
        try:
            os.write(fd, text.encode())
            os.close(fd)
            command(["visudo", "-cf", candidate])
            write_text(sudoers, text, 0o440)
        finally:
            Path(candidate).unlink(missing_ok=True)
        account = username(state["user"])
        for unit in state["bypass_units"]:
            path = Path(account.pw_dir) / ".config/systemd/user" / f"{unit}.d/90-uu-vps-proxy-bypass.conf"
            if path.exists() and not path.read_text().startswith("# Managed by uu-vps-proxy"):
                raise Error("远程控制服务已有同名覆写，未覆盖")
            write_text(path, f"# Managed by uu-vps-proxy: refresh cgroup identity before the host starts.\n[Service]\nExecStartPre=/usr/bin/sudo -n {helper}\n")
            os.chown(path, account.pw_uid, account.pw_gid)
        user_systemctl(state, "daemon-reload")
    command(["systemctl", "daemon-reload"])


def configure(args):
    trusted_tool()
    account = username(args.user)
    directory = BASE / args.user
    old_state = load(args.user) if (directory / "state.json").exists() else None
    if old_state and (not args.replace or old_state["enabled"]):
        raise Error("该用户已有配置；先 off，再用 configure --replace 明确替换")
    if args.profile:
        raw = json.loads(args.profile.read_text())
        profile = raw if isinstance(raw, dict) and "outbound" in raw else {"outbound": raw}
        validate(profile)
        outbound = profile["outbound"]
    else:
        outbound = proxy_from_url(args.proxy or getpass.getpass("家宽代理 URL（隐藏输入）> "))
    validate({"name": "desktop", "outbound": outbound})
    for unit in args.bypass_unit:
        if not re.fullmatch(r"[A-Za-z0-9_@.:-]+\.service", unit):
            raise Error("无效的用户服务名")
    used = {json.loads(path.read_text())["slot"] for path in BASE.glob("*/state.json")}
    slot = old_state["slot"] if old_state else next((number for number in range(400) if number not in used), None)
    if slot is None:
        raise Error("没有可用的配置槽")
    address = ipaddress.IPv4Address("172.29.128.1") + slot * 4
    state = {"user": args.user, "uid": account.pw_uid, "slot": slot, "enabled": False,
             "interface": f"uuvps{account.pw_uid}", "address": f"{address}/30", "dns_port": 10530 + slot,
             "mark": 0x0A550000 + slot, "priority": 14000 + slot * 32, "route_table": 50000 + slot,
             "bypass_units": args.bypass_unit or (old_state["bypass_units"] if old_state else []),
             "bypass_ipv4": args.bypass_ip or (old_state.get("bypass_ipv4", []) if old_state else []),
             "expected_ip": None, "timezone": None}
    for ip in state["bypass_ipv4"]:
        ipaddress.IPv4Address(ip)
    if Path(f"/sys/class/net/{state['interface']}").exists():
        raise Error("目标 TUN 名称已被占用")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    config_path = directory / "sing-box.json"
    previous = config_path.read_text() if config_path.exists() else None
    try:
        atomic_json(config_path, config_for(state, outbound))
        command(["sing-box", "check", "-c", str(config_path)])
    except BaseException:
        if previous is None:
            config_path.unlink(missing_ok=True)
        else:
            write_text(config_path, previous, 0o600)
        raise
    save(state)
    install_units(state)
    print(f"已配置 {args.user}（UID {account.pw_uid}）；运行 uu-vps-proxy on {args.user} 启用")


def check(state):
    url = "https://ipinfo.io/json"
    result = command(["runuser", "-u", state["user"], "--", "curl", "--proxy", "", "--noproxy", "*", "-4",
                      "--fail", "--silent", "--show-error", "--connect-timeout", "8", "--max-time", "20", url])
    try:
        data = json.loads(result.stdout)
        observed = {"ip": str(ipaddress.IPv4Address(data["ip"])), "timezone": data["timezone"],
                    "country": data.get("country", ""), "city": data.get("city", ""), "org": data.get("org", "")}
        ZoneInfo(observed["timezone"])
    except (KeyError, TypeError, ValueError):
        raise Error("出口服务返回无效结果") from None
    if state["expected_ip"] and state["expected_ip"] != observed["ip"]:
        raise Error("实际出口与绑定 IP 不同")
    print(json.dumps(observed, ensure_ascii=False, indent=2))
    return observed


def timezone_for_user(state, timezone):
    account = username(state["user"])
    path = Path(account.pw_dir) / ".config/environment.d/95-uu-vps-proxy.conf"
    for directory in (path.parent.parent, path.parent):
        if not directory.exists():
            directory.mkdir(mode=0o700)
            os.chown(directory, account.pw_uid, account.pw_gid)
    if path.exists() and not path.read_text().startswith("# Managed by uu-vps-proxy"):
        raise Error("已有同名用户时区配置，未覆盖")
    write_text(path, f"# Managed by uu-vps-proxy\nTZ={timezone}\n")
    os.chown(path, account.pw_uid, account.pw_gid)
    user_systemctl(state, "set-environment", f"TZ={timezone}", allow_failure=True)


def on(state):
    state["enabled"] = True
    save(state)
    unit = f"uuvps-tun@{state['user']}.service"
    try:
        command(["systemctl", "enable", "--now", unit])
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not Path(f"/sys/class/net/{state['interface']}").exists():
            time.sleep(0.1)
        observed = check(state)
        state.update(load(state["user"]))
        state.update(expected_ip=observed["ip"], timezone=observed["timezone"])
        save(state)
        timezone_for_user(state, observed["timezone"])
        print("用户级 TUN 已启用并固定出口；已打开的 GUI 程序重开后读取新时区。")
    except BaseException:
        off(state)
        raise


def off(state):
    state["enabled"] = False
    save(state)
    command(["systemctl", "disable", "--now", f"uuvps-tun@{state['user']}.service"], allow_failure=True)
    command(["systemctl", "stop", f"uuvps-bypass@{state['user']}.service"], allow_failure=True)
    command(["systemctl", "stop", f"uuvps-guard@{state['user']}.service"], allow_failure=True)
    guard_off(state)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="uu-vps-proxy", description="按 Linux 用户管理桌面全局 TUN 与固定代理出口（需要 root）")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="action", required=True)
    setup = sub.add_parser("configure", help="配置指定用户，认证默认隐藏输入")
    setup.add_argument("user")
    choice = setup.add_mutually_exclusive_group()
    choice.add_argument("--proxy")
    choice.add_argument("--profile", type=Path, help="复用 sing-box 出口 JSON")
    setup.add_argument("--bypass-unit", action="append", default=[], help="保持直连的远程控制用户服务")
    setup.add_argument("--bypass-ip", action="append", default=[], help="额外保持直连的 IPv4 地址")
    setup.add_argument("--replace", action="store_true", help="明确替换一个已经关闭的用户配置")
    for action in ("on", "off", "status", "check", "refresh", "guard-off", "watch"):
        item = sub.add_parser(action)
        item.add_argument("user")
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise Error("请使用 sudo uu-vps-proxy；只管理指定用户的路由和本工具自己的防火墙表")
        if args.action == "configure":
            configure(args)
            return 0
        state = load(args.user)
        if args.action == "on":
            on(state)
        elif args.action == "off":
            off(state)
        elif args.action == "check":
            check(state)
        elif args.action == "refresh":
            refresh(state)
        elif args.action == "guard-off":
            guard_off(state)
        elif args.action == "watch":
            watch(args.user)
        else:
            unit = f"uuvps-tun@{state['user']}.service"
            status = command(["systemctl", "is-active", unit], allow_failure=True).stdout.strip()
            print(json.dumps({key: state[key] for key in ("user", "uid", "enabled", "interface", "expected_ip", "timezone", "bypass_units")}, ensure_ascii=False, indent=2))
            print("service:", status)
        return 0
    except (Error, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print("错误：" + (str(error) if isinstance(error, Error) else type(error).__name__), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
