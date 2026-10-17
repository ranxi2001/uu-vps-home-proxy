#!/usr/bin/env python3
"""Install the independent management tool without pip or runtime dependencies."""
import argparse
import os
import shlex
import shutil
import sys
import tempfile
import uuid
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="安装 UU VPS Home Proxy；不会启停网络或覆盖用户配置")
    parser.add_argument("--prefix", type=Path, default=Path("/usr/local"))
    args = parser.parse_args()
    if sys.platform != "linux" or sys.version_info < (3, 11):
        parser.error("需要 Linux 和 Python >= 3.11")
    source = Path(__file__).resolve().parent
    prefix = args.prefix.expanduser().resolve()
    shared = prefix / "share/uu-vps-home-proxy"
    shared.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="version-", dir=shared))
    try:
        shutil.copytree(source / "uu_vps_proxy", stage / "uu_vps_proxy", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for name in ("README.md", "LICENSE", "CHANGELOG.md", "THIRD_PARTY.md"):
            shutil.copy2(source / name, stage / name)
        for name in ("docs", "deploy"):
            shutil.copytree(source / name, stage / name)
        replacement = shared / (".current-" + uuid.uuid4().hex)
        replacement.symlink_to(stage.name, target_is_directory=True)
        os.replace(replacement, shared / "current")
        binary = prefix / "bin/uu-vps-proxy"
        binary.parent.mkdir(parents=True, exist_ok=True)
        script = "#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -I " + shlex.quote(str(shared / "current/uu_vps_proxy/entry.py")) + ' "$@"\n'
        fd, candidate = tempfile.mkstemp(prefix=".uu-vps-proxy-", dir=binary.parent)
        with os.fdopen(fd, "w") as stream:
            stream.write(script)
        os.chmod(candidate, 0o755)
        os.replace(candidate, binary)
        print(f"已安装：{binary}\n安装过程未改动现有网络或启动服务。")
    except BaseException:
        if not (shared / "current").exists() or (shared / "current").resolve() != stage:
            shutil.rmtree(stage, ignore_errors=True)
        raise


if __name__ == "__main__":
    main()
