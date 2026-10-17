# 新 VPS 部署

目标结构是一个普通桌面用户运行 UU 与桌面应用，root 管理该 UID 的代理与网络例外。现有桌面无需重新放进容器。

## 1. 准备用户与依赖

Debian/Ubuntu 示例，`desktop` 换成自己的用户名：

```bash
sudo useradd --create-home --shell /bin/bash desktop
sudo passwd desktop
sudo loginctl enable-linger desktop
sudo apt-get install python3 iproute2 nftables curl util-linux sudo tzdata
```

已有用户时跳过创建与密码步骤。无需把桌面用户设为 root；网络管理命令由管理员执行。

按 [sing-box 官方安装说明](https://sing-box.sagernet.org/installation/package-manager/)安装 1.14.0+。当前测试内核为 1.14.3。不要替换机器上其他代理服务的配置或监听端口。

## 2. 先完成 UU Linux 桌面

按 [UU Linux 主机上游文档](https://github.com/VallierDev/uu-remote-linux)安装主机。无显示器 VPS 使用该项目的 `contrib/virtual-desktop/` 方案准备 Xvfb、桌面会话与 Xauthority；有物理桌面的机器使用其对应显示配置。

在桌面用户会话内完成 `uuremote-server login`，由账号持有人扫码确认。不要复制登录 token、二维码或 TURN 凭据到此仓库。

默认服务名使用 `uuremote-native.service`。可参考本仓库 [用户服务模板](../deploy/uuremote-native.service)，主机二进制放在该用户的 `~/.local/bin/uuremote-server`。模板默认上游虚拟桌面 `:99` 和 `%t/uu-virtual-99.Xauthority`；物理桌面应另设 `desktop.env`，不要覆盖已经能工作的服务。

**先用官方客户端验收画面、鼠标和键盘，再开启代理。** 若 UU 此时不通，先解决桌面本身的问题。

## 3. 安装和配置本项目

```bash
sudo python3 install.py --prefix /usr/local
sudo uu-vps-proxy configure desktop --bypass-unit uuremote-native.service
```

根据提示隐藏输入代理 URL，例如 `socks5://用户名:密码@代理地址:端口`。不要把真实代理写进源码或示例文件。

也可导入单个 sing-box outbound JSON：

```bash
sudo uu-vps-proxy configure desktop --profile /private/outbound.json \
  --bypass-unit uuremote-native.service
```

`configure` 创建专属系统服务、root 私有配置及 UU 启动前的固定刷新助手。助手只刷新该用户预先配置的规则，sudo 例外只接受无参数执行，不给任意命令免密。

## 4. 开启与验收

```bash
sudo uu-vps-proxy on desktop
sudo uu-vps-proxy check desktop
sudo uu-vps-proxy status desktop
```

在真实桌面浏览器中打开 IP 查询页，确认是代理出口；同时确认 UU 画面与鼠标仍正常。开启后会设置开机启动。新进程按出口时区启动，已经打开的 GUI 应用需重开后读取时区。

代理不支持 UDP 时，普通应用 UDP 不会回退直连；UU 使用自己的直连例外。IPv6 普通出站阻断。系统 DNS 委托给其他 UID 的机器应另做 DNS 验证，详见 [验证与边界](validation.md)。

## 5. 回滚与更换

```bash
sudo uu-vps-proxy off desktop
sudo uu-vps-proxy configure desktop --replace
sudo uu-vps-proxy on desktop
```

`off` 撤下该用户的本项目规则并停止本项目服务，不停止 UU 或桌面。若测试时已经造成 ICE/UDP 会话失效，关闭代理后可在合适时机重启 UU 主机服务以重建会话；该操作会关闭正在连接的客户端窗口，所以先协调使用者。

不同工具对同一 UID 同时设置 TUN 会冲突。当前正在工作的旧部署不会因克隆或安装本项目而自动迁移；迁移应先明确关闭旧工具，再配置新工具，不直接叠加启用。
