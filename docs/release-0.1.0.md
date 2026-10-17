独立发布 UU Remote + VPS 按用户 TUN 家宽出口项目。

- `uu-vps-proxy` 管理指定 Linux 用户的代理配置、开机启动、检查、状态和关闭回滚。
- 包含 UU 控制连接与动态 TCP/UDP 套接字直连例外、连接标记、已有 UDP 端口前置路由及必要的源地址转换。
- 提供独立安装器、UU 用户服务模板、新 VPS 部署说明和隔离 UDP 往返回归。

需要 Python 3.11+、sing-box 1.14+ 以及发行版网络工具。安装器不自动启动或迁移现有服务，压缩包不含真实家宽配置或 UU 登录信息。

上游 UU Linux 主机单独安装，其源码和许可证保持独立。详见 README 与 THIRD_PARTY.md。
