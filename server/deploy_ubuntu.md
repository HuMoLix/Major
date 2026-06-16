# Ubuntu 24.04 LTS 服务端完整部署指南

本指南将指导您在 Ubuntu 24.04 LTS 服务器上部署本项目的 Python FastAPI 激活服务和 WireGuard 数据隧道服务。

---

## 第一步：防火墙与系统准备

首先更新系统，并使用 `ufw`（Ubuntu 默认防火墙）放行所需的端口：
- **TCP 8000**：FastAPI 激活服务
- **TCP 8443**：TLS 混淆代理端口 (UDP-over-TLS)
- **UDP 51820**：WireGuard 虚拟专用网通道

```bash
# 更新系统包
sudo apt update && sudo apt upgrade -y

# 安装 Python 相关工具
sudo apt install -y python3-pip python3-venv python3-full

# 配置防火墙端口
sudo ufw allow 8000/tcp
sudo ufw allow 8443/tcp
sudo ufw allow 51820/udp
sudo ufw allow 22/tcp  # 确保放行 SSH 端口以免断开连接
sudo ufw enable
```

---

## 第二步：安装与配置 WireGuard

我们将使用项目中的自动化脚本来安装和注册 WireGuard：

1. 将 `server/` 文件夹上传到 Ubuntu 服务器的某个工作目录（例如 `/opt/vpn-server`）。
2. 执行安装脚本：
   ```bash
   cd /opt/vpn-server
   chmod +x setup_wireguard.sh
   sudo ./setup_wireguard.sh
   ```
3. 脚本执行完毕后，控制台会输出服务端的公钥。例如：
   ```text
   服务端公钥     : mYJPVcXGDHyFwJYpyCv0Taf+7qSBoe6ktRCGFw3vDmk=
   ```
   **复制并保存这个公钥，下一步需要用到。**

---

## 第三步：部署 Python 虚拟环境与依赖

1. 在工作目录创建并激活虚拟环境：
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
2. 安装依赖包：
   ```bash
   pip install -r requirements.txt
   ```

---

## 第四步：配置 API 服务端 ([main.py](file:///E:/major/server/main.py))

在服务器上修改 `main.py` 配置文件：

1. 打开并编辑 [main.py](file:///E:/major/server/main.py)：
   ```bash
   nano main.py
   ```
2. 更改以下两项配置：
   * **SERVER_WG_PUBLIC_KEY**：替换为**第二步**中生成的 WireGuard 服务端公钥。
   * **SERVER_ENDPOINT**：修改为虚拟机的真实公网 IP 或内网 IP + 端口（如 `"192.168.150.128:51820"`）。
   ```python
   # main.py 配置修改示例
   SERVER_WG_PUBLIC_KEY = "mYJPVcXGDHyFwJYpyCv0Taf+7qSBoe6ktRCGFw3vDmk="  # 替换成你的
   SERVER_ENDPOINT = "192.168.150.128:51820"                            # 替换成你的服务器 IP
   ```
3. 保存并关闭文件（Nano 下按 `Ctrl+O` 回车保存，`Ctrl+X` 退出）。

---

## 第五步：注册 FastAPI 系统守护进程 (Systemd Service)

为了保证 API 服务在后台常驻运行，并在服务器重启时自动启动，我们需要配置一个 systemd 系统服务。

1. 创建服务文件 `/etc/systemd/system/vpn-api.service`：
   ```bash
   sudo nano /etc/systemd/system/vpn-api.service
   ```
2. 写入以下配置（请根据实际的工作路径修改 `WorkingDirectory` 和 `ExecStart`）：
   ```ini
   [Unit]
   Description=Commercial VPN Activation API Service
   After=network.target

   [Service]
   User=root
   WorkingDirectory=/opt/vpn-server
   ExecStart=/opt/vpn-server/.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```
3. 保存并关闭文件。
4. 重新加载系统服务并开启自启：
   ```bash
   # 重新加载服务文件
   sudo systemctl daemon-reload
   
   # 开启开机自启并立刻启动服务
   sudo systemctl enable vpn-api.service
   sudo systemctl start vpn-api.service
   ```
5. 检查 API 服务运行状态：
   ```bash
   sudo systemctl status vpn-api.service
   ```
   看到显示 `active (running)` 说明服务已经成功常驻运行。

---

## 第五步（续）：注册 TLS 混淆代理系统守护进程 (vpn-tls-proxy.service)

为了让 TLS 代理在后台常驻运行以支持 UDP-over-TLS 功能，我们同样将其注册为 systemd 服务：

1. 创建服务文件 `/etc/systemd/system/vpn-tls-proxy.service`：
   ```bash
   sudo nano /etc/systemd/system/vpn-tls-proxy.service
   ```
2. 写入以下配置：
   ```ini
   [Unit]
   Description=Commercial VPN UDP-over-TLS Proxy Service
   After=network.target vpn-api.service

   [Service]
   User=root
   WorkingDirectory=/opt/vpn-server
   ExecStart=/opt/vpn-server/.venv/bin/python tls_proxy.py --port 8443 --wg-host 127.0.0.1 --wg-port 51820
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```
3. 保存并关闭文件。
4. 重新加载系统服务并开启自启：
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable vpn-tls-proxy.service
   sudo systemctl start vpn-tls-proxy.service
   ```
5. 检查 TLS 代理服务运行状态：
   ```bash
   sudo systemctl status vpn-tls-proxy.service
   ```

---

## 第六步：生成用于测试的激活码

使用之前创建的管理脚本在服务器上生成激活码：
```bash
# 确保在虚拟环境下运行，或指定完整路径：
/opt/vpn-server/.venv/bin/python generate_key.py --days 30 --count 1
```
控制台会输出生成的激活码（形如 `KEY-H9W9-RRTG-TX3K-6L7Y`）。

---

## 第七步：运维与检查指令

在 Ubuntu 服务器上进行维护时，可使用以下常用命令：

* **检查 WireGuard 运行状态与流量**：
  ```bash
  sudo wg show
  ```
* **查看 API 的实时运行日志**（方便排查客户端激活请求）：
  ```bash
  sudo journalctl -u vpn-api.service -f
  ```
* **重启 API 服务**：
  ```bash
  sudo systemctl restart vpn-api.service
  ```
