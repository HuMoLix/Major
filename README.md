# 商业版 WireGuard 激活、控制与 Web 管理系统部署指南

本项目是一套完整的商业级虚拟专用网（VPN）连接管理系统，包含：
1. **Rust 客户端 (Windows)**：内存解密并直接加载 WireGuard 隧道至 Wintun 网卡，不在本地留存敏感配置文件，绑定硬件指纹防止一码多用。
2. **FastAPI 服务端 (CentOS 7 / Ubuntu)**：处理客户端的安全激活验证、动态 IP 分配以及与内核级 WireGuard 网卡 (`wg0`) 的实时同步注册。
3. **Flask Web 管理后台 (CentOS 7 / Ubuntu)**：现代 Notion 风格设计，内置管理员账号，支持可视化增删查改激活码、自定义激活时长（精确到秒）以及一键封禁并强制下线客户端。

---

## 目录结构

```text
E:/major/
├── README.md                 # 完整部署指南文档
├── server/                   # 服务端代码 (Python)
│   ├── db.py                 # 数据库模型与自动表结构迁移
│   ├── crypto.py             # AES-256-GCM 双向解密算法
│   ├── main.py               # FastAPI 激活与连接同步主程序
│   ├── web.py                # Flask Web 管理后台
│   ├── templates/            # 网页模版（Notion 主题风格）
│   │   ├── login.html        # 登录页面 (已隐藏默认口令)
│   │   └── dashboard.html    # 仪表盘管理页面 (支持 AJAX 异步操作)
│   ├── init_db.py            # 数据库初始化与测试数据种子文件
│   ├── setup_wireguard.sh    # Linux 服务端 WireGuard 自动化安装配置脚本 (已适配 CentOS 7)
│   └── requirements.txt      # 依赖包声明文件
└── client/                   # 客户端代码 (Rust)
    ├── Cargo.toml            # Rust 依赖配置文件
    ├── download_wintun.ps1   # Wintun 驱动 DLL 自动下载脚本
    └── src/                  # 客户端源码（包含 config, crypto, tunnel, main）
```

---

## 第一部分：服务端部署 (以 CentOS 7 为主，附 Ubuntu 步骤)

CentOS 7 的内核版本较低（3.10.x），原生不支持 WireGuard，本项目已在 `setup_wireguard.sh` 中集成了 ELRepo 的内核模块自动构建与加载，并在 `README` 中适配了 CentOS 的 `firewalld` 防火墙。

### 1. 系统依赖安装与防火墙放行

#### 针对 CentOS 7 系统：
安装基础 Python 3、系统工具并放行端口：
```bash
# 1. 安装 Python3 与基础工具
sudo yum install -y python3 python3-devel gcc

# 2. 开放防火墙端口 (8000/TCP 激活, 8080/TCP 后台, 8443/TCP TLS代理, 51820/UDP WireGuard)
sudo firewall-cmd --zone=public --add-port=8000/tcp --permanent
sudo firewall-cmd --zone=public --add-port=8080/tcp --permanent
sudo firewall-cmd --zone=public --add-port=8443/tcp --permanent
sudo firewall-cmd --zone=public --add-port=51820/udp --permanent

# 3. 必须开启 NAT 转发伪装规则（重要！否则客户端连接后无法共享出网）
sudo firewall-cmd --zone=public --add-masquerade --permanent

# 4. 重载防火墙
sudo firewall-cmd --reload
```

#### 针对 Ubuntu 24.04 系统（备用）：
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-pip python3-venv python3-full
sudo ufw allow 22/tcp && sudo ufw allow 8000/tcp && sudo ufw allow 8080/tcp && sudo ufw allow 8443/tcp && sudo ufw allow 51820/udp
sudo ufw enable
```

---

### 2. 配置与安装 WireGuard
将项目中的 `server/` 文件夹上传到服务器的 `/opt/vpn-server` 目录。

```bash
cd /opt/vpn-server
chmod +x setup_wireguard.sh
# 脚本会自动识别 CentOS 7，并拉取 ELRepo 安装内核模块 kmod-wireguard
sudo ./setup_wireguard.sh
```
*执行完毕后，终端会打印出服务端的 WireGuard 公钥，请将其记录下来。*

---

### 3. 配置 FastAPI 服务
编辑 `/opt/vpn-server/main.py` 文件，填写您的服务器配置：
- **SERVER_WG_PUBLIC_KEY**：替换为上一步生成的服务端 WireGuard 公钥。
- **SERVER_ENDPOINT**：修改为虚拟机的公网/内网 IP 以及端口（格式如 `"192.168.100.1:51820"`）。

```python
# main.py 配置修改示例
SERVER_WG_PUBLIC_KEY = "dZ4hy0mxNNooH3wmiFXsVmz9+eOF0lIKDsJTuOpKSXI="  # 您的服务端公钥
SERVER_ENDPOINT = "192.168.100.1:51820"                            # 您的服务器 IP 端口
```

---

### 4. 安装 Python 依赖与数据迁移
```bash
# 创建虚拟环境
python3 -m venv .venv
source .venv/bin/activate

# 安装依赖
pip install -r requirements.txt

# 初始化数据库并自动迁移表结构 (自动在现有数据库添加 is_banned 和 duration_seconds 字段)
python init_db.py
```

---

### 5. 注册 Systemd 守护进程
为了保证两套后端常驻运行，我们需要将其注册为 Systemd 服务：

#### A. 激活 API 服务 (`vpn-api.service`)：
```bash
sudo nano /etc/systemd/system/vpn-api.service
```
写入配置：
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

#### B. 网页管理控制台服务 (`vpn-web.service`)：
```bash
sudo nano /etc/systemd/system/vpn-web.service
```
写入配置：
```ini
[Unit]
Description=Commercial VPN Admin Web Dashboard
After=network.target

[Service]
User=root
WorkingDirectory=/opt/vpn-server
ExecStart=/opt/vpn-server/.venv/bin/python web.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

#### C. TLS 混淆代理服务 (`vpn-tls-proxy.service`)：
```bash
sudo nano /etc/systemd/system/vpn-tls-proxy.service
```
写入配置：
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

#### D. 启动所有服务：
```bash
sudo systemctl daemon-reload

# 启用并开启开机自启
sudo systemctl enable vpn-api.service vpn-web.service vpn-tls-proxy.service
sudo systemctl start vpn-api.service vpn-web.service vpn-tls-proxy.service

# 检查运行状态
sudo systemctl status vpn-api.service vpn-web.service vpn-tls-proxy.service
```

---

## 第二部分：客户端构建与运行 (Windows)

### 1. 搭建编译环境
客户端需要在有 Rust 环境的机器上进行编译。
1. 下载并安装 [Rustup](https://rustup.rs/) (Windows 64位安装程序)。
2. 安装完毕后，在 CMD 或 PowerShell 中运行 `cargo --version` 确认安装成功。

### 2. 下载 Wintun 驱动与编译
1. 打开 Windows PowerShell（以**管理员身份**运行），进入项目客户端目录 `E:\major\client`。
2. 运行脚本自动下载 `wintun.dll` 驱动到客户端目录：
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\download_wintun.ps1
   ```
3. 编译发布版二进制程序：
   ```powershell
   cargo build --release
   ```
   *编译成功后，可执行文件位于 `client\target\release\client.exe`。*

### 3. 在客户端机器上运行
1. 将编译好的 `client.exe` 和 `wintun.dll` 放置在同一个目录下。
2. 以**管理员身份**打开 PowerShell 或 CMD，进入该目录运行：
   * **普通模式**（默认）：只显示版本信息、授权输入和精简的秒级倒计时。
     ```cmd
     client.exe
     ```
   * **调试模式**：打印详细的设备指纹、生成公钥、API 请求负载、接口响应，以及解密后来自服务端的完整 WireGuard 配置信息。
     ```cmd
     client.exe --debug
     ```
3. 提示 `Enter License Key:`，输入由 Web 管理台生成的激活码进行激活连接。
4. **全流量代理配置**（如果客户端处于无默认网关的隔离局域网中，请执行以下命令设置默认流量走 VPN）：
   ```cmd
   # 1. 确保到网关服务器 IP 的流量依然走原来的局域网物理网口 (防止流量环路套娃)
   # 格式: route add <网关IP> <本机静态IP>
   route add 192.168.100.1 192.168.100.2
   
   # 2. 将全局默认网关指向虚拟网口 (IP 需要替换为实际分配的客户端 Tunnel IP)
   # 格式: route add 0.0.0.0 mask 0.0.0.0 <分配的客户端IP>
   route add 0.0.0.0 mask 0.0.0.0 10.0.0.4 metric 1
   ```

---

## 第三部分：Web 后台管理员操作指南

网页端运行于 `http://<您的服务器IP>:8080`，内置管理员凭证如下：
- **Username**：`admin`
- **Password**：`aasdff12`

### 常见操作说明

#### 1. 生成激活码
在左侧的 "Generate Key" 面板中：
- 可选输入自定义 Key 名称（留空则自动生成）。
- 选择激活码的生命周期类型（天/小时/分钟/秒），输入时间值，点击 **Generate** 即可生成。
- 生成后，该激活码状态为 `unused`。

#### 2. 设备一键解绑 (Unbind)
当用户的电脑重装系统或需要更换设备使用激活码时：
- 在列表中找到该用户的激活码。
- 点击操作列的 **Unbind** 按钮。这会清除设备指纹信息，并自动将其从 WireGuard 接口中移除，使其可在一台新设备上激活使用。

#### 3. 封禁激活码并强制下线 (Ban)
如果发现激活码违规或用户欠费：
- 在列表中点击该激活码操作列的 **Ban** 按钮。
- **即时断网**：在修改数据库的同时，服务端会立即向系统内核发送 Peer 剔除指令，客户端的 VPN 隧道将瞬间失效，断开数据流通讯。
- **防重复激活**：任何设备尝试再次激活此激活码时将获得 `403 Forbidden` 错误。

#### 4. 删除激活码 (Delete)
- 点击 **Delete** 按钮。
- 同样会断开活跃用户的 WireGuard 隧道，并从数据库中物理删除此记录。
