#!/bin/bash

# ==============================================================================
# WireGuard Linux Server Automated Installation & Configuration Script
# 支持系统: Ubuntu / Debian / CentOS / Rocky Linux / AlmaLinux
# ==============================================================================

# 必须以 root 权限运行
if [ "$EUID" -ne 0 ]; then
    echo "错误: 请使用 sudo 或 root 权限运行此脚本。"
    exit 1
fi

echo "=================================================="
echo "    开始自动安装和配置 WireGuard 服务端..."
echo "=================================================="

# 1. 自动识别操作系统并安装 WireGuard
if [ -f /etc/redhat-release ]; then
    if grep -q "release 7" /etc/redhat-release; then
        OS="centos7"
    else
        OS="rhel"
    fi
elif [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "$ID" = "ubuntu" ] || [ "$ID" = "debian" ]; then
        OS="ubuntu"
    elif [ "$ID" = "centos" ] && [ "$VERSION_ID" = "7" ]; then
        OS="centos7"
    else
        OS=$ID
    fi
else
    echo "错误: 无法识别的操作系统类型。"
    exit 1
fi

echo "[1/6] 检测到操作系统为: $OS，正在开始自动安装..."
case "$OS" in
    ubuntu)
        echo ">>> 执行 Ubuntu/Debian 自动安装流程..."
        apt-get update -y
        apt-get install -y wireguard iptables uuid-runtime
        ;;
    centos7)
        echo ">>> 执行 CentOS 7 自动安装流程 (正在配置 EPEL 与 ELRepo 内核源)..."
        yum install -y epel-release
        rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
        yum install -y https://www.elrepo.org/elrepo-release-7.el7.elrepo.noarch.rpm
        yum install -y kmod-wireguard wireguard-tools iptables uuid-runtime
        modprobe wireguard
        ;;
    centos|rhel|rocky|almalinux)
        echo ">>> 执行 CentOS 8 / RHEL 新版操作系统自动安装流程..."
        yum install -y epel-release elrepo-release
        yum install -y kmod-wireguard wireguard-tools iptables uuid-runtime
        modprobe wireguard
        ;;
    *)
        echo "错误: 不支持的系统类型 ($OS)。请手动安装。"
        exit 1
        ;;
esac

# 2. 启用系统内核的 IP 转发功能与网络栈调优 (BBR拥塞控制及缓冲区优化)
echo "[2/6] 启用内核 IPv4 转发及系统网络栈调优..."
sysctl_file="/etc/sysctl.conf"

# 辅助函数：安全修改/添加内核参数，避免重复写入
set_sysctl() {
    local key=$1
    local value=$2
    if grep -q "^[# ]*${key}" "$sysctl_file"; then
        sed -i "s|^[# ]*${key}.*|${key}=${value}|g" "$sysctl_file"
    else
        echo "${key}=${value}" >> "$sysctl_file"
    fi
}

# 开启 IP 转发
set_sysctl "net.ipv4.ip_forward" "1"

# 检查内核是否支持 BBR 并有条件地配置
if modprobe tcp_bbr >/dev/null 2>&1; then
    set_sysctl "net.core.default_qdisc" "fq"
    set_sysctl "net.ipv4.tcp_congestion_control" "bbr"
    echo "内核支持并已启用 BBR 拥塞控制算法。"
else
    echo "警告: 当前内核版本不支持 BBR，已跳过 BBR 调优。"
fi

# 调大系统网络读写缓冲区限制，支持大窗口高带宽数据吞吐
set_sysctl "net.core.rmem_max" "16777216"
set_sysctl "net.core.wmem_max" "16777216"
set_sysctl "net.ipv4.tcp_rmem" "4096 87380 16777216"
set_sysctl "net.ipv4.tcp_wmem" "4096 65536 16777216"

# 调大网卡队列 backlog 长度，防止并发高峰网络层丢包
set_sysctl "net.core.netdev_max_backlog" "10000"

# 加载配置
sysctl -p

# 3. 自动生成服务端公钥和私钥
echo "[3/6] 生成 WireGuard 密钥对..."
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
SERVER_PRIV_KEY=$(cat /etc/wireguard/server.key)
SERVER_PUB_KEY=$(cat /etc/wireguard/server.pub)

# 4. 自动识别网卡名称并配置 NAT 规则
echo "[4/6] 自动检测系统主网卡及配置 NAT 规则..."
# 获取默认路由指向的物理网卡接口名称
NET_INTF=$(ip route show | grep default | awk '{print $5}' | head -n1)
if [ -z "$NET_INTF" ]; then
    # 回退选择第一个非 loopback 的物理网卡
    NET_INTF=$(ip link show | grep -v "lo" | awk -F: '$0 !~ "lowerup" {print $2}' | head -n1 | tr -d ' ')
fi
echo "检测到主网卡接口为: $NET_INTF"

# 5. 生成配置文件 /etc/wireguard/wg0.conf
echo "[5/6] 写入配置文件 /etc/wireguard/wg0.conf..."
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.0.0.1/24
SaveConfig = true
ListenPort = 51820
PrivateKey = $SERVER_PRIV_KEY

# 流量转发、NAT 混淆规则以及 TCP MSS 钳夹限制 (防止 MTU 分片协商失败导致网页卡死或握手失败)
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $NET_INTF -j MASQUERADE; iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $NET_INTF -j MASQUERADE; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
EOF

chmod 600 /etc/wireguard/wg0.conf

# 6. 注册 systemd 服务并启动
echo "[6/6] 启动 WireGuard 服务并开启自启..."
systemctl stop wg-quick@wg0 2>/dev/null
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# 检查接口运行状态
if ip link show wg0 >/dev/null 2>&1; then
    echo "=================================================="
    echo "🎉 WireGuard 服务端配置并启动成功！"
    echo "--------------------------------------------------"
    echo " 服务端口       : UDP 51820"
    echo " 服务端内网网关 : 10.0.0.1/24"
    echo " 服务端公钥     : $SERVER_PUB_KEY"
    echo "=================================================="
    echo "👉 请将此 [服务端公钥] 填写至 main.py 的 SERVER_WG_PUBLIC_KEY 中。"
else
    echo "错误: wg0 网卡未能成功启动，请检查内核支持。"
    exit 1
fi
