import asyncio
import ssl
import socket
import os
import subprocess
import argparse

# Default Configuration
DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_LISTEN_PORT = 8443
DEFAULT_WG_HOST = "127.0.0.1"
DEFAULT_WG_PORT = 51820
CERT_FILE = "server.crt"
KEY_FILE = "server.key"

def ensure_certificates():
    """Generates self-signed TLS certificates if they don't exist."""
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print("[PROXY] Certificates not found. Generating self-signed TLS certificates...")
        try:
            # Generate key and cert using OpenSSL CLI
            cmd = [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", KEY_FILE, "-out", CERT_FILE,
                "-days", "3650", "-nodes",
                "-subj", "/CN=VPN-TLS-Proxy"
            ]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"[PROXY] Successfully generated {CERT_FILE} and {KEY_FILE}")
        except Exception as e:
            print(f"[PROXY ERROR] Failed to auto-generate certificates: {e}")
            print("[PROXY ERROR] Please generate server.crt and server.key manually.")
            raise e

async def bridge_tls_to_udp(reader, writer, wg_host, wg_port):
    client_addr = writer.get_extra_info('peername')
    print(f"[PROXY] New TLS connection from {client_addr}")
    
    # Enable TCP_NODELAY to reduce latency
    try:
        sock = writer.transport.get_extra_info('socket')
        if sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception as e:
        print(f"[PROXY DEBUG] Failed to set TCP_NODELAY: {e}")
        
    loop = asyncio.get_running_loop()
    
    # 1. Create UDP socket bound to 127.0.0.1 on a random port
    # WireGuard will reply back to this port.
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setblocking(False)
    try:
        udp_sock.bind(('127.0.0.1', 0))
        udp_sock.connect((wg_host, wg_port))
        print(f"[PROXY] Bound local UDP socket to {udp_sock.getsockname()} and connected to WireGuard at {wg_host}:{wg_port}")
    except Exception as e:
        print(f"[PROXY ERROR] Failed to bind or connect local UDP socket: {e}")
        writer.close()
        return

    # 2. TLS -> UDP task
    async def tls_to_udp():
        try:
            while True:
                # Read 2-byte packet length
                len_bytes = await reader.readexactly(2)
                packet_len = int.from_bytes(len_bytes, byteorder='big')
                if packet_len <= 0 or packet_len > 2048:
                    break
                # Read exact length of packet data
                packet_data = await reader.readexactly(packet_len)
                # Forward packet to WireGuard UDP port
                udp_sock.send(packet_data)
        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            print(f"[PROXY DEBUG] Exception in TLS -> UDP task: {e}")

    # 3. UDP -> TLS task
    async def udp_to_tls():
        try:
            while True:
                # Read from UDP socket asynchronously
                packet_data = await loop.sock_recv(udp_sock, 2048)
                packet_len = len(packet_data)
                if packet_len > 0:
                    # Prefix with 2-byte length and send via TLS
                    writer.write(packet_len.to_bytes(2, byteorder='big') + packet_data)
                    await writer.drain()
        except Exception as e:
            print(f"[PROXY DEBUG] Exception in UDP -> TLS task: {e}")

    # Run tasks concurrently
    tasks = [
        asyncio.create_task(tls_to_udp()),
        asyncio.create_task(udp_to_tls())
    ]
    
    await asyncio.gather(*tasks, return_exceptions=True)
    
    # Clean up tasks and sockets
    for t in tasks:
        if not t.done():
            t.cancel()
            
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
        
    udp_sock.close()
    print(f"[PROXY] TLS connection from {client_addr} closed")

async def main():
    parser = argparse.ArgumentParser(description="UDP-over-TLS Server Proxy for WireGuard")
    parser.add_argument("--host", default=DEFAULT_LISTEN_HOST, help="Proxy listen host")
    parser.add_argument("--port", type=int, default=DEFAULT_LISTEN_PORT, help="Proxy listen TCP port")
    parser.add_argument("--wg-host", default=DEFAULT_WG_HOST, help="WireGuard server host")
    parser.add_argument("--wg-port", type=int, default=DEFAULT_WG_PORT, help="WireGuard server UDP port")
    args = parser.parse_args()

    ensure_certificates()

    # Configure SSL Context
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    except Exception as e:
        print(f"[PROXY ERROR] Failed to load SSL certificate chain: {e}")
        return

    # Start TLS Server
    server = await asyncio.start_server(
        lambda r, w: bridge_tls_to_udp(r, w, args.wg_host, args.wg_port),
        args.host,
        args.port,
        ssl=ssl_context
    )

    addr = server.sockets[0].getsockname()
    print(f"[PROXY] Serving TLS proxy on {addr} -> forwarding to UDP {args.wg_host}:{args.wg_port}")

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[PROXY] Stopped by user.")
