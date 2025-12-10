#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
服务器代理 - 简化版 HTTP/HTTPS 代理服务器
部署在公网服务器上，让客户端通过服务器的 IP 上网

功能:
- HTTP 代理 (GET, POST 等)
- HTTPS 代理 (CONNECT 隧道)
- 支持 IPv4 和 IPv6
- 无需上游代理，直接使用服务器出口 IP

用法:
  python server_proxy.py                    # 默认监听 8080 端口
  python server_proxy.py -p 3128            # 指定端口
  python server_proxy.py -p 8080 -b 0.0.0.0 # 指定绑定地址和端口
"""

import socket
import threading
import select
import sys
import signal
import argparse
import logging

# 配置
DEFAULT_PORT = 8080
DEFAULT_BIND = "0.0.0.0"
BUFFER_SIZE = 8192
TIMEOUT = 60

# 全局变量
running = True
logger = None


def setup_logging(verbose=False):
    """配置日志"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s | %(levelname)-7s | %(message)s',
        datefmt='%H:%M:%S'
    )
    return logging.getLogger('ServerProxy')


def parse_request(data):
    """
    解析 HTTP 请求
    Returns: (method, host, port, path, raw_request)
    """
    try:
        if not data or len(data) < 10:
            return None, None, None, None, data
        
        text = data.decode('utf-8', errors='ignore')
        lines = text.split('\r\n')
        
        if not lines or not lines[0].strip():
            return None, None, None, None, data
        
        # 解析请求行
        parts = lines[0].strip().split(' ')
        if len(parts) < 2:
            return None, None, None, None, data
        
        method = parts[0].upper()
        url = parts[1]
        
        # CONNECT 方法 (HTTPS)
        if method == 'CONNECT':
            # 处理 IPv6 格式 [ipv6]:port
            if url.startswith('['):
                bracket_end = url.find(']')
                if bracket_end != -1:
                    host = url[1:bracket_end]
                    port = 443
                    if len(url) > bracket_end + 2 and url[bracket_end + 1] == ':':
                        try:
                            port = int(url[bracket_end + 2:])
                        except ValueError:
                            pass
                else:
                    host = url
                    port = 443
            else:
                if ':' in url:
                    idx = url.rfind(':')
                    host = url[:idx]
                    try:
                        port = int(url[idx + 1:])
                    except ValueError:
                        port = 443
                else:
                    host = url
                    port = 443
            return method, host, port, None, data
        
        # HTTP 请求
        host = ''
        port = 80
        path = url
        
        # 从 Host 头获取主机
        for line in lines[1:]:
            lower = line.lower().strip()
            if lower.startswith('host:'):
                host_val = line.split(':', 1)[1].strip()
                if ':' in host_val and not host_val.startswith('['):
                    host, port_str = host_val.rsplit(':', 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        port = 80
                else:
                    host = host_val
                break
        
        # 从 URL 提取路径
        if url.startswith('http://'):
            url_path = url[7:]
            slash_idx = url_path.find('/')
            if slash_idx != -1:
                path = url_path[slash_idx:]
            else:
                path = '/'
        
        return method, host, port, path, data
        
    except Exception as e:
        logger.debug("解析请求失败: %s" % e)
        return None, None, None, None, data


def connect_to_host(host, port):
    """连接到目标主机，支持 IPv4/IPv6"""
    try:
        # 处理 IPv6 括号
        if host.startswith('[') and host.endswith(']'):
            host = host[1:-1]
        
        # DNS 解析
        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        
        # 尝试连接
        for family, socktype, proto, canonname, sockaddr in addr_info:
            try:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(TIMEOUT)
                sock.connect(sockaddr)
                return sock
            except socket.error:
                continue
        
        return None
    except Exception as e:
        logger.debug("连接失败 %s:%d - %s" % (host, port, e))
        return None


def tunnel(client, target):
    """双向隧道转发"""
    client.setblocking(False)
    target.setblocking(False)
    
    try:
        while running:
            readable, _, exceptional = select.select(
                [client, target], [], [client, target], 1
            )
            
            if exceptional:
                break
            
            for sock in readable:
                try:
                    data = sock.recv(BUFFER_SIZE)
                    if not data:
                        return
                    
                    if sock is client:
                        target.sendall(data)
                    else:
                        client.sendall(data)
                except (BlockingIOError, socket.error):
                    continue
    except Exception:
        pass


def handle_client(client_sock, client_addr):
    """处理客户端连接"""
    client_ip = client_addr[0]
    target_sock = None
    
    try:
        client_sock.settimeout(TIMEOUT)
        data = client_sock.recv(BUFFER_SIZE)
        
        if not data:
            return
        
        method, host, port, path, raw = parse_request(data)
        
        if not host:
            logger.debug("[%s] 无法解析请求" % client_ip)
            return
        
        logger.info("[%s] %s %s:%d" % (client_ip, method, host, port))
        
        # 连接目标
        target_sock = connect_to_host(host, port)
        if not target_sock:
            client_sock.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            return
        
        if method == 'CONNECT':
            # HTTPS 隧道
            client_sock.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            tunnel(client_sock, target_sock)
        else:
            # HTTP 请求 - 修改为相对路径
            text = raw.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            if lines and path:
                parts = lines[0].split(' ')
                if len(parts) >= 3:
                    parts[1] = path
                    lines[0] = ' '.join(parts)
                    raw = '\r\n'.join(lines).encode()
            
            target_sock.sendall(raw)
            
            # 转发响应
            while True:
                try:
                    resp = target_sock.recv(BUFFER_SIZE)
                    if not resp:
                        break
                    client_sock.sendall(resp)
                except socket.timeout:
                    break
                except Exception:
                    break
    
    except Exception as e:
        logger.debug("[%s] 错误: %s" % (client_ip, e))
    finally:
        if target_sock:
            try:
                target_sock.close()
            except:
                pass
        try:
            client_sock.close()
        except:
            pass


def get_local_ip():
    """获取本机 IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "unknown"


def signal_handler(signum, frame):
    """处理退出信号"""
    global running
    print("\n\n🛑 正在关闭服务器...")
    running = False
    sys.exit(0)


def main():
    global logger, running
    
    parser = argparse.ArgumentParser(
        description='服务器代理 - HTTP/HTTPS 代理服务器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  python server_proxy.py                    默认监听 0.0.0.0:8080
  python server_proxy.py -p 3128            监听 3128 端口
  python server_proxy.py -p 8080 -v         详细日志模式
'''
    )
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT,
                        help='监听端口 (默认: %d)' % DEFAULT_PORT)
    parser.add_argument('-b', '--bind', default=DEFAULT_BIND,
                        help='绑定地址 (默认: %s)' % DEFAULT_BIND)
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='详细日志模式')
    
    args = parser.parse_args()
    
    logger = setup_logging(args.verbose)
    
    # 获取本机 IP
    local_ip = get_local_ip()
    
    # 打印启动信息
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                    🌐 服务器代理                                   ║
║                    Server Proxy                                  ║
╚══════════════════════════════════════════════════════════════════╝

📋 配置信息:
   • 监听地址: %s:%d
   • 服务器 IP: %s

📱 客户端代理设置:
   • 代理服务器: %s
   • 代理端口: %d
   • 代理类型: HTTP
""" % (args.bind, args.port, local_ip, local_ip, args.port))
    
    # 注册信号
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 创建服务器
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.bind, args.port))
        server.listen(100)
        server.settimeout(1)
        
        logger.info("🚀 代理服务器已启动，监听 %s:%d" % (args.bind, args.port))
        logger.info("按 Ctrl+C 停止服务器")
        print()
        
    except PermissionError:
        print("❌ 错误: 没有权限绑定端口 %d" % args.port)
        sys.exit(1)
    except OSError as e:
        print("❌ 错误: 无法绑定端口 %d: %s" % (args.port, e))
        sys.exit(1)
    
    # 主循环
    while running:
        try:
            client, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except Exception as e:
            if running:
                logger.error("接受连接错误: %s" % e)


if __name__ == "__main__":
    main()
