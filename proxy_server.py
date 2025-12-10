#!/usr/bin/env python3
"""
局域网代理服务器
将局域网设备的请求转发到本地 VPN 代理端口

功能:
- 监听 HTTP 代理请求
- 转发到上游代理 (VPN)
- 支持 HTTP 和 HTTPS (CONNECT) 请求
- 支持用户名密码认证 (公网安全)
- 支持 IP 白名单
"""

import socket
import threading
import select
import logging
import sys
import signal
import argparse
import base64
import time
import ipaddress
from typing import Optional, Tuple, Dict
from collections import defaultdict
from utils import (
    load_config, 
    get_local_ip_addresses, 
    check_upstream_proxy,
    print_banner,
    ProxyConfig
)

# 全局配置
config: Optional[ProxyConfig] = None
logger: Optional[logging.Logger] = None
server_socket: Optional[socket.socket] = None
running = True

# 连接统计
connection_stats = {
    'total': 0,
    'active': 0,
    'success': 0,
    'failed': 0,
    'auth_failed': 0,
    'ip_blocked': 0
}
stats_lock = threading.Lock()

# 速率限制
rate_limit_data: Dict[str, list] = defaultdict(list)
rate_limit_lock = threading.Lock()


def setup_logging(level: str) -> logging.Logger:
    """配置日志系统"""
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s | %(levelname)-7s | %(message)s',
        datefmt='%H:%M:%S'
    )
    
    return logging.getLogger('LAN-Proxy')


def check_ip_whitelist(client_ip: str) -> bool:
    """
    检查客户端IP是否在白名单中
    
    Args:
        client_ip: 客户端IP地址
        
    Returns:
        bool: True 表示允许访问
    """
    if not config.security.ip_whitelist:
        return True  # 白名单为空，允许所有IP
    
    try:
        client_addr = ipaddress.ip_address(client_ip)
        
        for allowed in config.security.ip_whitelist:
            try:
                # 尝试作为网段解析
                if '/' in allowed:
                    network = ipaddress.ip_network(allowed, strict=False)
                    if client_addr in network:
                        return True
                else:
                    # 作为单个IP解析
                    if client_addr == ipaddress.ip_address(allowed):
                        return True
            except ValueError:
                continue
        
        return False
    except ValueError:
        return False


def check_rate_limit(client_ip: str) -> bool:
    """
    检查是否超过速率限制
    
    Args:
        client_ip: 客户端IP地址
        
    Returns:
        bool: True 表示允许访问 (未超限)
    """
    if not config.security.rate_limit_enabled:
        return True
    
    current_time = time.time()
    window_start = current_time - 60  # 1分钟窗口
    
    with rate_limit_lock:
        # 清理过期记录
        rate_limit_data[client_ip] = [
            t for t in rate_limit_data[client_ip] if t > window_start
        ]
        
        # 检查是否超限
        if len(rate_limit_data[client_ip]) >= config.security.rate_limit_per_minute:
            return False
        
        # 记录本次请求
        rate_limit_data[client_ip].append(current_time)
        return True


def verify_proxy_auth(request_data: bytes) -> Tuple[bool, str]:
    """
    验证代理认证
    
    Args:
        request_data: HTTP请求数据
        
    Returns:
        Tuple[bool, str]: (是否通过认证, 用户名或错误信息)
    """
    if not config.security.auth_enabled:
        return True, ""
    
    try:
        request_text = request_data.decode('utf-8', errors='ignore')
        
        # 查找 Proxy-Authorization 头
        for line in request_text.split('\r\n'):
            if line.lower().startswith('proxy-authorization:'):
                auth_value = line.split(':', 1)[1].strip()
                
                # 解析 Basic 认证
                if auth_value.lower().startswith('basic '):
                    encoded = auth_value[6:].strip()
                    try:
                        decoded = base64.b64decode(encoded).decode('utf-8')
                        if ':' in decoded:
                            username, password = decoded.split(':', 1)
                            if (username == config.security.username and 
                                password == config.security.password):
                                return True, username
                            else:
                                return False, "用户名或密码错误"
                    except Exception:
                        return False, "认证格式错误"
        
        return False, "未提供认证信息"
    except Exception as e:
        return False, f"认证解析失败: {e}"


def send_auth_required(client_socket: socket.socket):
    """发送需要认证的响应"""
    response = (
        b'HTTP/1.1 407 Proxy Authentication Required\r\n'
        b'Proxy-Authenticate: Basic realm="LAN Proxy"\r\n'
        b'Content-Length: 0\r\n'
        b'\r\n'
    )
    try:
        client_socket.sendall(response)
    except Exception:
        pass


def send_forbidden(client_socket: socket.socket, reason: str = "Access Denied"):
    """发送禁止访问的响应"""
    body = f"<html><body><h1>403 Forbidden</h1><p>{reason}</p></body></html>".encode()
    response = (
        b'HTTP/1.1 403 Forbidden\r\n'
        b'Content-Type: text/html\r\n'
        f'Content-Length: {len(body)}\r\n'.encode() +
        b'\r\n' +
        body
    )
    try:
        client_socket.sendall(response)
    except Exception:
        pass


def parse_http_request(request_data: bytes) -> Tuple[str, int, str, bytes]:
    """
    解析 HTTP 请求
    
    Returns:
        Tuple[str, int, str, bytes]: (主机, 端口, 方法, 原始请求)
    """
    try:
        # 检查请求数据是否为空或过短
        if not request_data or len(request_data) < 10:
            logger.debug(f"请求数据过短: {len(request_data) if request_data else 0} 字节")
            return '', 0, '', request_data
        
        # 解码请求头
        request_text = request_data.decode('utf-8', errors='ignore')
        
        # 尝试不同的行分隔符
        if '\r\n' in request_text:
            lines = request_text.split('\r\n')
        elif '\n' in request_text:
            lines = request_text.split('\n')
        else:
            lines = [request_text]
        
        if not lines or not lines[0].strip():
            logger.debug(f"请求行为空")
            return '', 0, '', request_data
        
        # 解析请求行
        first_line = lines[0].strip()
        parts = first_line.split(' ')
        
        if len(parts) < 2:
            logger.debug(f"请求行格式无效: {first_line[:50]}")
            return '', 0, '', request_data
        
        method = parts[0].upper()
        url = parts[1]
        
        # 验证 HTTP 方法是否有效
        valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 
                         'PATCH', 'CONNECT', 'TRACE']
        if method not in valid_methods:
            logger.debug(f"无效的 HTTP 方法: {method}")
            return '', 0, '', request_data
        
        # CONNECT 方法 (HTTPS)
        if method == 'CONNECT':
            host_port = url.split(':')
            host = host_port[0]
            try:
                port = int(host_port[1]) if len(host_port) > 1 else 443
            except ValueError:
                port = 443
            return host, port, method, request_data
        
        # 普通 HTTP 请求
        # 从 Host 头获取主机信息
        host = ''
        port = 80
        
        for line in lines[1:]:
            line_lower = line.lower().strip()
            if line_lower.startswith('host:'):
                host_value = line.split(':', 1)[1].strip()
                if ':' in host_value:
                    host, port_str = host_value.rsplit(':', 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        port = 80
                else:
                    host = host_value
                break
        
        # 如果 URL 是完整 URL，从中提取主机
        if url.startswith('http://'):
            url_path = url[7:]
            if '/' in url_path:
                host_part = url_path.split('/')[0]
            else:
                host_part = url_path
            if ':' in host_part:
                host, port_str = host_part.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    port = 80
            else:
                host = host_part
        elif url.startswith('https://'):
            url_path = url[8:]
            port = 443
            if '/' in url_path:
                host_part = url_path.split('/')[0]
            else:
                host_part = url_path
            if ':' in host_part:
                host, port_str = host_part.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    port = 443
            else:
                host = host_part
        
        if not host:
            logger.debug(f"无法从请求中提取主机: method={method}, url={url[:50]}")
        
        return host, port, method, request_data
        
    except Exception as e:
        logger.debug(f"解析请求失败: {e}, 数据前100字节: {request_data[:100]}")
        return '', 0, '', request_data


def forward_data(source: socket.socket, destination: socket.socket, 
                 description: str = "") -> int:
    """
    转发数据
    
    Args:
        source: 源套接字
        destination: 目标套接字
        description: 描述信息
        
    Returns:
        int: 转发的字节数
    """
    total_bytes = 0
    try:
        while running:
            readable, _, _ = select.select([source], [], [], 1)
            if source in readable:
                data = source.recv(8192)
                if not data:
                    break
                destination.sendall(data)
                total_bytes += len(data)
            else:
                # 检查连接是否还活着
                try:
                    source.getpeername()
                except:
                    break
    except Exception as e:
        logger.debug(f"转发数据时出错 ({description}): {e}")
    
    return total_bytes


def handle_tunnel(client_socket: socket.socket, upstream_socket: socket.socket,
                  host: str, port: int):
    """
    处理 HTTPS 隧道 (CONNECT 方法)
    """
    # 发送连接成功响应给客户端
    client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
    
    # 创建双向转发
    client_socket.setblocking(False)
    upstream_socket.setblocking(False)
    
    try:
        while running:
            readable, _, exceptional = select.select(
                [client_socket, upstream_socket], 
                [], 
                [client_socket, upstream_socket],
                1
            )
            
            if exceptional:
                break
            
            for sock in readable:
                try:
                    data = sock.recv(8192)
                    if not data:
                        return
                    
                    if sock is client_socket:
                        upstream_socket.sendall(data)
                    else:
                        client_socket.sendall(data)
                except (BlockingIOError, socket.error):
                    continue
                    
    except Exception as e:
        logger.debug(f"隧道处理出错: {e}")


def connect_to_upstream() -> Optional[socket.socket]:
    """
    连接到上游代理
    
    Returns:
        Optional[socket.socket]: 上游代理套接字，失败返回 None
    """
    try:
        upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream_socket.settimeout(30)
        upstream_socket.connect((config.upstream.host, config.upstream.port))
        return upstream_socket
    except Exception as e:
        logger.error(f"连接上游代理失败: {e}")
        return None


def handle_client(client_socket: socket.socket, client_address: Tuple[str, int]):
    """
    处理客户端连接
    """
    client_ip = client_address[0]
    upstream_socket = None
    success = False
    
    # 更新统计
    with stats_lock:
        connection_stats['total'] += 1
        connection_stats['active'] += 1
    
    try:
        # ========== 安全检查 ==========
        
        # 1. IP 白名单检查
        if not check_ip_whitelist(client_ip):
            logger.warning(f"[{client_ip}] IP 不在白名单中，拒绝连接")
            with stats_lock:
                connection_stats['ip_blocked'] += 1
            send_forbidden(client_socket, "IP not allowed")
            return
        
        # 2. 速率限制检查
        if not check_rate_limit(client_ip):
            logger.warning(f"[{client_ip}] 超过速率限制，拒绝连接")
            send_forbidden(client_socket, "Rate limit exceeded")
            return
        
        # 接收客户端请求
        client_socket.settimeout(30)
        request_data = client_socket.recv(8192)
        
        if not request_data:
            return
        
        # 3. 认证检查
        auth_passed, auth_info = verify_proxy_auth(request_data)
        if not auth_passed:
            logger.warning(f"[{client_ip}] 认证失败: {auth_info}")
            with stats_lock:
                connection_stats['auth_failed'] += 1
            send_auth_required(client_socket)
            return
        
        # ========== 安全检查结束 ==========
        
        # 解析请求
        host, port, method, raw_request = parse_http_request(request_data)
        
        if not host:
            # 这通常是浏览器的预连接探测或空请求，属于正常行为
            logger.debug(f"[{client_ip}] 无法解析请求 (可能是预连接探测)")
            return
        
        if config.logging.show_requests:
            if config.security.auth_enabled and auth_info:
                logger.info(f"[{client_ip}] [{auth_info}] {method} {host}:{port}")
            else:
                logger.info(f"[{client_ip}] {method} {host}:{port}")
        
        # 连接上游代理
        upstream_socket = connect_to_upstream()
        if not upstream_socket:
            client_socket.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            return
        
        if method == 'CONNECT':
            # HTTPS 隧道
            # 发送 CONNECT 请求到上游代理
            connect_request = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
            upstream_socket.sendall(connect_request.encode())
            
            # 读取上游代理响应
            response = upstream_socket.recv(4096)
            
            if b'200' in response:
                # 建立隧道
                handle_tunnel(client_socket, upstream_socket, host, port)
            else:
                # 上游代理拒绝连接
                client_socket.sendall(response)
        else:
            # HTTP 请求 - 直接转发
            upstream_socket.sendall(raw_request)
            
            # 接收并转发响应
            while True:
                try:
                    response_data = upstream_socket.recv(8192)
                    if not response_data:
                        break
                    client_socket.sendall(response_data)
                except socket.timeout:
                    break
                except Exception:
                    break
        
        success = True
                    
    except Exception as e:
        logger.debug(f"[{client_ip}] 处理请求时出错: {e}")
    finally:
        # 更新统计
        with stats_lock:
            connection_stats['active'] -= 1
            if success:
                connection_stats['success'] += 1
            else:
                connection_stats['failed'] += 1
        
        if upstream_socket:
            try:
                upstream_socket.close()
            except:
                pass
        try:
            client_socket.close()
        except:
            pass


def signal_handler(signum, frame):
    """处理退出信号"""
    global running
    print("\n\n🛑 正在关闭服务器...")
    running = False
    if server_socket:
        try:
            server_socket.close()
        except:
            pass
    sys.exit(0)


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description='局域网代理服务器 - 将局域网请求转发到 VPN 代理',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  python proxy_server.py                    使用默认配置文件 config.yaml
  python proxy_server.py -c my_config.yaml  使用自定义配置文件
  python proxy_server.py --skip-check       跳过上游代理检查
        '''
    )
    parser.add_argument(
        '-c', '--config',
        default='config.yaml',
        help='配置文件路径 (默认: config.yaml)'
    )
    parser.add_argument(
        '--skip-check',
        action='store_true',
        help='跳过上游代理健康检查'
    )
    return parser.parse_args()


def main():
    """主函数"""
    global config, logger, server_socket, running
    
    # 解析命令行参数
    args = parse_args()
    
    # 加载配置
    try:
        config = load_config(args.config)
    except FileNotFoundError as e:
        print(f"❌ 错误: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ 配置加载失败: {e}")
        sys.exit(1)
    
    # 设置日志
    logger = setup_logging(config.logging.level)
    
    # 获取局域网 IP
    ip_addresses = get_local_ip_addresses()
    
    # 打印启动信息
    print_banner(config, ip_addresses)
    
    # 检查上游代理
    if args.skip_check:
        print("⏭️  跳过上游代理检查")
    else:
        print("🔍 正在检查上游代理...")
        is_healthy, message = check_upstream_proxy(
            config.upstream,
            config.health_check.test_url,
            config.health_check.timeout
        )
        
        if is_healthy:
            print(f"✅ {message}")
        else:
            print(f"❌ {message}")
            print()
            print("⚠️  警告: 上游代理不可用，代理服务仍将启动，但可能无法正常工作。")
            print("   请检查 VPN 是否已启动，端口配置是否正确。")
            print()
            
            # 询问是否继续
            try:
                response = input("是否继续启动? (y/n): ").strip().lower()
                if response != 'y':
                    print("已取消启动。")
                    sys.exit(0)
            except KeyboardInterrupt:
                print("\n已取消启动。")
                sys.exit(0)
    
    print()
    
    # 注册信号处理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 创建服务器套接字
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((config.server.host, config.server.port))
        server_socket.listen(100)
        server_socket.settimeout(1)  # 允许检查 running 标志
        
        logger.info(f"🚀 代理服务器已启动，监听 {config.server.host}:{config.server.port}")
        logger.info("按 Ctrl+C 停止服务器")
        print()
        
    except PermissionError:
        print(f"❌ 错误: 没有权限绑定端口 {config.server.port}")
        print("   如果端口小于 1024，需要 root 权限")
        sys.exit(1)
    except OSError as e:
        print(f"❌ 错误: 无法绑定端口 {config.server.port}: {e}")
        print("   端口可能已被占用")
        sys.exit(1)
    
    # 主循环
    while running:
        try:
            client_socket, client_address = server_socket.accept()
            
            # 为每个客户端创建新线程
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True
            )
            client_thread.start()
            
        except socket.timeout:
            continue
        except Exception as e:
            if running:
                logger.error(f"接受连接时出错: {e}")


if __name__ == "__main__":
    main()
