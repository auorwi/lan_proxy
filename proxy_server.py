#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
局域网代理服务器
将局域网设备的请求转发到本地 VPN 代理端口

功能:
- 监听 HTTP 代理请求
- 转发到上游代理 (VPN)
- 支持 HTTP 和 HTTPS (CONNECT) 请求
"""

import socket
import threading
import select
import logging
import sys
import signal
import argparse
from typing import Optional, Tuple
from utils import (
    load_config, 
    get_local_ip_addresses, 
    check_upstream_proxy,
    print_banner,
    ProxyConfig
)

# 全局配置
config = None  # type: Optional[ProxyConfig]
logger = None  # type: Optional[logging.Logger]
server_socket = None  # type: Optional[socket.socket]
running = True
upstream_available = True  # 上游代理是否可用

# 连接统计
connection_stats = {
    'total': 0,
    'active': 0,
    'success': 0,
    'failed': 0
}
stats_lock = threading.Lock()


def setup_logging(level):
    # type: (str) -> logging.Logger
    """配置日志系统"""
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s | %(levelname)-7s | %(message)s',
        datefmt='%H:%M:%S'
    )
    
    return logging.getLogger('LAN-Proxy')


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
            # 处理 IPv6 地址格式 [ipv6]:port
            if url.startswith('['):
                # IPv6 地址
                bracket_end = url.find(']')
                if bracket_end != -1:
                    host = url[1:bracket_end]
                    if len(url) > bracket_end + 2 and url[bracket_end + 1] == ':':
                        try:
                            port = int(url[bracket_end + 2:])
                        except ValueError:
                            port = 443
                    else:
                        port = 443
                else:
                    host = url
                    port = 443
            else:
                # IPv4 或域名
                if ':' in url:
                    last_colon = url.rfind(':')
                    host = url[:last_colon]
                    try:
                        port = int(url[last_colon + 1:])
                    except ValueError:
                        port = 443
                else:
                    host = url
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


def handle_tunnel(client_socket, upstream_socket, host, port, send_response=True):
    # type: (socket.socket, socket.socket, str, int, bool) -> None
    """
    处理 HTTPS 隧道 (CONNECT 方法)
    
    Args:
        send_response: 是否发送 200 Connection Established 响应
    """
    # 发送连接成功响应给客户端（如果需要）
    if send_response:
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


def connect_to_upstream():
    # type: () -> Optional[socket.socket]
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
        logger.error(u"连接上游代理失败: %s" % e)
        return None


def connect_direct(host, port):
    # type: (str, int) -> Optional[socket.socket]
    """
    直接连接到目标服务器（不通过上游代理）
    支持 IPv4、IPv6 和域名解析
    
    Args:
        host: 目标主机（域名、IPv4 或 IPv6 地址）
        port: 目标端口
        
    Returns:
        Optional[socket.socket]: 目标服务器套接字，失败返回 None
    """
    try:
        # 处理 IPv6 地址格式 [xxxx:xxxx:...]
        if host.startswith('[') and host.endswith(']'):
            host = host[1:-1]
        
        # 使用 getaddrinfo 支持 IPv4/IPv6 和 DNS 解析
        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        
        # 尝试连接第一个可用地址
        for family, socktype, proto, canonname, sockaddr in addr_info:
            try:
                target_socket = socket.socket(family, socktype, proto)
                target_socket.settimeout(30)
                target_socket.connect(sockaddr)
                return target_socket
            except socket.error:
                continue
        
        logger.error(u"无法连接到目标服务器 %s:%d - 所有地址都失败" % (host, port))
        return None
        
    except socket.gaierror as e:
        logger.error(u"DNS解析失败 %s - %s" % (host, e))
        return None
    except Exception as e:
        logger.error(u"直接连接目标服务器失败 %s:%d - %s" % (host, port, e))
        return None


def handle_client(client_socket, client_address):
    # type: (socket.socket, Tuple[str, int]) -> None
    """
    处理客户端连接
    """
    global upstream_available
    client_ip = client_address[0]
    target_socket = None
    success = False
    
    # 更新统计
    with stats_lock:
        connection_stats['total'] += 1
        connection_stats['active'] += 1
    
    try:
        # 接收客户端请求
        client_socket.settimeout(30)
        request_data = client_socket.recv(8192)
        
        if not request_data:
            return
        
        # 解析请求
        host, port, method, raw_request = parse_http_request(request_data)
        
        if not host:
            # 这通常是浏览器的预连接探测或空请求，属于正常行为
            logger.debug(u"[%s] 无法解析请求 (可能是预连接探测)" % client_ip)
            return
        
        if config.logging.show_requests:
            mode = "PROXY" if upstream_available else "DIRECT"
            logger.info(u"[%s] [%s] %s %s:%d" % (client_ip, mode, method, host, port))
        
        if upstream_available:
            # ======== 通过上游代理转发 ========
            target_socket = connect_to_upstream()
            if not target_socket:
                client_socket.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                return
            
            if method == 'CONNECT':
                # HTTPS 隧道 - 通过上游代理
                connect_request = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n" % (host, port, host, port)
                target_socket.sendall(connect_request.encode())
                
                # 读取上游代理响应
                response = target_socket.recv(4096)
                
                if b'200' in response:
                    # 建立隧道
                    handle_tunnel(client_socket, target_socket, host, port)
                else:
                    # 上游代理拒绝连接
                    client_socket.sendall(response)
            else:
                # HTTP 请求 - 转发到上游代理
                target_socket.sendall(raw_request)
                
                # 接收并转发响应
                while True:
                    try:
                        response_data = target_socket.recv(8192)
                        if not response_data:
                            break
                        client_socket.sendall(response_data)
                    except socket.timeout:
                        break
                    except Exception:
                        break
        else:
            # ======== 直接连接目标服务器 ========
            target_socket = connect_direct(host, port)
            if not target_socket:
                client_socket.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                return
            
            if method == 'CONNECT':
                # HTTPS 隧道 - 直接连接
                # 告诉客户端连接已建立
                client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                # 建立隧道（不再发送响应，因为上面已经发送了）
                handle_tunnel(client_socket, target_socket, host, port, send_response=False)
            else:
                # HTTP 请求 - 需要修改请求为相对路径
                # 将绝对URL转换为相对路径
                request_text = raw_request.decode('utf-8', errors='ignore')
                lines = request_text.split('\r\n')
                if lines:
                    first_line = lines[0]
                    parts = first_line.split(' ')
                    if len(parts) >= 3 and parts[1].startswith('http://'):
                        # 提取路径部分
                        url = parts[1]
                        path_start = url.find('/', 7)  # 跳过 http://
                        if path_start != -1:
                            parts[1] = url[path_start:]
                        else:
                            parts[1] = '/'
                        lines[0] = ' '.join(parts)
                        raw_request = '\r\n'.join(lines).encode()
                
                target_socket.sendall(raw_request)
                
                # 接收并转发响应
                while True:
                    try:
                        response_data = target_socket.recv(8192)
                        if not response_data:
                            break
                        client_socket.sendall(response_data)
                    except socket.timeout:
                        break
                    except Exception:
                        break
        
        success = True
                    
    except Exception as e:
        logger.debug(u"[%s] 处理请求时出错: %s" % (client_ip, e))
    finally:
        # 更新统计
        with stats_lock:
            connection_stats['active'] -= 1
            if success:
                connection_stats['success'] += 1
            else:
                connection_stats['failed'] += 1
        
        if target_socket:
            try:
                target_socket.close()
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
    global config, logger, server_socket, running, upstream_available
    
    # 解析命令行参数
    args = parse_args()
    
    # 加载配置
    try:
        config = load_config(args.config)
    except FileNotFoundError as e:
        print(u"❌ 错误: %s" % e)
        sys.exit(1)
    except Exception as e:
        print(u"❌ 配置加载失败: %s" % e)
        sys.exit(1)
    
    # 设置日志
    logger = setup_logging(config.logging.level)
    
    # 获取局域网 IP
    ip_addresses = get_local_ip_addresses()
    
    # 打印启动信息
    print_banner(config, ip_addresses)
    
    # 检查上游代理
    if args.skip_check:
        print(u"⏭️  跳过上游代理检查")
        upstream_available = True
    else:
        print(u"🔍 正在检查上游代理...")
        is_healthy, message = check_upstream_proxy(
            config.upstream,
            config.health_check.test_url,
            config.health_check.timeout
        )
        
        if is_healthy:
            print(u"✅ %s" % message)
            upstream_available = True
        else:
            print(u"❌ %s" % message)
            print()
            print(u"⚠️  上游代理不可用，将使用直连模式（服务器出口IP）")
            upstream_available = False
    
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
        
        mode_str = u"代理模式" if upstream_available else u"直连模式"
        logger.info(u"🚀 代理服务器已启动 [%s]，监听 %s:%d" % (mode_str, config.server.host, config.server.port))
        logger.info(u"按 Ctrl+C 停止服务器")
        print()
        
    except PermissionError:
        print(u"❌ 错误: 没有权限绑定端口 %d" % config.server.port)
        print(u"   如果端口小于 1024，需要 root 权限")
        sys.exit(1)
    except OSError as e:
        print(u"❌ 错误: 无法绑定端口 %d: %s" % (config.server.port, e))
        print(u"   端口可能已被占用")
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
