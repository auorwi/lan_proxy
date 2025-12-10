# -*- coding: utf-8 -*-
"""
工具函数模块
提供网络检测、配置加载等功能
"""

import socket
import yaml
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass


@dataclass
class ServerConfig:
    """服务器配置"""
    port: int
    host: str


@dataclass
class UpstreamConfig:
    """上游代理配置"""
    host: str
    port: int
    proxy_type: str


@dataclass
class LoggingConfig:
    """日志配置"""
    level: str
    show_requests: bool


@dataclass
class HealthCheckConfig:
    """健康检查配置"""
    test_url: str
    timeout: int


@dataclass
class ProxyConfig:
    """完整代理配置"""
    server: ServerConfig
    upstream: UpstreamConfig
    logging: LoggingConfig
    health_check: HealthCheckConfig


def load_config(config_path: str = "config.yaml") -> ProxyConfig:
    """
    加载配置文件
    
    Args:
        config_path: 配置文件路径
        
    Returns:
        ProxyConfig: 配置对象
    """
    config_file = Path(config_path)
    
    if not config_file.exists():
        raise FileNotFoundError(f"配置文件不存在: {config_path}")
    
    with open(config_file, 'r', encoding='utf-8') as f:
        config_data = yaml.safe_load(f)
    
    server = ServerConfig(
        port=config_data.get('server', {}).get('port', 8080),
        host=config_data.get('server', {}).get('host', '0.0.0.0')
    )
    
    upstream = UpstreamConfig(
        host=config_data.get('upstream', {}).get('host', '127.0.0.1'),
        port=config_data.get('upstream', {}).get('port', 15236),
        proxy_type=config_data.get('upstream', {}).get('type', 'http')
    )
    
    logging_cfg = LoggingConfig(
        level=config_data.get('logging', {}).get('level', 'INFO'),
        show_requests=config_data.get('logging', {}).get('show_requests', True)
    )
    
    health_check = HealthCheckConfig(
        test_url=config_data.get('health_check', {}).get('test_url', 'https://www.google.com'),
        timeout=config_data.get('health_check', {}).get('timeout', 10)
    )
    
    return ProxyConfig(
        server=server,
        upstream=upstream,
        logging=logging_cfg,
        health_check=health_check
    )


def get_local_ip_addresses() -> List[Tuple[str, str]]:
    """
    获取本机所有局域网 IP 地址
    
    Returns:
        List[Tuple[str, str]]: (接口名称, IP地址) 列表
    """
    ip_list = []
    
    try:
        # 方法1: 通过创建临时连接获取主要 IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # 不需要真正连接，只是获取路由信息
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            ip_list.append(("primary", primary_ip))
    except Exception:
        pass
    
    try:
        # 方法2: 获取主机名对应的所有 IP
        hostname = socket.gethostname()
        # 获取所有地址信息
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
        for info in addr_info:
            ip = info[4][0]
            if ip not in [addr[1] for addr in ip_list] and not ip.startswith('127.'):
                ip_list.append(("interface", ip))
    except Exception:
        pass
    
    # 如果还是没有找到，尝试其他方法
    if not ip_list:
        try:
            # 获取所有网络接口（跨平台方法）
            import subprocess
            import platform
            
            if platform.system() == "Darwin":  # macOS
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'inet ' in line and '127.0.0.1' not in line:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            ip = parts[1]
                            if ip not in [addr[1] for addr in ip_list]:
                                ip_list.append(("interface", ip))
            elif platform.system() == "Linux":
                result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
                ips = result.stdout.strip().split()
                for ip in ips:
                    if ip not in [addr[1] for addr in ip_list]:
                        ip_list.append(("interface", ip))
        except Exception:
            pass
    
    return ip_list


def check_upstream_proxy(upstream: UpstreamConfig, test_url: str, timeout: int) -> Tuple[bool, str]:
    """
    检查上游代理是否可用
    
    Args:
        upstream: 上游代理配置
        test_url: 测试 URL
        timeout: 超时时间
        
    Returns:
        Tuple[bool, str]: (是否可用, 消息)
    """
    proxy_url = f"http://{upstream.host}:{upstream.port}"
    
    # 首先检查端口是否开放
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((upstream.host, upstream.port))
        sock.close()
        
        if result != 0:
            return False, f"上游代理端口 {upstream.host}:{upstream.port} 未开放或无法连接"
    except Exception as e:
        return False, f"检查上游代理端口失败: {str(e)}"
    
    # 然后尝试通过代理访问测试 URL
    try:
        proxy_handler = urllib.request.ProxyHandler({
            'http': proxy_url,
            'https': proxy_url
        })
        opener = urllib.request.build_opener(proxy_handler)
        
        request = urllib.request.Request(
            test_url,
            headers={'User-Agent': 'Mozilla/5.0 LAN-Proxy-Health-Check'}
        )
        
        response = opener.open(request, timeout=timeout)
        status_code = response.getcode()
        
        if status_code == 200:
            return True, f"上游代理正常，成功访问 {test_url}"
        else:
            return True, f"上游代理响应，状态码: {status_code}"
            
    except urllib.error.URLError as e:
        return False, f"通过上游代理访问失败: {str(e)}"
    except Exception as e:
        return False, f"健康检查失败: {str(e)}"


def print_banner(config: ProxyConfig, ip_addresses: List[Tuple[str, str]]):
    """
    打印启动横幅
    
    Args:
        config: 代理配置
        ip_addresses: IP 地址列表
    """
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                    🌐 局域网代理服务器                              ║
║                    LAN Proxy Server                              ║
╚══════════════════════════════════════════════════════════════════╝
"""
    print(banner)
    
    print("📋 配置信息:")
    print(f"   • 监听端口: {config.server.port}")
    print(f"   • 上游代理: {config.upstream.host}:{config.upstream.port}")
    print(f"   • 代理类型: {config.upstream.proxy_type.upper()}")
    print()
    
    print("🖥️  局域网 IP 地址:")
    if ip_addresses:
        for _, ip in ip_addresses:
            print(f"   • http://{ip}:{config.server.port}")
    else:
        print("   ⚠️  未能获取局域网 IP 地址")
    print()
    
    print("📱 其他设备代理设置:")
    if ip_addresses:
        primary_ip = ip_addresses[0][1]
        print(f"   • 代理服务器: {primary_ip}")
        print(f"   • 代理端口: {config.server.port}")
        print(f"   • 代理类型: HTTP")
        print(f"   • 认证: 无需认证")
    print()


def format_bytes(size: int) -> str:
    """格式化字节大小显示"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"


if __name__ == "__main__":
    # 测试功能
    print("测试获取本地 IP 地址:")
    ips = get_local_ip_addresses()
    for name, ip in ips:
        print(f"  {name}: {ip}")
