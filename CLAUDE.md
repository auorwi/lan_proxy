# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目简介

局域网代理工具：将局域网内其他设备的 HTTP/HTTPS 请求通过本机的 VPN 代理转发出去。当上游代理不可用时，自动降级为直连模式。

## 常用命令

```bash
# 安装依赖
pip install -r requirements.txt

# 启动代理服务器（使用默认 config.yaml）
python proxy_server.py

# 使用自定义配置文件
python proxy_server.py -c my_config.yaml

# 跳过上游代理健康检查直接启动
python proxy_server.py --skip-check
```

## 架构说明

项目只有两个核心文件：

- **`proxy_server.py`** — 主服务器逻辑。使用 `threading` 每个连接一个线程，通过 `select` 实现双向数据转发。全局 `upstream_available` 标志控制当前是代理模式还是直连模式。
- **`utils.py`** — 配置加载（`dataclass` 结构）、局域网 IP 检测、上游代理健康检查、启动横幅打印。

### 请求处理流程

1. 客户端连接 → `handle_client()` 在新线程中处理
2. `parse_http_request()` 解析请求，区分 `CONNECT`（HTTPS 隧道）和普通 HTTP
3. 根据 `upstream_available`：
   - **代理模式**：连接上游代理 (`connect_to_upstream()`)，CONNECT 请求转发隧道建立指令，HTTP 请求直接转发原始数据
   - **直连模式**：直接连接目标服务器 (`connect_direct()`)，HTTP 请求需将绝对 URL 转换为相对路径

### 配置结构

`config.yaml` 通过 `load_config()` 解析为嵌套 dataclass：`ProxyConfig` → `ServerConfig` / `UpstreamConfig` / `LoggingConfig` / `HealthCheckConfig`

上游代理默认指向 `127.0.0.1:15236`（本机 VPN 代理端口），对外监听 `0.0.0.0:8080`。
