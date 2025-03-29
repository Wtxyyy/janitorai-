#!/bin/bash

# ================================================================
# Project: 简易扒卡 (Ngrok API Character Card Extractor)
# Author: T小和Gemini
# Version: 3.1
# Description: 使用 Ngrok 创建一个临时 API 端点，接收特定格式的 JSON 数据，
#              将其转换为角色卡片格式 (V3)，并保存在本地文件夹中。
#              增加了 Authtoken 保存和 CORS 支持。
# ================================================================

# --- 配置 ---
LOCAL_PORT=8080
FIXED_RESPONSE_TEXT="请求已收到并成功处理。"
# 更新文件夹名称
DATA_DIR="./原始数据" # 用于存放原始接收数据的文件夹名称
PROCESSED_DATA_DIR="./可直接导入角色卡" # 用于存放处理后数据的文件夹名称
NGROK_LOG_FILE="./ngrok_runtime.log"
# Authtoken 保存文件
AUTHTOKEN_FILE=".ngrok_authtoken"
CUSTOM_INSTRUCTION="重要说明：API 端点已启用 CORS。它会接收 POST 请求中的 JSON 数据，按 V3 卡片格式处理后保存（文件名基于角色名），并返回固定消息。请妥善保管此链接。按 Ctrl+C 可以关闭此服务和脚本。"
# --- 配置结束 ---

# 定义清理函数
cleanup() {
    echo -e "\n正在停止服务..."
    if [[ ! -z "$NGROK_PID" ]] && kill -0 $NGROK_PID 2>/dev/null; then
        echo "正在停止 Ngrok (PID: $NGROK_PID)..."
        kill $NGROK_PID
    fi
    if [[ ! -z "$LOCAL_SERVER_PID" ]] && kill -0 $LOCAL_SERVER_PID 2>/dev/null; then
        echo "正在停止本地服务器 (PID: $LOCAL_SERVER_PID)..."
        kill $LOCAL_SERVER_PID
    fi
    # 保留日志文件以便调试
    # rm -f "$NGROK_LOG_FILE"
    echo "服务已停止。"
    exit 0
}

# 设置 trap
trap cleanup SIGINT SIGTERM

# 1. 检查并安装依赖 (curl, unzip, python3)
echo "--- 依赖检查 ---"
echo "正在检查所需工具 (curl, unzip, python3)..."
missing_tools=()
command -v curl >/dev/null 2>&1 || missing_tools+=("curl")
command -v unzip >/dev/null 2>&1 || missing_tools+=("unzip")
command -v python3 >/dev/null 2>&1 || missing_tools+=("python3")

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo "错误：缺少以下工具: ${missing_tools[*]}"
    echo "请先安装它们。例如，在 Debian/Ubuntu 上运行:"
    echo "sudo apt update && sudo apt install -y curl unzip python3"
    # 对于其他发行版，请使用相应的包管理器 (如 yum, dnf, pacman)
    exit 1
fi
echo "所需工具已找到。"
echo "------------------"

# 2. 创建数据接收和处理文件夹
echo "--- 文件夹设置 ---"
echo "正在创建数据文件夹 '$DATA_DIR' 和 '$PROCESSED_DATA_DIR' (如果不存在)..."
mkdir -p "$DATA_DIR"
mkdir -p "$PROCESSED_DATA_DIR"
echo "数据文件夹准备就绪。"
echo "--------------------"

# 3. 检查并下载 Ngrok
echo "--- Ngrok 设置 ---"
NGROK_CMD="ngrok"
if ! command -v ngrok > /dev/null 2>&1; then
    echo "未在 PATH 中找到 ngrok。正在检查当前目录..."
    if [ -f "./ngrok" ]; then
        echo "在当前目录找到 ngrok 可执行文件。"
        NGROK_CMD="./ngrok"
        chmod +x ./ngrok
    else
        echo "未找到 ngrok，尝试下载..."
        ARCH=$(uname -m)
        NGROK_ZIP_FILENAME="ngrok-stable-linux-amd64.zip"
        NGROK_DOWNLOAD_URL="https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.zip"
        if [[ "$ARCH" == "aarch64" ]] || [[ "$ARCH" == "arm64" ]]; then
            NGROK_ZIP_FILENAME="ngrok-stable-linux-arm64.zip"
            NGROK_DOWNLOAD_URL="https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-arm64.zip"
            echo "检测到 ARM64 架构。"
        elif [[ "$ARCH" == "armv7l" ]]; then
             NGROK_ZIP_FILENAME="ngrok-stable-linux-arm.zip"
             NGROK_DOWNLOAD_URL="https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-arm.zip"
             echo "检测到 ARMv7l 架构。"
        elif [[ "$ARCH" != "x86_64" ]] && [[ "$ARCH" != "amd64" ]]; then
             echo "警告：未知的或非默认支持的架构 '$ARCH'。将尝试下载 amd64 版本。"
        else
             echo "检测到 AMD64/x86_64 架构。"
        fi
        echo "正在从 $NGROK_DOWNLOAD_URL 下载..."
        curl -# -Lo "$NGROK_ZIP_FILENAME" "$NGROK_DOWNLOAD_URL" || { echo "错误：下载 Ngrok 失败。"; rm -f "$NGROK_ZIP_FILENAME"; exit 1; }
        echo "正在解压 $NGROK_ZIP_FILENAME..."
        unzip -oq "$NGROK_ZIP_FILENAME" -d . || { echo "错误：解压 Ngrok 失败。请确保 'unzip' 已安装且文件未损坏。"; rm -f "$NGROK_ZIP_FILENAME"; exit 1; }
        echo "Ngrok 下载并解压完成。"
        rm -f "$NGROK_ZIP_FILENAME" # 清理 zip 文件
        chmod +x ./ngrok
        NGROK_CMD="./ngrok" # 使用本地下载的 ngrok
    fi
else
    echo "在 PATH 中找到 ngrok。"
fi
echo "------------------"

# 4. 触发确认并获取/确认 Authtoken
echo "--- 用户确认和 Authtoken ---"
echo "脚本即将使用 Ngrok 创建一个公开的 API 端点。"
echo "这需要您的 Ngrok Authtoken 进行认证。"
echo "您可以访问 https://dashboard.ngrok.com/get-started/your-authtoken 获取。"
echo -e "\n\033[1;33m[重要提示] 手机用户使用 Termux，请务必打开手机热点，否则可能无法生成链接或访问！\033[0m\n" # 添加 Termux 提示
read -p "请阅读以上信息，按 Enter 键继续，或按 Ctrl+C 取消..." DUMMY_VAR_UNUSED

NGROK_AUTHTOKEN=""
# 检查是否存在已保存的 Authtoken
if [ -f "$AUTHTOKEN_FILE" ] && [ -s "$AUTHTOKEN_FILE" ]; then
    STORED_TOKEN=$(cat "$AUTHTOKEN_FILE")
    echo "检测到已保存的 Authtoken。"
    read -p "是否使用已保存的 Authtoken? (Y/n/c - 输入 'c' 或 'n' 来更改/重新输入): " use_stored
    # 默认为 Yes (按 Enter 或输入 Y/y)
    if [[ "$use_stored" =~ ^[Yy]?$ ]]; then
        NGROK_AUTHTOKEN=$STORED_TOKEN
        echo "已使用保存的 Authtoken。"
    elif [[ "$use_stored" =~ ^[CcNn]$ ]]; then # 如果输入 c/C 或 n/N，则提示输入新的
        echo "请输入新的 Ngrok Authtoken..."
        # 让代码继续执行下面的输入提示
    else
        echo "无效输入，将提示输入新的 Authtoken..."
        # 让代码继续执行下面的输入提示
    fi
fi

# 如果没有加载到 token (首次运行或用户选择更改)
if [ -z "$NGROK_AUTHTOKEN" ]; then
    read -p "请输入您的 Ngrok Authtoken: " NGROK_AUTHTOKEN
    if [ -z "$NGROK_AUTHTOKEN" ]; then
        echo "错误：未提供 Authtoken。正在退出。"
        exit 1
    fi
    # 保存新输入的 token
    echo "正在保存 Authtoken..."
    echo "$NGROK_AUTHTOKEN" > "$AUTHTOKEN_FILE"
    chmod 600 "$AUTHTOKEN_FILE" # 限制文件权限，增加安全性
    if [ $? -eq 0 ]; then
        echo "Authtoken 已成功保存到 $AUTHTOKEN_FILE"
    else
        echo "警告：保存 Authtoken 失败，请检查文件系统权限。"
    fi
fi
echo "---------------------------"

# 5. 配置 Ngrok Authtoken
echo "--- Ngrok 配置 ---"
echo "正在使用提供的 Authtoken 配置 Ngrok..."
# 使用 stdbuf 尝试获取实时输出，或者直接忽略输出
stdbuf -o0 $NGROK_CMD config add-authtoken "$NGROK_AUTHTOKEN" 2>&1 | grep -v "Authtoken saved" || echo "Ngrok Authtoken 配置完成（或已存在）。"
# 上面的命令尝试隐藏 "Authtoken saved..." 的默认输出，如果配置命令本身出错则显示错误
echo "------------------"

# 6. 启动本地 Python Web 服务器 (后台运行)
echo "--- 本地服务器启动 ---"
echo "正在后台启动本地 Web 服务器（含数据处理和CORS），监听端口 $LOCAL_PORT ..."

# --- Python 脚本 (内含数据转换逻辑和 CORS) ---
PYTHON_SCRIPT=$(cat <<EOF
import http.server
import socketserver
import sys
import io
import json
import os
import datetime
import re
import uuid
import traceback

# --- 配置 (从命令行参数获取) ---
PORT = int(sys.argv[1])
RESPONSE_TEXT = sys.argv[2].encode('utf-8')
RAW_DATA_DIR = sys.argv[3]
PROCESSED_DATA_DIR = sys.argv[4]

# --- 辅助函数 ---
def get_current_timestamp():
    """生成指定格式的时间戳 YYYY-MM-DD @HHh MMm SSs MMMms"""
    now = datetime.datetime.now()
    ms = now.strftime('%f')[:3]
    return now.strftime(f'%Y-%m-%d @%Hh %Mm %Ss {ms}ms')

def extract_tag_content(text, tag_name):
    """从文本中提取指定标签的内容 (非贪婪, 忽略大小写)"""
    pattern = f"<{re.escape(tag_name)}>(.*?)</{re.escape(tag_name)}>"
    match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else ""

def sanitize_filename(name):
    """清理文件名，移除不安全字符，替换空格"""
    # 移除非字母、数字、下划线、连字符的字符
    safe_name = re.sub(r'[^\w\-]+', '_', name)
    # 移除开头和结尾的下划线
    safe_name = safe_name.strip('_')
    # 防止文件名过短或为空
    return safe_name if safe_name else "processed_card"

# --- 数据转换核心逻辑 ---
def transform_data(input_data):
    output = {}
    system_prompt_content = ""
    description = ""
    scenario = ""
    mes_example = ""
    first_mes = ""
    name = "UnknownCharacter" # 默认名称

    if 'messages' in input_data and isinstance(input_data['messages'], list):
        for msg in input_data['messages']:
            role = msg.get('role')
            content = msg.get('content', '').strip()

            if role == 'system':
                system_prompt_content = content
                char_match = re.search(r"<(?!\/?(?:system|scenario|example_dialogs)\b)([^>]+?)>(.*?)</\1>", content, re.DOTALL | re.IGNORECASE)
                if char_match:
                    char_tag_name = char_match.group(1).strip()
                    char_tag_content = char_match.group(2).strip()
                    name = char_tag_name
                    description = char_tag_content
                scenario = extract_tag_content(content, 'scenario')
                raw_example = extract_tag_content(content, 'example_dialogs')
                if raw_example:
                    raw_example = re.sub(r'^Example conversations between.*?:\s*', '', raw_example, flags=re.IGNORECASE).strip()
                    mes_example = raw_example.replace('\n', '\r\n')
                    mes_example = re.sub(r'\bUSER:', 'user:', mes_example, flags=re.IGNORECASE) # 使用 \b 确保是单词边界

            elif role == 'assistant' and not first_mes:
                first_mes = content

    if name == "UnknownCharacter" and mes_example and ":" in mes_example:
         potential_name = mes_example.split(":", 1)[0].strip()
         if potential_name and potential_name.lower() != 'user': # 确保不是 'user:'
             name = potential_name

    # 提供默认值
    if not description and name != "UnknownCharacter": description = f"{name} 的描述待补充。"
    elif not description: description = "可爱，爱唱歌，也喜欢跳舞"
    if not scenario: scenario = "场景待补充。"
    if not mes_example: mes_example = f"{name}:你好！\\r\\nuser:你好！"
    if not first_mes: first_mes = f"你好，我是{name}！"

    current_time_str = get_current_timestamp()
    output = {
        "name": name, "description": description, "personality": "", "scenario": scenario,
        "first_mes": first_mes, "mes_example": mes_example, "creatorcomment": "", "avatar": "none",
        "chat": f"{name} - {current_time_str.split('@')[0].strip()} @{current_time_str.split('@')[1].strip()}",
        "talkativeness": "0.5", "fav": False, "tags": [], "spec": "chara_card_v3", "spec_version": "3.0",
        "create_date": current_time_str,
        "data": {
            "name": name, "description": description, "personality": "", "scenario": scenario,
            "first_mes": first_mes, "mes_example": mes_example, "creator_notes": "", "system_prompt": "",
            "post_history_instructions": "", "tags": [], "creator": "", "character_version": "",
            "alternate_greetings": [],
            "extensions": {
                "talkativeness": "0.5", "fav": False, "world": "",
                "depth_prompt": {"prompt": "", "depth": 4, "role": "system"}
            },
            "group_only_greetings": []
        }
    }
    print(f"数据转换完成，角色名: {name}")
    return output

# --- HTTP 请求处理器 ---
class ProcessingHTTPHandler(http.server.BaseHTTPRequestHandler):
    def send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.send_header('Access-Control-Max-Age', '86400')

    def do_OPTIONS(self):
        print(f"收到 OPTIONS 请求: {self.path} from {self.client_address}")
        self.send_response(204)
        self.send_cors_headers()
        self.end_headers()
        print("已发送 CORS 预检响应头")

    def do_GET(self):
        print(f"收到 GET 请求: {self.path} from {self.client_address}")
        self.send_response(200)
        self.send_cors_headers()
        self.send_header('Content-type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(RESPONSE_TEXT)))
        self.end_headers()
        self.wfile.write(RESPONSE_TEXT)
        print("已发送 GET 响应")

    def do_POST(self):
        timestamp_short = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:19]
        unique_id = str(uuid.uuid4())[:8]
        raw_filename = f"raw_{timestamp_short}_{unique_id}.json"
        processed_filename = f"processed_{timestamp_short}_{unique_id}.json"
        raw_filepath = os.path.join(RAW_DATA_DIR, raw_filename)
        processed_filepath = os.path.join(PROCESSED_DATA_DIR, processed_filename)
        post_data_str = ""
        print(f"收到 POST 请求: {self.path} from {self.client_address}")

        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                print("警告: 空 POST 请求体")
                self.send_response(400); self.send_cors_headers(); self.send_header('Content-type', 'text/plain'); self.end_headers(); self.wfile.write(b"Error: Empty POST body."); return

            post_data_bytes = self.rfile.read(content_length)
            try: post_data_str = post_data_bytes.decode('utf-8')
            except UnicodeDecodeError:
                try: post_data_str = post_data_bytes.decode('gbk'); print("警告: 使用 GBK 解码")
                except UnicodeDecodeError: post_data_str = post_data_bytes.decode('latin-1'); print("警告: 使用 latin-1 解码")
            print(f"请求体大小: {content_length} bytes")

            # 保存原始数据
            try:
                with open(raw_filepath, 'w', encoding='utf-8') as f_raw: f_raw.write(post_data_str)
                print(f"原始数据已保存至: {raw_filepath}")
            except IOError as e: print(f"错误：无法写入原始数据文件 {raw_filepath}: {e}")

            # 解析、转换、保存处理后数据
            input_json = json.loads(post_data_str)
            processed_json = transform_data(input_json)
            character_name = processed_json.get('name', 'UnknownCharacter')
            safe_filename_base = sanitize_filename(character_name)
            processed_filename = f"{safe_filename_base}.json" # 直接用名字，如果需要唯一性可以加时间戳
            # 检查文件是否已存在，如果存在则添加后缀
            counter = 1
            original_processed_filepath = os.path.join(PROCESSED_DATA_DIR, processed_filename)
            processed_filepath = original_processed_filepath
            while os.path.exists(processed_filepath):
                 processed_filename = f"{safe_filename_base}_{counter}.json"
                 processed_filepath = os.path.join(PROCESSED_DATA_DIR, processed_filename)
                 counter += 1
            if processed_filepath != original_processed_filepath:
                 print(f"注意: 文件 {original_processed_filepath} 已存在，将保存为 {processed_filename}")


            with open(processed_filepath, 'w', encoding='utf-8') as f_processed:
                json.dump(processed_json, f_processed, ensure_ascii=False, indent=4)
            print(f"处理后的角色卡已保存至: {processed_filepath}")

            # 发送成功响应
            self.send_response(200); self.send_cors_headers(); self.send_header('Content-type', 'text/plain; charset=utf-8'); self.send_header('Content-Length', str(len(RESPONSE_TEXT))); self.end_headers(); self.wfile.write(RESPONSE_TEXT)
            print("已发送 POST 成功响应")

        except json.JSONDecodeError as e:
            print(f"错误: 无效 JSON: {e}. Data(start): {post_data_str[:200]}...")
            self.send_response(400); self.send_cors_headers(); self.send_header('Content-type', 'text/plain'); self.end_headers(); self.wfile.write(f"Error: Invalid JSON. {e}".encode())
        except KeyError as e:
            print(f"错误: JSON 缺少字段: {e}. Data(start): {post_data_str[:200]}...")
            self.send_response(400); self.send_cors_headers(); self.send_header('Content-type', 'text/plain'); self.end_headers(); self.wfile.write(f"Error: Missing field {e}".encode())
        except IOError as e:
            print(f"错误: 无法写入文件 {processed_filepath}: {e}")
            self.send_response(500); self.send_cors_headers(); self.send_header('Content-type', 'text/plain'); self.end_headers(); self.wfile.write(b"Error: Cannot save file.")
        except Exception as e:
            print(f"未知服务器错误: {e}")
            traceback.print_exc() # 打印完整的回溯信息到日志
            error_log_path = os.path.join(RAW_DATA_DIR, f"error_{timestamp_short}_{unique_id}.log")
            try:
                with open(error_log_path, 'w', encoding='utf-8') as f_err:
                    f_err.write(f"Timestamp: {timestamp_short}\nError: {e}\nTraceback:\n{traceback.format_exc()}\n\nRaw Data:\n{post_data_str}\n")
                print(f"错误详情记录到: {error_log_path}")
            except Exception as log_e: print(f"记录错误日志失败: {log_e}")
            self.send_response(500); self.send_cors_headers(); self.send_header('Content-type', 'text/plain'); self.end_headers(); self.wfile.write(b"Error: Internal server error.")

# --- 服务器启动主逻辑 ---
if __name__ == "__main__":
    os.makedirs(RAW_DATA_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)
    with socketserver.TCPServer(("", PORT), ProcessingHTTPHandler) as httpd:
        print(f"本地服务器已在 http://localhost:{PORT} 启动 (PID: {os.getpid()})")
        print(f"原始数据将保存到: {os.path.abspath(RAW_DATA_DIR)}")
        print(f"处理后角色卡将保存到: {os.path.abspath(PROCESSED_DATA_DIR)}")
        print("等待传入请求...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n收到 Ctrl+C, 服务器正在关闭...")
            httpd.server_close()
EOF
) # 结束 PYTHON_SCRIPT=$(...) 的括号

# 在后台运行 Python 服务器，使用 -u 选项使日志实时输出
python3 -u -c "$PYTHON_SCRIPT" "$LOCAL_PORT" "$FIXED_RESPONSE_TEXT" "$DATA_DIR" "$PROCESSED_DATA_DIR" > ./local_server.log 2>&1 &
LOCAL_SERVER_PID=$!

# 短暂等待并确认服务器启动
sleep 3
if ! kill -0 $LOCAL_SERVER_PID 2>/dev/null; then
    echo "错误：本地 Python Web 服务器未能成功启动。请检查 ./local_server.log 获取详细错误信息。"
    cleanup
    exit 1
fi
echo "本地服务器已在后台运行 (PID: $LOCAL_SERVER_PID)。日志文件: ./local_server.log"
echo "----------------------"

# 7. 启动 Ngrok (后台运行)
echo "--- Ngrok 隧道启动 ---"
echo "正在后台启动 Ngrok，将本地端口 $LOCAL_PORT 暴露到公网..."
# 添加 --domain 参数如果用户有自定义域名的话，否则保持原样
$NGROK_CMD http $LOCAL_PORT --log "$NGROK_LOG_FILE" &
NGROK_PID=$!

# 8. 等待 Ngrok 启动并获取公网 URL
echo "正在等待 Ngrok 生成公网 URL (最多等待约 30 秒)..."
NGROK_URL=""
ATTEMPTS=0
MAX_ATTEMPTS=15
while [ -z "$NGROK_URL" ] && [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
    sleep 2
    # 尝试从 Ngrok Agent API 获取 URL
    NGROK_URL=$(curl -sf --connect-timeout 2 http://127.0.0.1:4040/api/tunnels | grep -o '"public_url":"https://[^"]*' | grep 'https://' | head -n 1 | cut -d'"' -f4)
    # 如果获取失败，并且 Ngrok 进程还在运行，则继续尝试
    if [ -z "$NGROK_URL" ] && ! kill -0 $NGROK_PID 2>/dev/null; then
         echo -e "\n错误：Ngrok 进程似乎已意外退出。请检查日志 $NGROK_LOG_FILE。"
         cleanup
         exit 1
    fi
    echo -n "." # 打印进度点
    ATTEMPTS=$((ATTEMPTS + 1))
done
echo # 换行
echo "---------------------"

# 9. 显示结果
if [ -z "$NGROK_URL" ]; then
    echo -e "\n\033[1;31m错误：无法在 $MAX_ATTEMPTS 次尝试内获取 Ngrok 公网 URL。\033[0m"
    echo "可能原因及排查方法:"
    echo "1. Ngrok 启动失败: 检查 Ngrok 运行时日志 '$NGROK_LOG_FILE'。"
    echo "2. 网络问题: 确保您的设备可以访问互联网和 Ngrok 服务。"
    echo "3. 本地服务器问题: 检查本地服务器日志 './local_server.log' 是否有错误。"
    echo "4. Ngrok Agent API (127.0.0.1:4040) 未就绪或访问受限。"
    echo "5. (Termux用户) 是否已打开手机热点？"
    cleanup
    exit 1
else
    echo -e "\n=========== \033[1;32mAPI 已就绪\033[0m ============"
    echo "您的临时公网 API URL (用于 POST JSON 数据) 是:"
    echo -e "  \033[1;34m$NGROK_URL\033[0m"
    echo "  (如果需要访问特定路径如 /v1, 请附加到此 URL 后)"
    echo "========================================"
    echo -e "$CUSTOM_INSTRUCTION"
    echo "----------------------------------------"
    echo "数据存储位置:"
    echo "  原始请求数据: $(realpath "$DATA_DIR")"
    echo "  处理后角色卡: $(realpath "$PROCESSED_DATA_DIR")"
    echo "----------------------------------------"
    echo "日志文件:"
    echo "  本地服务器日志: ./local_server.log"
    echo "  Ngrok 运行时日志: $NGROK_LOG_FILE"
    echo -e "\n\033[1;33m按 Ctrl+C 可以停止服务并关闭此脚本。\033[0m"

    # 等待 Ngrok 进程结束 (例如用户按 Ctrl+C，触发 trap)
    wait $NGROK_PID
fi

# 如果 wait 返回 (意味着 Ngrok 进程退出了，而不是通过 trap)，也执行清理
cleanup