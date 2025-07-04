import logging
import sys
import os
import requests
import re
import csv
import subprocess
import threading
import time
import json
import argparse
import platform
import shutil
import tarfile
from typing import List, Tuple, Dict
from collections import defaultdict
from charset_normalizer import detect
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from pathlib import Path
from packaging import version
import tempfile
import atexit
import stat
import venv
import ast

# 确保日志文件路径可写
LOG_FILE = "speedtest.log"
LOG_DIR = os.path.dirname(os.path.abspath(__file__))
try:
    os.makedirs(LOG_DIR, exist_ok=True)
    LOG_PATH = os.path.join(LOG_DIR, LOG_FILE)
    with open(LOG_PATH, 'a', encoding='utf-8') as f:
        pass
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s',
        handlers=[
            logging.FileHandler(LOG_PATH, encoding="utf-8", mode="w"),
            logging.StreamHandler(sys.stdout)  # 恢复 StreamHandler
        ],
        force=True
    )
    logger = logging.getLogger(__name__)
    logger.info(f"日志初始化完成，日志文件: {LOG_PATH}")
except Exception as e:
    print(f"无法创建日志文件 {LOG_PATH}: {e}")
    sys.exit(1)

# 禁用 stdout 缓冲，确保实时输出
sys.stdout.reconfigure(line_buffering=True)

# 配置
IP_LIST_FILE = "ip.txt"
IPS_FILE = "ips.txt"
FINAL_CSV = "ip.csv"
INPUT_FILE = "input.csv"
TEMP_FILE = os.path.join(tempfile.gettempdir(), "temp_proxy.csv")
TEMP_FILE_CACHE_DURATION = 3600
INPUT_URL = "https://bihai.cf/CFIP/CUCC/standard.csv"
COUNTRY_CACHE_FILE = "country_cache.json"
GEOIP_DB_PATH = Path("GeoLite2-Country.mmdb")
GEOIP_DB_URL_BACKUP = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key={}&suffix=tar.gz"
MAXMIND_LICENSE_KEY = os.getenv("MAXMIND_LICENSE_KEY", "")
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.google.com/"
}
DESIRED_COUNTRIES = ['TW', 'JP', 'HK', 'SG', 'KR', 'IN', 'KP', 'VN', 'TH', 'MM','US']
REQUIRED_PACKAGES = ['requests', 'charset-normalizer', 'geoip2==4.8.0', 'maxminddb>=2.0.0']
CONFIG_FILE = ".gitconfig.json"
SSH_KEY_PATH = os.path.expanduser("~/.ssh/id_ed25519")
VENV_DIR = ".venv"

# 国家代码和标签
COUNTRY_LABELS = {
    'JP': ('🇯🇵', '日本'), 'KR': ('🇰🇷', '韩国'), 'SG': ('🇸🇬', '新加坡'),
    'TW': ('🇹🇼', '台湾'), 'HK': ('🇭🇰', '香港'), 'MY': ('🇲🇾', '马来西亚'),
    'TH': ('🇹🇭', '泰国'), 'ID': ('🇮🇩', '印度尼西亚'), 'PH': ('🇵🇭', '菲律宾'),
    'VN': ('🇻🇳', '越南'), 'IN': ('🇮🇳', '印度'), 'MO': ('🇲🇴', '澳门'),
    'KH': ('🇰🇭', '柬埔寨'), 'LA': ('🇱🇦', '老挝'), 'MM': ('🇲🇲', '缅甸'),
    'MN': ('🇲🇳', '蒙古'), 'KP': ('🇵🇵', '朝鲜'), 'US': ('🇺🇸', '美国'),
    'GB': ('🇬🇧', '英国'), 'DE': ('🇩🇪', '德国'), 'FR': ('🇫🇷', '法国'),
    'IT': ('🇮🇹', '意大利'), 'ES': ('🇪🇸', '西班牙'), 'NL': ('🇳🇱', '荷兰'),
    'FI': ('🇫🇮', '芬兰'), 'AU': ('🇦🇺', '澳大利亚'), 'CA': ('🇨🇦', '加拿大'),
    'NZ': ('🇳🇿', '新西兰'), 'BR': ('🇧🇷', '巴西'), 'RU': ('🇷🇺', '俄罗斯'),
    'PL': ('🇵🇱', '波兰'), 'UA': ('🇺🇦', '乌克兰'), 'CZ': ('🇨🇿', '捷克'),
    'HU': ('🇭🇺', '匈牙利'), 'RO': ('🇷🇴', '罗马尼亚'), 'SA': ('🇸🇦', '沙特阿拉伯'),
    'AE': ('🇦🇪', '阿联酋'), 'QA': ('🇶🇦', '卡塔尔'), 'IL': ('🇮🇱', '以色列'),
    'TR': ('🇹🇷', '土耳其'), 'IR': ('🇮🇷', '伊朗'),
    'CN': ('🇨🇳', '中国'), 'BD': ('🇧🇩', '孟加拉国'), 'PK': ('🇵🇰', '巴基斯坦'),
    'LK': ('🇱�开户', '斯里兰卡'), 'NP': ('🇵🇵', '尼泊尔'), 'BT': ('🇧🇹', '不丹'),
    'MV': ('🇲🇻', '马尔代夫'), 'BN': ('🇧🇳', '文莱'), 'TL': ('🇹🇱', '东帝汶'),
    'EG': ('🇪🇬', '埃及'), 'ZA': ('🇿🇦', '南非'), 'NG': ('🇳🇬', '尼日利亚'),
    'KE': ('🇰🇪', '肯尼亚'), 'GH': ('🇬🇭', '加纳'), 'MA': ('🇲🇦', '摩洛哥'),
    'DZ': ('🇩🇿', '阿尔及利亚'), 'TN': ('🇹🇳', '突尼斯'), 'AR': ('🇦🇷', '阿根廷'),
    'CL': ('🇨🇱', '智利'), 'CO': ('🇨🇴', '哥伦比亚'), 'PE': ('🇵🇪', '秘鲁'),
    'MX': ('🇲🇽', '墨西哥'), 'VE': ('🇻🇪', '委内瑞拉'), 'SE': ('🇸🇪', '瑞典'),
    'NO': ('🇳🇴', '挪威'), 'DK': ('🇩🇰', '丹麦'), 'CH': ('🇨🇭', '瑞士'),
    'AT': ('🇦🇹', '奥地利'), 'BE': ('🇧🇪', '比利时'), 'IE': ('🇮🇪', '爱尔兰'),
    'PT': ('🇵🇹', '葡萄牙'), 'GR': ('🇬🇷', '希腊'), 'BG': ('🇧🇬', '保加利亚'),
    'SK': ('🇸🇰', '斯洛伐克'), 'SI': ('🇸🇮', '斯洛文尼亚'), 'HR': ('🇭🇷', '克罗地亚'),
    'RS': ('🇷🇸', '塞尔维亚'), 'BA': ('🇧🇦', '波黑'), 'MK': ('🇲🇰', '北马其顿'),
    'AL': ('🇦🇱', '阿尔巴尼亚'), 'KZ': ('🇰🇿', '哈萨克斯坦'), 'UZ': ('🇺🇿', '乌兹别克斯坦'),
    'KG': ('🇰🇬', '吉尔吉斯斯坦'), 'TJ': ('🇹🇯', '塔吉克斯坦'), 'TM': ('🇹🇲', '土库曼斯坦'),
    'GE': ('🇬🇪', '格鲁吉亚'), 'AM': ('🇦🇲', '亚美尼亚'), 'AZ': ('🇦🇿', '阿塞拜疆'),
    'KW': ('🇰🇼', '科威特'), 'BH': ('🇧🇭', '巴林'), 'OM': ('🇴🇲', '阿曼'),
    'JO': ('🇯🇴', '约旦'), 'LB': ('🇱🇧', '黎巴嫩'), 'SY': ('🇸🇾', '叙利亚'),
    'IQ': ('🇮🇶', '伊拉克'), 'YE': ('🇾🇪', '也门'),
    'EE': ('🇪🇪', '爱沙尼亚'), 'LV': ('🇱🇻', '拉脱维亚'), 'LT': ('🇱🇹', '立陶宛'),
    'MD': ('🇲🇩', '摩尔多瓦'), 'LU': ('🇱🇺', '卢森堡'), 'SC': ('🇸🇨', '塞舌尔'),
    'CY': ('🇨🇾', '塞浦路斯'), 'GI': ('🇬🇮', '直布罗陀'),
}

# 国家别名
COUNTRY_ALIASES = {
    'SOUTH KOREA': 'KR', 'KOREA': 'KR', 'REPUBLIC OF KOREA': 'KR', 'KOREA, REPUBLIC OF': 'KR',
    'HONG KONG': 'HK', 'HONGKONG': 'HK', 'HK SAR': 'HK',
    'UNITED STATES': 'US', 'USA': 'US', 'U.S.': 'US', 'UNITED STATES OF AMERICA': 'US',
    'UNITED KINGDOM': 'GB', 'UK': 'GB', 'GREAT BRITAIN': 'GB', '英国': 'GB',
    'JAPAN': 'JP', 'JPN': 'JP', '日本': 'JP',
    'TAIWAN': 'TW', 'TWN': 'TW', 'TAIWAN, PROVINCE OF CHINA': 'TW', '台湾': 'TW',
    'SINGAPORE': 'SG', 'SGP': 'SG', '新加坡': 'SG',
    'FRANCE': 'FR', 'FRA': 'FR', '法国': 'FR',
    'GERMANY': 'DE', 'DEU': 'DE', '德国': 'DE',
    'NETHERLANDS': 'NL', 'NLD': 'NL', '荷兰': 'NL',
    'AUSTRALIA': 'AU', 'AUS': 'AU', '澳大利亚': 'AU',
    'CANADA': 'CA', 'CAN': 'CA', '加拿大': 'CA',
    'BRAZIL': 'BR', 'BRA': 'BR', '巴西': 'BR',
    'RUSSIA': 'RU', 'RUS': 'RU', '俄罗斯': 'RU',
    'INDIA': 'IN', 'IND': 'IN', '印度': 'IN',
    'CHINA': 'CN', 'CHN': 'CN', '中国': 'CN',
    'VIET NAM': 'VN', 'VIETNAM': 'VN', '越南': 'VN',
    'THAILAND': 'TH', 'THA': 'TH', '泰国': 'TH',
    'BURMA': 'MM', 'MYANMAR': 'MM', '缅甸': 'MM',
    'NORTH KOREA': 'KP', 'KOREA, DEMOCRATIC PEOPLE\'S REPUBLIC OF': 'KP', '朝鲜': 'KP',
    'MOLDOVA': 'MD', 'REPUBLIC OF MOLDOVA': 'MD', 'MOLDOVA, REPUBLIC OF': 'MD', '摩尔多瓦': 'MD',
    'LUXEMBOURG': 'LU', 'GRAND DUCHY OF LUXEMBOURG': 'LU', '卢森堡': 'LU',
    'SEYCHELLES': 'SC', 'REPUBLIC OF SEYCHELLES': 'SC', '塞舌尔': 'SC',
    'CYPRUS': 'CY', 'REPUBLIC OF CYPRUS': 'CY', '塞浦路斯': 'CY',
    'GIBRALTAR': 'GI', '直布罗陀': 'GI',
}

# 城市到国家代码映射表
CITY_TO_COUNTRY = {
    'TOKYO': 'JP',
    'HONG KONG': 'HK',
    'HONGKONG': 'HK',
    'LOS ANGELES': 'US',
    'MANILA': 'PH',
    'SINGAPORE': 'SG',
    'SAN JOSE': 'US',
    'YEREVAN': 'AM',
    'FRANKFURT': 'DE',
    'AMSTERDAM': 'NL',
    'MOSCOW': 'RU',
    'SEOUL': 'KR',
    'TAIPEI': 'TW',
    'BANGKOK': 'TH',
    'JAKARTA': 'ID',
    'HO CHI MINH CITY': 'VN',
    'HANOI': 'VN',
    'NEW DELHI': 'IN',
    'YANGON': 'MM',
    'MACAU': 'MO',
    'PHNOM PENH': 'KH',
    'VIENTIANE': 'LA',
    'ULAANBAATAR': 'MN',
    'PYONGYANG': 'KP',
    'CHISINAU': 'MD',
    'KISHINEV': 'MD',
    'LUXEMBOURG': 'LU',
    'VICTORIA': 'SC',
    'NICOSIA': 'CY',
    'GIBRALTAR': 'GI',
}

# IATA 代码到国家代码映射表
IATA_TO_COUNTRY = {
    'NRT': 'JP',
    'HKG': 'HK',
    'LAX': 'US',
    'MNL': 'PH',
    'SIN': 'SG',
    'SJC': 'US',
    'EVN': 'AM',
    'FRA': 'DE',
    'AMS': 'NL',
    'DME': 'RU',
    'ICN': 'KR',
    'TPE': 'TW',
    'BKK': 'TH',
    'CGK': 'ID',
    'SGN': 'VN',
    'HAN': 'VN',
    'DEL': 'IN',
    'RGN': 'MM',
    'MFM': 'MO',
    'PNH': 'KH',
    'VTE': 'LA',
    'ULN': 'MN',
    'KIV': 'MD',
    'LUX': 'LU',
    'SEZ': 'SC',
    'LCA': 'CY',
    'PFO': 'CY',
    'GIB': 'GI',
}

def find_speedtest_script() -> str:
    system = platform.system().lower()
    candidates = []
    if system == "windows":
        candidates = ["iptest.bat", ".\\iptest.bat"]
    else:
        candidates = ["iptest.sh", "./iptest.sh", "iptest", "./iptest"]
    for candidate in candidates:
        if os.path.exists(candidate):
            if not os.access(candidate, os.X_OK) and system != "windows":
                try:
                    os.chmod(candidate, 0o755)
                    logger.info(f"已为 {candidate} 添加执行权限")
                except Exception as e:
                    logger.error(f"无法为 {candidate} 添加执行权限: {e}")
                    continue
            logger.info(f"找到测速脚本: {candidate}")
            return candidate
    logger.error("未找到测速脚本，请确保 iptest.sh 或 iptest.bat 存在")
    sys.exit(1)

SPEEDTEST_SCRIPT = find_speedtest_script()

def is_termux() -> bool:
    """检查是否运行在 Termux 环境中"""
    return os.getenv("TERMUX_VERSION") is not None or "com.termux" in os.getenv("PREFIX", "")

def parse_speedlimit_from_script(script_path: str) -> float:
    """从 iptest.sh 或 iptest.bat 解析 speedlimit 参数，默认为 8.0 MB/s"""
    try:
        # 使用 charset_normalizer 检测文件编码
        with open(script_path, "rb") as f:
            raw_data = f.read()
        detected = detect(raw_data)
        encoding = detected.get("encoding", "utf-8") or "utf-8"
        logger.info(f"检测到 {script_path} 的编码: {encoding}")

        # 解码文件内容
        content = raw_data.decode(encoding, errors="replace")
        logger.debug(f"{script_path} 内容（前 1000 字符）: {content[:1000]}")

        # 匹配 speedlimit 参数，支持多种格式
        speedlimit_match = re.search(
            r'(?:--)?speed(?:limit|_limit)\s*[=:\s]\s*"?(\d*\.?\d*)"?\s*(?:MB/s)?',
            content,
            re.IGNORECASE
        )
        if speedlimit_match:
            speedlimit = float(speedlimit_match.group(1))
            logger.info(f"从 {script_path} 解析到 speedlimit: {speedlimit} MB/s")
            return speedlimit

        logger.info(f"未在 {script_path} 中找到 speedlimit 参数，使用默认值 8.0 MB/s")
        return 8.0
    except Exception as e:
        logger.warning(f"无法解析 {script_path} 的 speedlimit 参数: {e}，使用默认值 8.0 MB/s")
        return 8.0

def filter_ip_csv_by_speed(csv_file: str, speed_limit: float):
    """根据 speed_limit 过滤 ip.csv 中的低速节点"""
    try:
        temp_file = csv_file + ".tmp"
        with open(csv_file, "r", encoding="utf-8") as f_in, open(temp_file, "w", newline="", encoding="utf-8") as f_out:
            reader = csv.reader(f_in)
            writer = csv.writer(f_out)
            header = next(reader, None)
            if not header:
                logger.error(f"{csv_file} 没有有效的表头")
                return
            writer.writerow(header)
            speed_col = 9  # 第 10 列是“下载速度MB/s”
            filtered_count = 0
            total_count = 0
            for row in reader:
                total_count += 1
                if len(row) > speed_col and row[speed_col].strip():
                    try:
                        speed = float(row[speed_col])
                        if speed >= speed_limit:
                            writer.writerow(row)
                        else:
                            filtered_count += 1
                    except ValueError:
                        filtered_count += 1
                        continue
                else:
                    filtered_count += 1
            logger.info(f"过滤 {csv_file}: 总计 {total_count} 个节点，过滤掉 {filtered_count} 个低速节点（速度 < {speed_limit} MB/s）")
        os.replace(temp_file, csv_file)
    except Exception as e:
        logger.error(f"过滤 {csv_file} 失败: {e}")

geoip_reader = None

def cleanup_temp_file():
    if os.path.exists(TEMP_FILE):
        try:
            os.remove(TEMP_FILE)
            logger.info(f"已清理临时文件: {TEMP_FILE}")
        except Exception as e:
            logger.warning(f"无法清理临时文件: {e}")

atexit.register(cleanup_temp_file)

def setup_and_activate_venv():
    logger = logging.getLogger(__name__)
    
    # 定义依赖列表
    REQUIRED_PACKAGES = ['requests', 'charset-normalizer', 'geoip2==4.8.0', 'maxminddb>=2.0.0', 'packaging>=21.3']
    
    # 检测平台
    system = sys.platform.lower()
    if system.startswith('win'):
        system = 'windows'
    elif system.startswith('linux'):
        system = 'linux'
    elif system.startswith('darwin'):
        system = 'darwin'
    else:
        logger.error(f"不支持的平台: {system}")
        sys.exit(1)
    
    logger.debug(f"检测到的平台: {system}")
    logger.debug(f"Python 可执行文件: {sys.executable}, 版本: {sys.version}")
    
    venv_path = Path('.venv')
    logger.debug(f"虚拟环境路径: {venv_path}")
    
    # 检查是否需要重建虚拟环境
    recreate_venv = False
    if venv_path.exists():
        logger.debug(f"检测到现有虚拟环境: {venv_path}")
        venv_python = str(venv_path / ('Scripts' if system == 'windows' else 'bin') / 'python')
        try:
            result = subprocess.run([venv_python, '--version'], check=True, capture_output=True, text=True)
            logger.debug(f"虚拟环境 Python 版本: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            logger.warning(f"虚拟环境 Python 不可用: {e}, 将重新创建")
            recreate_venv = True
    else:
        logger.debug("未找到虚拟环境，将创建")
        recreate_venv = True
    
    pip_venv = str(venv_path / ('Scripts' if system == 'windows' else 'bin') / 'pip')
    logger.debug("开始检查虚拟环境依赖")
    
    # 检查已安装的依赖
    installed_packages = {}
    if not recreate_venv:
        try:
            result = subprocess.run([pip_venv, "list", "--format=json"], check=True, capture_output=True, text=True)
            logger.debug(f"pip list 输出: {result.stdout}")
            installed_packages = {pkg["name"].lower(): pkg["version"] for pkg in json.loads(result.stdout)}
            logger.debug(f"已安装的包: {installed_packages}")
        except subprocess.CalledProcessError as e:
            logger.error(f"pip list 失败: {e}, 输出: {e.output}")
            recreate_venv = True
    
    # 验证依赖是否满足
    missing_packages = []
    if not recreate_venv:
        for pkg in REQUIRED_PACKAGES:
            if '==' in pkg:
                pkg_name, expected_version = pkg.split('==')
                version_op = '=='
            elif '>=' in pkg:
                pkg_name, expected_version = pkg.split('>=')
                version_op = '>='
            else:
                pkg_name, expected_version = pkg, None
                version_op = None
            pkg_name = pkg_name.lower().replace('_', '-')
            
            if pkg_name not in installed_packages:
                logger.warning(f"未找到依赖: {pkg_name}")
                missing_packages.append(pkg)
                continue
            
            if expected_version:
                installed_version = installed_packages[pkg_name]
                if version_op == '==' and installed_version != expected_version:
                    logger.warning(f"依赖 {pkg_name} 版本不匹配，实际 {installed_version}，期望 == {expected_version}")
                    missing_packages.append(pkg)
                elif version_op == '>=' and version.parse(installed_version) < version.parse(expected_version):
                    logger.warning(f"依赖 {pkg_name} 版本过低，实际 {installed_version}，期望 >= {expected_version}")
                    missing_packages.append(pkg)
    
    if missing_packages:
        logger.warning(f"虚拟环境缺少依赖: {missing_packages}，将重新创建")
        recreate_venv = True
    else:
        logger.info("所有依赖已满足，无需重新创建虚拟环境")
        recreate_venv = False
    
    # 创建或重建虚拟环境
    if recreate_venv:
        if venv_path.exists():
            logger.debug("删除现有虚拟环境")
            shutil.rmtree(venv_path, ignore_errors=True)
            logger.debug("成功删除现有虚拟环境")
        
        logger.debug(f"创建虚拟环境: {venv_path}")
        try:
            subprocess.run([sys.executable, '-m', 'venv', str(venv_path)], check=True)
            logger.debug("虚拟环境创建成功")
        except subprocess.CalledProcessError as e:
            logger.error(f"创建虚拟环境失败: {e}")
            sys.exit(1)
        
        venv_python = str(venv_path / ('Scripts' if system == 'windows' else 'bin') / 'python')
        pip_venv = str(venv_path / ('Scripts' if system == 'windows' else 'bin') / 'pip')
        logger.debug(f"虚拟环境 Python: {venv_python}, pip: {pip_venv}")
        
        # 尝试升级 pip（非致命）
        try:
            result = subprocess.run([pip_venv, 'install', '--upgrade', 'pip'], check=True, capture_output=True, text=True)
            logger.debug(f"升级 pip 成功: {result.stdout}")
        except subprocess.CalledProcessError as e:
            logger.warning(f"升级 pip 失败: {e}, 输出: {e.output}, 继续安装依赖")
        
        # 安装依赖
        for pkg in REQUIRED_PACKAGES:
            logger.debug(f"安装依赖: {pkg}")
            try:
                result = subprocess.run([pip_venv, 'install', pkg], check=True, capture_output=True, text=True)
                logger.debug(f"成功安装依赖: {pkg}, 输出: {result.stdout}")
            except subprocess.CalledProcessError as e:
                logger.error(f"安装依赖 {pkg} 失败: {e}, 输出: {e.output}")
                sys.exit(1)
    
    # 将虚拟环境的 site-packages 添加到 sys.path
    venv_site = str(venv_path / ('Lib' if system == 'windows' else 'lib') / 
                    f"python{sys.version_info.major}.{sys.version_info.minor}" / 'site-packages')
    logger.debug(f"虚拟环境 site-packages: {venv_site}")
    if venv_site not in sys.path:
        sys.path.insert(0, venv_site)
    logger.debug("虚拟环境已激活")
    
    # 清理模块缓存
    for module in list(sys.modules.keys()):
        if module.startswith('geoip2') or module.startswith('maxminddb'):
            del sys.modules[module]
    logger.debug("已清理 geoip2 和 maxminddb 模块缓存")
    
    # 验证关键模块
    try:
        import geoip2.database
        import maxminddb
        import packaging
        logger.debug("所有关键模块导入成功")
    except ImportError as e:
        logger.error(f"无法导入关键模块: {e}")
        sys.exit(1)

def get_latest_geoip_url() -> str:
    api_url = "https://api.github.com/repos/P3TERX/GeoLite.mmdb/releases/latest"
    logger.info(f"正在从 GitHub API 获取最新版本: {api_url}")
    try:
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504, 429])
        session.mount('https://', HTTPAdapter(max_retries=retry))
        response = session.get(api_url, headers=HEADERS, timeout=30)
        response.raise_for_status()
        release_data = response.json()
        
        for asset in release_data.get("assets", []):
            if asset.get("name") == "GeoLite2-Country.mmdb":
                download_url = asset.get("browser_download_url")
                logger.info(f"找到最新 GeoIP 数据库 URL: {download_url}")
                return download_url
        
        logger.error("未找到 GeoLite2-Country.mmdb 的下载 URL")
        return ""
    except Exception as e:
        logger.error(f"无法获取最新 GeoIP 数据库 URL: {e}")
        return ""

def download_geoip_database(dest_path: Path) -> bool:
    url = get_latest_geoip_url()
    if not url:
        logger.error("无法获取最新 GeoIP 数据库 URL")
        return False
    
    proxy_services = [
        ("Ghfast.top", "https://ghfast.top/"),
        ("Gitproxy.clickr", "https://gitproxy.click/"),
        ("Gh-proxy.ygxz", "https://gh-proxy.ygxz.in/"),
        ("Github.ur1.fun", "https://github.ur1.fun/")
    ]
    
    urls_to_try = [("无代理", url)]
    for proxy_name, proxy_prefix in proxy_services:
        if url.startswith("https://github.com/"):
            proxy_url = proxy_prefix + url
            urls_to_try.append((proxy_name, proxy_url))
    
    for proxy_name, download_url in urls_to_try:
        logger.info(f"下载 GeoIP 数据库（使用 {proxy_name}）: {download_url}")
        try:
            session = requests.Session()
            retry = Retry(total=5, backoff_factor=2, status_forcelist=[500, 502, 503, 504, 429])
            session.mount('https://', HTTPAdapter(max_retries=retry))
            response = session.get(download_url, timeout=60, stream=True, headers=HEADERS)
            response.raise_for_status()
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            with open(dest_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            logger.info(f"下载进度: {progress:.2f}%")
            logger.info(f"GeoIP 数据库下载完成: {dest_path}")
            if not dest_path.exists() or dest_path.stat().st_size < 100:
                logger.error(f"下载的 GeoIP 数据库无效")
                dest_path.unlink(missing_ok=True)
                return False
            return True
        except Exception as e:
            logger.warning(f"通过 {proxy_name} 下载 GeoIP 数据库失败: {e}")
            continue
    
    logger.error("所有代理服务均无法下载 GeoIP 数据库")
    return False

def download_geoip_database_maxmind(dest_path: Path) -> bool:
    if not MAXMIND_LICENSE_KEY:
        logger.warning("未设置 MAXMIND_LICENSE_KEY，无法从 MaxMind 下载 GeoIP 数据库。请在环境变量中设置 MAXMIND_LICENSE_KEY 或检查 GitHub 下载源。")
        return False
    url = GEOIP_DB_URL_BACKUP.format(MAXMIND_LICENSE_KEY)
    logger.info(f"从 MaxMind 下载 GeoIP 数据库: {url}")
    try:
        if dest_path.exists():
            logger.info(f"删除旧的 GeoIP 数据库文件: {dest_path}")
            dest_path.unlink(missing_ok=True)
            
        session = requests.Session()
        retry = Retry(total=5, backoff_factor=2, status_forcelist=[500, 502, 503, 504, 429])
        session.mount('https://', HTTPAdapter(max_retries=retry))
        response = session.get(url, timeout=60, stream=True, headers=HEADERS)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))
        downloaded = 0
        temp_tar = dest_path.with_suffix(".tar.gz")
        with open(temp_tar, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        progress = (downloaded / total_size) * 100
                        logger.info(f"下载进度: {progress:.2f}%")
        with tarfile.open(temp_tar, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith("GeoLite2-Country.mmdb"):
                    tar.extract(member, dest_path.parent)
                    extracted_path = dest_path.parent / member.name
                    extracted_path.rename(dest_path)
                    break
        temp_tar.unlink(missing_ok=True)
        if not dest_path.exists() or dest_path.stat().st_size < 100:
            logger.error(f"解压的 GeoIP 数据库无效")
            dest_path.unlink(missing_ok=True)
            return False
        return True
    except Exception as e:
        logger.error(f"从 MaxMind 下载 GeoIP 数据库失败: {e}")
        temp_tar.unlink(missing_ok=True)
        return False

def init_geoip_reader(offline: bool = False, update_geoip: bool = False):
    global geoip_reader
    
    def is_geoip_file_valid(file_path: Path) -> bool:
        if not file_path.exists():
            return False
        if file_path.stat().st_size < 1024 * 1024:
            logger.warning(f"GeoIP 数据库文件 {file_path} 过小，可能无效")
            return False
        mtime = file_path.stat().st_mtime
        current_time = time.time()
        age_days = (current_time - mtime) / (24 * 3600)
        if age_days > 30:
            logger.warning(f"GeoIP 数据库文件 {file_path} 已超过 30 天 ({age_days:.1f} 天)，建议使用 --update-geoip 更新")
        return True
    
    if offline:
        logger.info("离线模式启用，将使用本地 GeoIP 数据库")
        if not GEOIP_DB_PATH.exists():
            logger.error(f"离线模式下未找到本地 GeoIP 数据库: {GEOIP_DB_PATH}")
            sys.exit(1)
    else:
        if update_geoip:
            logger.info("检测到 --update-geoip 参数，强制更新 GeoIP 数据库")
            GEOIP_DB_PATH.unlink(missing_ok=True)
        if GEOIP_DB_PATH.exists() and is_geoip_file_valid(GEOIP_DB_PATH):
            logger.info(f"本地 GeoIP 数据库已存在且有效: {GEOIP_DB_PATH}，直接使用")
        else:
            if GEOIP_DB_PATH.exists():
                logger.info(f"本地 GeoIP 数据库无效: {GEOIP_DB_PATH}，将重新下载")
                GEOIP_DB_PATH.unlink(missing_ok=True)
            else:
                logger.info(f"本地 GeoIP 数据库不存在: {GEOIP_DB_PATH}，尝试下载最新文件")
            success = download_geoip_database(GEOIP_DB_PATH)
            if not success:
                logger.warning("主下载源失败，尝试 MaxMind")
                success = download_geoip_database_maxmind(GEOIP_DB_PATH)
                if not success:
                    logger.error("下载 GeoIP 数据库失败，且本地无可用数据库")
                    sys.exit(1)
    
    try:
        import geoip2.database
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            logger.info("GeoIP 数据库验证成功")
        geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        logger.info("GeoIP 数据库加载成功")
    except ImportError as e:
        logger.error(f"无法导入 geoip2.database: {e}. 请确保 geoip2==4.8.0 已安装，并检查虚拟环境")
        sys.exit(1)
    except Exception as e:
        logger.error(f"GeoIP 数据库加载失败: {e}, 类型: {type(e).__name__}")
        if offline:
            logger.error("离线模式下无法加载 GeoIP 数据库，退出")
            sys.exit(1)
        logger.info("本地数据库可能损坏，尝试重新下载 GeoIP 数据库")
        GEOIP_DB_PATH.unlink(missing_ok=True)
        success = download_geoip_database(GEOIP_DB_PATH)
        if not success:
            logger.warning("主下载源失败，尝试 MaxMind")
            success = download_geoip_database_maxmind(GEOIP_DB_PATH)
            if not success:
                logger.error("重新下载 GeoIP 数据库失败")
                sys.exit(1)
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            logger.info("GeoIP 数据库验证成功")
        geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        logger.info("GeoIP 数据库加载成功")

def close_geoip_reader():
    global geoip_reader
    if geoip_reader:
        try:
            geoip_reader.close()
            logger.info("GeoIP 数据库已关闭")
        except Exception as e:
            logger.warning(f"关闭 GeoIP 数据库失败: {e}")
        geoip_reader = None

atexit.register(close_geoip_reader)

def check_dependencies(offline: bool = False, update_geoip: bool = False):
    init_geoip_reader(offline=offline, update_geoip=update_geoip)

def load_country_cache() -> Dict[str, str]:
    if os.path.exists(COUNTRY_CACHE_FILE):
        try:
            with open(COUNTRY_CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"无法加载国家缓存: {e}")
    return {}

def save_country_cache(cache: Dict[str, str]):
    try:
        with open(COUNTRY_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.warning(f"无法保存国家缓存: {e}")

def is_temp_file_valid(temp_file: str) -> bool:
    if not os.path.exists(temp_file):
        return False
    mtime = os.path.getmtime(temp_file)
    current_time = time.time()
    if (current_time - mtime) > TEMP_FILE_CACHE_DURATION:
        logger.info(f"临时文件 {temp_file} 已过期")
        return False
    if os.path.getsize(temp_file) < 10:
        logger.warning(f"临时文件 {temp_file} 内容太小")
        return False
    return True

def detect_delimiter(lines: List[str]) -> str:
    sample_lines = lines[:5]
    delimiters = [',', ';', '\t', ' ', '|', '-']
    counts = {d: 0 for d in delimiters}
    for line in sample_lines:
        if not line.strip() or line.startswith('#'):
            continue
        for d in delimiters:
            if d in line:
                counts[d] += line.count(d)
    max_count = max(counts.values())
    if max_count > 0:
        delimiter = max(counts, key=counts.get)
        logger.info(f"检测到分隔符: '{delimiter}'")
        return delimiter
    logger.warning("无法检测分隔符，假定为逗号")
    return ','

def is_valid_ip(ip: str) -> bool:
    ipv4_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    ipv6_pattern = re.compile(r'^(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$')
    return bool(ipv4_pattern.match(ip) or ipv6_pattern.match(ip.strip('[]')))

def is_valid_port(port: str) -> bool:
    try:
        port_num = int(port)
        return 0 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def is_country_like(value: str) -> bool:
    if not value:
        return False
    value_upper = value.upper().strip()
    if re.match(r'^[A-Z]{2}$', value_upper) and value_upper in COUNTRY_LABELS:
        return True
    if value_upper in COUNTRY_ALIASES:
        return True
    return False

def standardize_country(value: str) -> str:
    if not value:
        return ''
    value_clean = re.sub(r'[^a-zA-Z\s]', '', value).strip().upper()
    
    if value_clean in COUNTRY_LABELS:
        return value_clean
    
    if value_clean in COUNTRY_ALIASES:
        return COUNTRY_ALIASES[value_clean]
    
    if value_clean in CITY_TO_COUNTRY:
        return CITY_TO_COUNTRY[value_clean]
    
    if value_clean in IATA_TO_COUNTRY:
        return IATA_TO_COUNTRY[value_clean]
    
    value_no_space = value_clean.replace(' ', '')
    for alias, code in COUNTRY_ALIASES.items():
        alias_clean = alias.replace(' ', '')
        if value_no_space == alias_clean:
            return code
    for city, code in CITY_TO_COUNTRY.items():
        city_clean = city.replace(' ', '')
        if value_no_space == city_clean:
            return code
    
    return ''

def find_country_column(lines: List[str], delimiter: str) -> Tuple[int, int, int]:
    country_col = -1
    ip_col, port_col = 0, 1
    sample_lines = [line for line in lines[:20] if line.strip() and not line.startswith('#')]
    if not sample_lines:
        return ip_col, port_col, country_col

    col_matches = defaultdict(int)
    total_rows = len(sample_lines)
    for line in sample_lines:
        fields = line.split(delimiter)
        for col, field in enumerate(fields):
            field = field.strip()
            standardized = standardize_country(field)
            if standardized:
                col_matches[col] += 1

    if col_matches:
        for col, count in col_matches.items():
            logger.info(f"列 {col + 1}: 匹配 {count} 行 (匹配率: {count / total_rows:.2%})")
        country_col = max(col_matches, key=col_matches.get)
        match_rate = col_matches[country_col] / total_rows
        if match_rate >= 0.3:
            logger.info(f"选择国家列: 第 {country_col + 1} 列 (匹配率: {match_rate:.2%})")
        else:
            country_col = -1
    else:
        logger.info("未找到任何匹配国家代码、城市或 IATA 代码的列")

    return ip_col, port_col, country_col

def fetch_and_save_to_temp_file(url: str) -> str:
    logger.info(f"下载 URL: {url} 到 {TEMP_FILE}")
    try:
        session = requests.Session()
        retry = Retry(total=5, backoff_factor=2, status_forcelist=[500, 502, 503, 504, 429])
        session.mount('https://', HTTPAdapter(max_retries=retry))
        response = session.get(url, timeout=60, headers=HEADERS, stream=True)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))
        downloaded = 0
        temp_content = []
        with open(TEMP_FILE, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    temp_content.append(chunk)
                    if total_size > 0:
                        progress = (downloaded / total_size) * 100
                        logger.info(f"下载进度: {progress:.2f}%")
        
        try:
            with open(TEMP_FILE, "rb") as f:
                raw_data = f.read()
            encoding = detect(raw_data).get("encoding", "utf-8")
            content = raw_data.decode(encoding)
            lines = content.strip().splitlines()
            if not lines:
                logger.error(f"下载的文件 {TEMP_FILE} 为空")
                return ''
            logger.info(f"下载文件编码: {encoding}")
            logger.info(f"下载文件前 5 行: {lines[:5]}")
            delimiter = detect_delimiter(lines)
            if not delimiter:
                logger.error(f"下载的文件 {TEMP_FILE} 无法检测分隔符")
                return ''
            header = lines[0].strip().split(delimiter)
            if len(header) < 2 or 'ip' not in header[0].lower():
                logger.warning(f"下载的文件 {TEMP_FILE} 表头可能无效: {header}")
            if len(lines) < 2:
                logger.error(f"下载的文件 {TEMP_FILE} 缺少数据行")
                return ''
        except Exception as e:
            logger.error(f"验证下载文件格式失败: {e}")
            return ''
        
        logger.info(f"已下载到 {TEMP_FILE}")
        return TEMP_FILE
    except Exception as e:
        logger.error(f"无法下载 URL: {e}")
        return ''

def extract_ip_ports_from_file(file_path: str) -> List[Tuple[str, int, str]]:
    if not os.path.exists(file_path):
        logger.error(f"文件 {file_path} 不存在")
        return []
    start_time = time.time()
    with open(file_path, "rb") as f:
        raw_data = f.read()
    encoding = detect(raw_data).get("encoding", "utf-8")
    logger.info(f"文件 {file_path} 编码: {encoding}")
    try:
        content = raw_data.decode(encoding)
    except UnicodeDecodeError as e:
        logger.error(f"无法解码文件 {file_path}: {e}")
        return []
    ip_ports = extract_ip_ports_from_content(content)
    logger.info(f"文件 {file_path} 解析完成 (耗时: {time.time() - start_time:.2f} 秒)")
    return ip_ports

def extract_ip_ports_from_content(content: str) -> List[Tuple[str, int, str]]:
    server_port_pairs = []
    invalid_lines = []
    content = content.replace('\r\n', '\n').replace('\r', '\n')
    lines = content.splitlines()
    if not lines:
        logger.error("内容为空")
        return []

    logger.info(f"数据源样本 (前 5 行): {lines[:5]}")

    try:
        data = json.loads(content)
        for item in data:
            ip = item.get('ip', '') or item.get('IP Address', '') or item.get('ip_address', '')
            port = item.get('port', '') or item.get('Port', '')
            country = standardize_country(
                item.get('country', '') or
                item.get('countryCode', '') or
                item.get('country_code', '') or
                item.get('location', '') or
                item.get('nation', '') or
                item.get('region', '') or
                item.get('geo', '') or
                item.get('area', '') or
                item.get('dc city', '') or
                item.get('dc_city', '') or
                item.get('city', '') or
                item.get('dc location', '') or
                item.get('dc_location', '')
            )
            if is_valid_ip(ip) and is_valid_port(str(port)):
                server_port_pairs.append((ip, int(port), country))
        logger.info(f"从 JSON 解析出 {len(server_port_pairs)} 个节点，其中 {sum(1 for _, _, c in server_port_pairs if c)} 个有国家信息")
        return list(dict.fromkeys(server_port_pairs))
    except json.JSONDecodeError as e:
        logger.info(f"JSON 解析失败: {e}")

    delimiter = detect_delimiter(lines)
    if not delimiter:
        logger.warning("无法检测分隔符，假定为逗号")
        delimiter = ','

    ip_col, port_col, country_col = 0, 1, -1
    lines_to_process = lines
    if lines and lines[0].strip() and not lines[0].startswith('#'):
        header = lines[0].strip().split(delimiter)
        logger.info(f"检测到表头: {header}")
        for idx, col in enumerate(header):
            col_lower = col.strip().lower()
            if col_lower in ['ip', 'address', 'ip_address', 'ip地址', 'ip address']:
                ip_col = idx
            elif col_lower in ['port', '端口', 'port_number', '端口号']:
                port_col = idx
            elif col_lower in ['country', '国家', 'country_code', 'countrycode', '国际代码', 'nation', 'location', 'region', 'geo', 'area', 'Country', 'cc', 'iso_code', 'country_name', 'dc city', 'dc_city', 'city', 'dc location', 'dc_location']:
                country_col = idx
        if country_col != -1:
            logger.info(f"检测到国家列: 第 {country_col + 1} 列 (字段名: {header[country_col]})")
            lines_to_process = lines[1:]
        else:
            logger.info("表头中不包含国家相关列，尝试逐行逐列搜索")
            ip_col, port_col, country_col = find_country_column(lines, delimiter)
            if country_col >= 0:
                logger.info(f"通过逐行搜索确定国家列: 第 {country_col + 1} 列")
            else:
                logger.info(f"无法确定国家列，设为 -1")

    ip_port_pattern = re.compile(
        r'(((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|\[(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\]|(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}))[ :,\t](\d{1,5})'
    )

    for i, line in enumerate(lines_to_process):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = ip_port_pattern.match(line)
        if match:
            server = match.group(1).strip('[]')
            port = match.group(4)
            country = ''
            if delimiter:
                fields = line.split(delimiter)
                if country_col != -1 and country_col < len(fields):
                    country = standardize_country(fields[country_col].strip())
                if not country:
                    for col, field in enumerate(fields):
                        field = field.strip()
                        potential_country = standardize_country(field)
                        if potential_country:
                            country = potential_country
                            break
            if is_valid_port(port):
                server_port_pairs.append((server, int(port), country))
            else:
                invalid_lines.append(f"第 {i} 行: {line} (端口无效)")
            continue
        if delimiter:
            fields = line.split(delimiter)
            if len(fields) < max(ip_col, port_col, country_col) + 1:
                invalid_lines.append(f"第 {i} 行: {line} (字段太少)")
                continue
            server = fields[ip_col].strip('[]')
            port_str = fields[port_col].strip()
            country = ''
            if country_col != -1 and country_col < len(fields):
                country = standardize_country(fields[country_col].strip())
            if not country:
                for col, field in enumerate(fields):
                    field = field.strip()
                    potential_country = standardize_country(field)
                    if potential_country:
                        country = potential_country
                        break
            if is_valid_ip(server) and is_valid_port(port_str):
                server_port_pairs.append((server, int(port_str), country))
            else:
                invalid_lines.append(f"第 {i} 行: {line} (IP 或端口无效)")
        else:
            invalid_lines.append(f"第 {i} 行: {line} (格式无效)")

    if invalid_lines:
        logger.info(f"发现 {len(invalid_lines)} 个无效条目")
    logger.info(f"解析出 {len(server_port_pairs)} 个节点，其中 {sum(1 for _, _, c in server_port_pairs if c)} 个有国家信息")
    unique_server_port_pairs = list(dict.fromkeys(server_port_pairs))
    logger.info(f"去重后: {len(unique_server_port_pairs)} 个节点")
    return unique_server_port_pairs

def get_country_from_ip(ip: str, cache: Dict[str, str]) -> str:
    if ip in cache:
        return cache[ip]
    try:
        response = geoip_reader.country(ip)
        country_code = response.country.iso_code or ''
        if country_code:
            cache[ip] = country_code
            return country_code
        return ''
    except Exception:
        return ''

def get_countries_from_ips(ips: List[str], cache: Dict[str, str]) -> List[str]:
    uncached_ips = [ip for ip in ips if ip not in cache]
    if uncached_ips:
        logger.info(f"批量查询 {len(uncached_ips)} 个 IP 的国家信息")
        for ip in uncached_ips:
            try:
                response = geoip_reader.country(ip)
                cache[ip] = response.country.iso_code or ''
            except Exception:
                cache[ip] = ''
    return [cache[ip] for ip in ips]

def write_ip_list(ip_ports: List[Tuple[str, int, str]], is_github_actions: bool) -> str:
    if not ip_ports:
        logger.error(f"没有有效的节点来生成 {IP_LIST_FILE}")
        return None

    start_time = time.time()
    country_cache = load_country_cache()
    filtered_ip_ports = set()
    country_counts = defaultdict(int)
    filtered_counts = defaultdict(int)
    logger.info(f"开始处理 {len(ip_ports)} 个节点...")

    from_source = sum(1 for _, _, country in ip_ports if country and country in COUNTRY_LABELS)
    logger.info(f"数据源为 {from_source} 个节点提供了有效国家信息（包括城市映射）")

    # 收集需要查询数据库的 IP（国家信息为空或无效）
    ips_to_query = [ip for ip, _, country in ip_ports if not country or country not in COUNTRY_LABELS]
    supplemented = 0
    if ips_to_query:
        logger.info(f"批量查询 {len(ips_to_query)} 个 IP 的国家信息（缺失或无效）")
        countries = get_countries_from_ips(ips_to_query, country_cache)
        ip_country_map = dict(zip(ips_to_query, countries))
        supplemented = sum(1 for country in countries if country)
    else:
        ip_country_map = {}

    for ip, port, country in ip_ports:
        final_country = country
        source = "数据源" if country and country in COUNTRY_LABELS else "待查询"
        
        if not country or country not in COUNTRY_LABELS:
            final_country = ip_country_map.get(ip, '')
            if final_country:
                source = "GeoIP 数据库"
        
        if not DESIRED_COUNTRIES:
            filtered_ip_ports.add((ip, port))
            if final_country:
                country_counts[final_country] += 1
        elif final_country and final_country in DESIRED_COUNTRIES:
            filtered_ip_ports.add((ip, port))
            country_counts[final_country] += 1
        else:
            filtered_counts[final_country or 'UNKNOWN'] += 1

    total_retained = len(filtered_ip_ports)
    total_filtered = sum(filtered_counts.values())
    logger.info(f"过滤结果: 保留 {total_retained} 个节点，过滤掉 {total_filtered} 个节点")
    logger.info(f"通过 GeoIP 数据库补充国家信息: {supplemented} 个节点")
    logger.info(f"保留的国家分布: {dict(country_counts)}")
    logger.info(f"过滤掉的国家分布: {dict(filtered_counts)}")

    if not filtered_ip_ports:
        logger.error(f"没有有效的节点来生成 {IP_LIST_FILE}")
        return None

    with open(IP_LIST_FILE, "w", encoding="utf-8") as f:
        for ip, port in filtered_ip_ports:
            f.write(f"{ip} {port}\n")
    logger.info(f"已生成 {IP_LIST_FILE}")

    logger.info(f"生成 {IP_LIST_FILE}，包含 {len(filtered_ip_ports)} 个节点 (耗时: {time.time() - start_time:.2f} 秒)")
    save_country_cache(country_cache)
    return IP_LIST_FILE

def run_speed_test() -> str:
    if not SPEEDTEST_SCRIPT:
        logger.info("未找到测速脚本")
        return None

    if not os.path.exists(IP_LIST_FILE):
        logger.error(f"{IP_LIST_FILE} 不存在，请确保 write_ip_list 已正确生成文件")
        return None

    start_time = time.time()
    try:
        with open(IP_LIST_FILE, "r", encoding="utf-8") as f:
            ip_lines = [line.strip() for line in f if line.strip()]
        total_nodes = len(ip_lines)
        logger.info(f"{IP_LIST_FILE} 包含 {total_nodes} 个节点")
    except Exception as e:
        logger.error(f"无法读取 {IP_LIST_FILE}: {e}")
        return None

    # 解析 speedlimit 参数
    speed_limit = parse_speedlimit_from_script(SPEEDTEST_SCRIPT)
    
    logger.info("开始测速")
    system = platform.system().lower()
    is_termux_env = is_termux()
    try:
        if system == "windows":
            command = [SPEEDTEST_SCRIPT]
        elif is_termux_env:
            command = ["bash", SPEEDTEST_SCRIPT]  # Termux 使用 bash 执行 iptest.sh
        else:
            shell = shutil.which("bash") or shutil.which("sh") or "sh"
            command = ["stdbuf", "-oL", shell, SPEEDTEST_SCRIPT]
        
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            encoding='utf-8',
            errors='replace'
        )
        stdout_lines, stderr_lines = [], []
        def read_stream(stream, lines, is_stderr=False):
            while True:
                line = stream.readline()
                if not line:
                    break
                lines.append(line)
                logger.info(line.strip())  # 直接记录原始输出，无前缀
                sys.stdout.flush()
        stdout_thread = threading.Thread(target=read_stream, args=(process.stdout, stdout_lines))
        stderr_thread = threading.Thread(target=read_stream, args=(process.stderr, stderr_lines, True))
        stdout_thread.start()
        stderr_thread.start()

        return_code = process.wait()
        stdout_thread.join()
        stderr_thread.join()
        stdout = ''.join(stdout_lines)
        stderr = ''.join(stderr_lines)
        if stdout:
            logger.info(f"iptest 标准输出: {stdout}")
        if stderr:
            logger.warning(f"iptest 错误输出: {stderr}")

        logger.info(f"测速完成，耗时: {time.time() - start_time:.2f} 秒")
        if return_code != 0:
            logger.error(f"测速失败，返回码: {return_code}")
            return None
        if not os.path.exists(FINAL_CSV) or os.path.getsize(FINAL_CSV) < 10:
            logger.error(f"{FINAL_CSV} 未生成或内容无效")
            return None
        
        # 统计 ip.csv 的速度分布
        try:
            with open(FINAL_CSV, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                speeds = []
                speed_col = 9  # 第 10 列是“下载速度MB/s”
                for row in reader:
                    if len(row) > speed_col and row[speed_col].strip():
                        try:
                            speeds.append(float(row[speed_col]))
                        except ValueError:
                            continue
                if speeds:
                    logger.info(f"ip.csv 速度统计: 平均={sum(speeds)/len(speeds):.2f} MB/s, "
                               f"最小={min(speeds):.2f} MB/s, 最大={max(speeds):.2f} MB/s, "
                               f"节点数={len(speeds)}")
        except Exception as e:
            logger.warning(f"无法统计 ip.csv 速度分布: {e}")

        # 在 Termux 环境中，强制过滤低速节点
        if is_termux_env:
            logger.info(f"检测到 Termux 环境，应用速度下限过滤 (speedlimit={speed_limit} MB/s)")
            filter_ip_csv_by_speed(FINAL_CSV, speed_limit=speed_limit)  # 使用动态 speed_limit

        with open(FINAL_CSV, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
            node_count = len(lines) - 1 if lines else 0
            logger.info(f"{FINAL_CSV} 包含 {node_count} 个节点")
        return FINAL_CSV
    except Exception as e:
        logger.error(f"测速异常: {e}")
        return None

def filter_speed_and_deduplicate(csv_file: str, is_github_actions: bool):
    start_time = time.time()
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在")
        return
    seen = set()
    final_rows = []
    try:
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header:
                logger.error(f"{csv_file} 没有有效的表头")
                return
            for row in reader:
                if len(row) < 2 or not row[0].strip():
                    continue
                key = (row[0], row[1])
                if key not in seen:
                    seen.add(key)
                    final_rows.append(row)
    except Exception as e:
        logger.error(f"无法处理 {csv_file}: {e}")
        return
    if not final_rows:
        logger.info(f"没有有效的节点")
        os.remove(csv_file)
        return
    try:
        final_rows.sort(key=lambda x: float(x[9]) if len(x) > 9 and x[9] and x[9].replace('.', '', 1).isdigit() else 0.0, reverse=True)
    except Exception as e:
        logger.warning(f"排序失败: {e}")

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(final_rows)
    logger.info(f"已生成 {csv_file}")

    logger.info(f"{csv_file} 处理完成，{len(final_rows)} 个数据节点 (耗时: {time.time() - start_time:.2f} 秒)")
    return len(final_rows)

def generate_ips_file(csv_file: str, is_github_actions: bool):
    start_time = time.time()
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在")
        return
    country_cache = load_country_cache()
    final_nodes = []
    try:
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)
            for row in reader:
                if len(row) < 2:
                    continue
                ip, port = row[0], row[1]
                if not is_valid_ip(ip) or not is_valid_port(port):
                    continue
                country = country_cache.get(ip, '')
                if not country:
                    country = get_country_from_ip(ip, country_cache)
                if DESIRED_COUNTRIES and country and country in DESIRED_COUNTRIES:
                    final_nodes.append((ip, int(port), country))
    except Exception as e:
        logger.error(f"无法读取 {csv_file}: {e}")
        return
    if not final_nodes:
        logger.info(f"没有符合条件的节点（DESIRED_COUNTRIES: {DESIRED_COUNTRIES}）")
        return
    country_count = defaultdict(int)
    labeled_nodes = []
    for ip, port, country in sorted(final_nodes, key=lambda x: x[2] or 'ZZ'):
        country_count[country] += 1
        emoji, name = COUNTRY_LABELS.get(country, ('🌐', '未知'))
        label = f"{emoji} {name}-{country_count[country]}"
        labeled_nodes.append((ip, port, label))

    with open(IPS_FILE, "w", encoding="utf-8-sig") as f:
        for ip, port, label in labeled_nodes:
            f.write(f"{ip}:{port}#{label}\n")
    logger.info(f"已生成 {IPS_FILE}")

    logger.info(f"生成 {IPS_FILE}，{len(labeled_nodes)} 个数据节点 (耗时: {time.time() - start_time:.2f} 秒)")
    logger.info(f"国家分布: {dict(country_count)}")
    save_country_cache(country_cache)
    return len(labeled_nodes)

def validate_username(username: str) -> bool:
    """验证 Git 用户名格式"""
    if not username:
        logger.warning("用户名不能为空")
        return False
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$', username):
        logger.warning("用户名只能包含字母、数字、下划线或连字符，且必须以字母或数字开头")
        return False
    return True

def validate_repo_name(repo_name: str) -> bool:
    """验证 GitHub 仓库名称格式"""
    if not repo_name:
        logger.warning("仓库名称不能为空")
        return False
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$', repo_name):
        logger.warning("仓库名称只能包含字母、数字、下划线或连字符，且必须以字母或数字开头")
        return False
    if '/' in repo_name:
        logger.warning("仓库名称不能包含斜杠")
        return False
    return True

def validate_email(email: str) -> bool:
    """验证邮箱格式"""
    if not email:
        logger.warning("邮箱不能为空")
        return False
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        logger.warning("请输入有效的邮箱地址")
        return False
    return True

def validate_remote_url(remote_url: str) -> bool:
    """验证远程仓库地址格式"""
    if not re.match(r'^git@github\.com:[a-zA-Z0-9][a-zA-Z0-9_-]*/[a-zA-Z0-9][a-zA-Z0-9_-]*\.git$', remote_url):
        logger.warning(f"远程仓库地址格式无效: {remote_url}")
        return False
    return True

def verify_remote_url(remote_url: str) -> bool:
    """验证远程仓库是否可访问"""
    try:
        subprocess.run(
            ["git", "ls-remote", remote_url],
            check=True,
            capture_output=True,
            text=True
        )
        logger.info(f"远程仓库 {remote_url} 可访问")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"无法访问远程仓库 {remote_url}: {e.stderr}")
        return False

def verify_ssh_connection(ssh_key_path: str) -> bool:
    """验证与 GitHub 的 SSH 连接是否有效"""
    logger.info(f"开始验证 SSH 连接到 GitHub，使用密钥: {ssh_key_path}")
    if not os.path.exists(ssh_key_path):
        logger.error(f"SSH 密钥文件 {ssh_key_path} 不存在")
        logger.info("请生成 SSH 密钥：")
        logger.info("1. 运行 'ssh-keygen -t ed25519 -C \"your_email@example.com\"'")
        logger.info("2. 将公钥 (~/.ssh/id_ed25519.pub) 添加到 GitHub: https://github.com/settings/keys")
        return False

    if platform.system().lower() != "windows":
        try:
            file_stat = os.stat(ssh_key_path)
            if file_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                logger.warning(f"SSH 密钥文件 {ssh_key_path} 权限过于宽松，建议设置为 600")
                logger.info("修复权限：运行 'chmod 600 {ssh_key_path}'")
        except OSError as e:
            logger.warning(f"无法检查 SSH 密钥文件权限: {e}")

    try:
        result = subprocess.run(
            ["ssh", "-T", "-o", "StrictHostKeyChecking=no", "-i", ssh_key_path, "git@github.com"],
            capture_output=True,
            text=True,
            check=False
        )
        output = (result.stdout + result.stderr).lower()
        if "successfully authenticated" in output:
            logger.info("SSH 连接到 GitHub 验证成功")
            return True
        else:
            logger.warning(f"SSH 连接验证失败，输出: {output.strip()}")
            logger.info("请确保以下步骤已完成：")
            logger.info("1. SSH 私钥 ({ssh_key_path}) 存在且有效")
            logger.info("2. 对应的公钥已添加到 GitHub: https://github.com/settings/keys")
            logger.info("3. 检查 SSH 代理（如果使用）：运行 'ssh-add {ssh_key_path}'")
            return False
    except subprocess.CalledProcessError as e:
        logger.error(f"无法验证 SSH 连接: {e.stderr}")
        logger.info("可能的原因：")
        logger.info("- SSH 客户端未安装或配置错误")
        logger.info("- 网络连接问题")
        logger.info("- SSH 密钥未正确添加到 ssh-agent（尝试 'ssh-add {ssh_key_path}'）")
        return False
    except FileNotFoundError:
        logger.error("SSH 客户端未安装，请安装 OpenSSH")
        logger.info("Ubuntu: sudo apt-get install openssh-client")
        logger.info("Windows: 确保 Git Bash 或 OpenSSH 已安装")
        return False
    except Exception as e:
        logger.error(f"验证 SSH 连接时发生意外错误: {e}")
        return False

def load_config() -> Dict[str, str]:
    """加载并验证 .gitconfig.json 文件"""
    if not os.path.exists(CONFIG_FILE):
        logger.info(f"未找到缓存文件 {CONFIG_FILE}，将重新提示输入")
        return {}
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
            required_fields = ['user_name', 'user_email', 'repo_name', 'ssh_key_path', 'git_user_name']
            missing_fields = [field for field in required_fields if field not in config]
            if missing_fields:
                logger.warning(f"缓存文件缺少字段: {missing_fields}")
                return {}

            if not validate_username(config['user_name']):
                logger.warning(f"缓存文件中 user_name 无效: {config['user_name']}")
                return {}
            if not validate_email(config['user_email']):
                logger.warning(f"缓存文件中 user_email 无效: {config['user_email']}")
                return {}
            if not validate_username(config['git_user_name']):
                logger.warning(f"缓存文件中 git_user_name 无效: {config['git_user_name']}")
                return {}
            if not validate_repo_name(config['repo_name']):
                logger.warning(f"缓存文件中 repo_name 无效: {config['repo_name']}")
                return {}
            if not os.path.exists(config['ssh_key_path']):
                logger.warning(f"缓存文件中 ssh_key_path 不存在: {config['ssh_key_path']}")
                return {}
            if not os.access(config['ssh_key_path'], os.R_OK):
                logger.warning(f"缓存文件中 ssh_key_path 不可读: {config['ssh_key_path']}")
                return {}

            remote_url = f"git@github.com:{config['git_user_name']}/{config['repo_name']}.git"
            if not validate_remote_url(remote_url):
                logger.warning(f"构造的远程地址无效: {remote_url}")
                return {}
            if not verify_remote_url(remote_url):
                logger.warning(f"远程仓库不可访问: {remote_url}")
                return {}
            if not verify_ssh_connection(config['ssh_key_path']):
                logger.warning("SSH 连接验证失败")
                return {}

            logger.info("已从缓存加载 Git 配置")
            return config
    except json.JSONDecodeError as e:
        logger.error(f"解析 {CONFIG_FILE} 失败，JSON 格式错误: {e}")
        return {}
    except PermissionError as e:
        logger.error(f"无法读取 {CONFIG_FILE}，权限错误: {e}")
        return {}
    except Exception as e:
        logger.error(f"加载 {CONFIG_FILE} 时发生未知错误: {e}")
        return {}

def save_config(config: Dict[str, str]):
    """保存 Git 配置到 .gitconfig.json"""
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
        os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)
        logger.info(f"Git 配置已保存到 {CONFIG_FILE}")
    except Exception as e:
        logger.error(f"无法保存缓存文件 {CONFIG_FILE}: {e}")
        sys.exit(1)

def prompt_git_config() -> Dict[str, str]:
    """提示用户输入 Git 配置"""
    logger.info("需要配置 Git 信息")
    user_name = input("请输入 Git 用户名: ").strip()
    while not validate_username(user_name):
        user_name = input("请输入 Git 用户名: ").strip()

    user_email = input("请输入 Git 邮箱: ").strip()
    while not validate_email(user_email):
        user_email = input("请输入 Git 邮箱: ").strip()

    git_user_name = input("请输入 GitHub 用户名: ").strip()
    while not validate_username(git_user_name):
        git_user_name = input("请输入 GitHub 用户名: ").strip()

    repo_name = input("请输入 GitHub 仓库名称: ").strip()
    while not validate_repo_name(repo_name):
        repo_name = input("请输入 GitHub 仓库名称: ").strip()

    remote_url = f"git@github.com:{git_user_name}/{repo_name}.git"
    if not validate_remote_url(remote_url):
        logger.error(f"构造的远程仓库地址无效: {remote_url}")
        sys.exit(1)
    if not verify_remote_url(remote_url):
        logger.error(f"远程仓库不可访问: {remote_url}")
        logger.info("请确保：1. 仓库存在；2. GitHub 用户名正确；3. 你有访问权限")
        sys.exit(1)

    ssh_key_path = SSH_KEY_PATH
    if not os.path.exists(ssh_key_path) or not verify_ssh_connection(ssh_key_path):
        logger.info("SSH 密钥无效或不存在，请生成新密钥")
        ssh_key_path = generate_ssh_key()

    return {
        "user_name": user_name,
        "user_email": user_email,
        "repo_name": repo_name,
        "ssh_key_path": ssh_key_path,
        "git_user_name": git_user_name
    }

def generate_ssh_key() -> str:
    """生成 SSH 密钥并验证连接"""
    ssh_dir = os.path.expanduser("~/.ssh")
    private_key_path = SSH_KEY_PATH
    public_key_path = f"{private_key_path}.pub"

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        logger.info(f"SSH 密钥已存在: {private_key_path}")
        if verify_ssh_connection(private_key_path):
            return private_key_path
        logger.info("现有 SSH 密钥无法连接到 GitHub，将生成新密钥")

    try:
        os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
        logger.info(f"生成新的 SSH 密钥: {private_key_path}")
        email = input("请输入用于 SSH 密钥的邮箱（用于注释）: ").strip()
        while not validate_email(email):
            email = input("请输入有效的邮箱: ").strip()

        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-C", email, "-f", private_key_path, "-N", ""],
            check=True,
            capture_output=True,
            text=True
        )
        logger.info(f"SSH 密钥生成成功: {private_key_path}")

        if platform.system().lower() != "windows":
            os.chmod(private_key_path, 0o600)
            os.chmod(public_key_path, 0o644)
            logger.info(f"已设置密钥文件权限: {private_key_path} (600), {public_key_path} (644)")

        with open(public_key_path, "r", encoding="utf-8") as f:
            public_key = f.read().strip()
        logger.info("SSH 公钥内容如下，请添加到 GitHub: https://github.com/settings/keys")
        logger.info(public_key)
        input("请将以上公钥添加到 GitHub 后按 Enter 继续...")

        if not verify_ssh_connection(private_key_path):
            logger.error("新生成的 SSH 密钥仍无法连接到 GitHub")
            sys.exit(1)

        logger.info("SSH 密钥验证成功")
        return private_key_path
    except subprocess.CalledProcessError as e:
        logger.error(f"生成 SSH 密钥失败: {e.stderr}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"生成 SSH 密钥时发生未知错误: {e}")
        sys.exit(1)

def setup_git_config(is_github_actions: bool = False):
    """设置 Git 配置"""
    if is_github_actions:
        logger.info("检测到 GitHub Actions 环境，跳过交互式 Git 配置")
        try:
            subprocess.run(["git", "config", "--global", "user.name", "github-actions[bot]"], check=True)
            subprocess.run(["git", "config", "--global", "user.email", "github-actions[bot]@users.noreply.github.com"], check=True)
            logger.info("已设置 GitHub Actions 默认 Git 配置")
            return
        except subprocess.CalledProcessError as e:
            logger.error(f"设置 GitHub Actions Git 配置失败: {e}")
            sys.exit(1)

    # 检查是否已有全局 Git 配置
    try:
        current_user = subprocess.run(["git", "config", "--global", "user.name"], capture_output=True, text=True, check=False).stdout.strip()
        current_email = subprocess.run(["git", "config", "--global", "user.email"], capture_output=True, text=True, check=False).stdout.strip()
        if current_user and current_email:
            logger.info(f"检测到现有 Git 全局配置: user.name={current_user}, user.email={current_email}")
            config = load_config()
            if config:
                logger.info("使用缓存的 Git 配置")
                return
            logger.info("未找到有效的缓存配置，将提示输入")
        else:
            logger.info("未检测到 Git 全局配置，将提示输入")
    except subprocess.CalledProcessError as e:
        logger.warning(f"检查 Git 全局配置失败: {e}")

    # 加载或提示配置
    config = load_config()
    if not config:
        config = prompt_git_config()
        save_config(config)

    # 设置 Git 全局配置
    try:
        subprocess.run(["git", "config", "--global", "user.name", config['user_name']], check=True)
        subprocess.run(["git", "config", "--global", "user.email", config['user_email']], check=True)
        logger.info(f"已设置 Git 全局配置: user.name={config['user_name']}, user.email={config['user_email']}")
    except subprocess.CalledProcessError as e:
        logger.error(f"设置 Git 全局配置失败: {e}")
        sys.exit(1)

def commit_and_push(is_github_actions: bool = False):
    """提交并推送更改到 GitHub"""
    config = load_config()
    if not config:
        logger.error(f"未找到有效的 Git 配置，请确保 {CONFIG_FILE} 存在且有效")
        sys.exit(1)

    remote_url = f"git@github.com:{config['git_user_name']}/{config['repo_name']}.git"
    if not validate_remote_url(remote_url):
        logger.error(f"远程仓库地址无效: {remote_url}")
        sys.exit(1)
    if not verify_remote_url(remote_url):
        logger.error(f"远程仓库 {remote_url} 不可访问")
        sys.exit(1)
    if not verify_ssh_connection(config['ssh_key_path']):
        logger.error("SSH 连接验证失败")
        sys.exit(1)

    try:
        # 初始化 Git 仓库
        if not os.path.exists(".git"):
            subprocess.run(["git", "init"], check=True)
            logger.info("已初始化 Git 仓库")
        else:
            logger.info("Git 仓库已存在")

        # 检查工作区状态
        status_result = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            text=True,
            check=True
        )
        if "UU" in status_result.stdout:
            logger.warning("检测到未解决的合并冲突，请手动解决：")
            logger.warning("1. 运行 'git status' 查看冲突文件")
            logger.warning("2. 解决冲突后运行 'git add <file>'")
            logger.warning("3. 提交 'git commit'")
            return

        # 设置远程仓库
        try:
            subprocess.run(["git", "remote", "set-url", "origin", remote_url], check=True)
        except subprocess.CalledProcessError:
            subprocess.run(["git", "remote", "add", "origin", remote_url], check=True)
            logger.info(f"已设置远程仓库: {remote_url}")

        # 添加文件
        files_to_commit = [IPS_FILE, FINAL_CSV]
        for file in files_to_commit:
            if os.path.exists(file):
                subprocess.run(["git", "add", file], check=True)
                logger.info(f"已添加文件到 Git: {file}")
            else:
                logger.warning(f"文件 {file} 不存在，跳过添加")

        # 检查是否有更改
        status_result = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True
        )
        if not status_result.stdout.strip():
            logger.info("没有更改需要提交")
            return

        # 提交更改
        commit_message = "Update IP lists and test results" if is_github_actions else "Update IP lists and test results via script"
        subprocess.run(["git", "commit", "-m", commit_message], check=True)
        logger.info(f"已提交更改: {commit_message}")

        # 推送
        branch = "main" if is_github_actions else "main"
        subprocess.run(["git", "push", "origin", branch], check=True)
        logger.info(f"已推送更改到远程仓库: {remote_url} (分支: {branch})")
    except subprocess.CalledProcessError as e:
        logger.error(f"Git 操作失败: {e.stderr or str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"提交和推送过程中发生未知错误: {e}")
        sys.exit(1)

def filter_speed_and_deduplicate(csv_file: str, is_github_actions: bool):
    start_time = time.time()
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在")
        return
    seen = set()
    final_rows = []
    try:
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header:
                logger.error(f"{csv_file} 没有有效的表头")
                return
            for row in reader:
                if len(row) < 2 or not row[0].strip():
                    continue
                key = (row[0], row[1])
                if key not in seen:
                    seen.add(key)
                    final_rows.append(row)
    except Exception as e:
        logger.error(f"无法处理 {csv_file}: {e}")
        return
    if not final_rows:
        logger.info(f"没有有效的节点")
        os.remove(csv_file)
        return
    try:
        final_rows.sort(key=lambda x: float(x[9]) if len(x) > 9 and x[9] and x[9].replace('.', '', 1).isdigit() else 0.0, reverse=True)
    except Exception as e:
        logger.warning(f"排序失败: {e}")

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(final_rows)
    logger.info(f"已生成 {csv_file}")

    logger.info(f"{csv_file} 处理完成，{len(final_rows)} 个数据节点 (耗时: {time.time() - start_time:.2f} 秒)")
    return len(final_rows)

def generate_ips_file(csv_file: str, is_github_actions: bool):
    start_time = time.time()
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在")
        return
    country_cache = load_country_cache()
    final_nodes = []
    try:
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)
            for row in reader:
                if len(row) < 2:
                    continue
                ip, port = row[0], row[1]
                if not is_valid_ip(ip) or not is_valid_port(port):
                    continue
                country = country_cache.get(ip, '')
                if not country:
                    country = get_country_from_ip(ip, country_cache)
                if DESIRED_COUNTRIES and country and country in DESIRED_COUNTRIES:
                    final_nodes.append((ip, int(port), country))
    except Exception as e:
        logger.error(f"无法读取 {csv_file}: {e}")
        return
    if not final_nodes:
        logger.info(f"没有符合条件的节点（DESIRED_COUNTRIES: {DESIRED_COUNTRIES}）")
        return
    country_count = defaultdict(int)
    labeled_nodes = []
    for ip, port, country in sorted(final_nodes, key=lambda x: x[2] or 'ZZ'):
        country_count[country] += 1
        emoji, name = COUNTRY_LABELS.get(country, ('🌐', '未知'))
        label = f"{emoji} {name}-{country_count[country]}"
        labeled_nodes.append((ip, port, label))

    with open(IPS_FILE, "w", encoding="utf-8-sig") as f:
        for ip, port, label in labeled_nodes:
            f.write(f"{ip}:{port}#{label}\n")
    logger.info(f"已生成 {IPS_FILE}")

    logger.info(f"生成 {IPS_FILE}，{len(labeled_nodes)} 个数据节点 (耗时: {time.time() - start_time:.2f} 秒)")
    logger.info(f"国家分布: {dict(country_count)}")
    save_country_cache(country_cache)
    return len(labeled_nodes)

def main():
    parser = argparse.ArgumentParser(description="IP 测试和筛选脚本")
    parser.add_argument("--input-file", type=str, default=INPUT_FILE, help=f"输入 CSV 文件路径 (默认: {INPUT_FILE})")
    parser.add_argument("--url", type=str, default=INPUT_URL, help=f"输入 URL (默认: {INPUT_URL})")
    parser.add_argument("--offline", action="store_true", help="离线模式，不下载 GeoIP 数据库")
    parser.add_argument("--update-geoip", action="store_true", help="强制更新 GeoIP 数据库")
    args = parser.parse_args()

    is_github_actions = os.getenv("GITHUB_ACTIONS") == "true"
    logger.info(f"运行环境: {'GitHub Actions' if is_github_actions else '本地'}, 离线模式: {args.offline}, 更新 GeoIP: {args.update_geoip}")

    # 设置虚拟环境并安装依赖
    setup_and_activate_venv()

    # 检查依赖
    check_dependencies(offline=args.offline, update_geoip=args.update_geoip)

    # 设置 Git 配置
    setup_git_config(is_github_actions=is_github_actions)

    # 处理输入（优先读取本地 input.csv，若不存在或无效则从 URL 获取）
    ip_ports = []
    if os.path.exists(args.input_file):
        ip_ports = extract_ip_ports_from_file(args.input_file)
        if ip_ports:
            logger.info(f"从本地文件 {args.input_file} 提取到 {len(ip_ports)} 个节点")
        else:
            logger.warning(f"本地文件 {args.input_file} 无有效节点，尝试从 URL 获取")
    else:
        logger.info(f"本地文件 {args.input_file} 不存在，尝试从 URL 获取")

    if not ip_ports and args.url and not args.offline:
        temp_file = fetch_and_save_to_temp_file(args.url)
        if temp_file and is_temp_file_valid(temp_file):
            ip_ports = extract_ip_ports_from_file(temp_file)
            logger.info(f"从 URL {args.url} 提取到 {len(ip_ports)} 个节点")
        else:
            logger.error(f"无法从 URL {args.url} 获取有效节点")
            sys.exit(1)

    if not ip_ports:
        logger.error("没有有效的 IP 和端口数据")
        sys.exit(1)

    # 写入 IP 列表
    ip_list_file = write_ip_list(ip_ports, is_github_actions=is_github_actions)
    if not ip_list_file:
        logger.error("无法生成 IP 列表")
        sys.exit(1)

    # 运行测速
    csv_file = run_speed_test()
    if not csv_file:
        logger.error("测速失败")
        sys.exit(1)

    # 过滤和去重
    node_count = filter_speed_and_deduplicate(csv_file, is_github_actions=is_github_actions)
    if not node_count:
        logger.error("没有有效的节点")
        sys.exit(1)

    # 生成最终 IPs 文件
    final_node_count = generate_ips_file(csv_file, is_github_actions=is_github_actions)
    if not final_node_count:
        logger.error("无法生成最终 IPs 文件")
        sys.exit(1)

    # 提交并推送
    commit_and_push(is_github_actions=is_github_actions)

    logger.info("脚本执行完成")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("用户中断脚本执行")
        sys.exit(1)
    except Exception as e:
        logger.error(f"脚本执行失败: {e}")
        sys.exit(1)
