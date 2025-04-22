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
        level=logging.DEBUG,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(LOG_PATH, encoding="utf-8", mode="w"),
            logging.StreamHandler(sys.stdout)
        ],
        force=True
    )
    logger = logging.getLogger(__name__)
    logger.debug(f"日志初始化完成，日志文件: {LOG_PATH}")
except Exception as e:
    print(f"无法创建日志文件 {LOG_PATH}: {e}")
    sys.exit(1)

# 禁用 stdout 缓冲，确保日志实时输出
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
DESIRED_COUNTRIES = ['TW', 'JP', 'HK', 'SG', 'KR', 'IN', 'KP', 'VN', 'TH', 'MM']
REQUIRED_PACKAGES = ['requests', 'charset-normalizer', 'geoip2==4.8.0', 'maxminddb>=2.0.0']
CONFIG_FILE = ".gitconfig.json"
SSH_KEY_PATH = os.path.expanduser("~/.ssh/id_ed25519")
VENV_DIR = ".venv"

COUNTRY_LABELS = {
    'JP': ('🇯🇵', '日本'), 'KR': ('🇰🇷', '韩国'), 'SG': ('🇸🇬', '新加坡'),
    'TW': ('🇹🇼', '台湾'), 'HK': ('🇭🇰', '香港'), 'MY': ('🇲🇾', '马来西亚'),
    'TH': ('🇹🇭', '泰国'), 'ID': ('🇮🇩', '印度尼西亚'), 'PH': ('🇵🇭', '菲律宾'),
    'VN': ('🇻🇳', '越南'), 'IN': ('🇮🇳', '印度'), 'MO': ('🇲🇴', '澳门'),
    'KH': ('🇰🇭', '柬埔寨'), 'LA': ('🇱🇦', '老挝'), 'MM': ('🇲🇲', '缅甸'),
    'MN': ('🇲🇳', '蒙古'), 'KP': ('🇰🇵', '朝鲜'), 'US': ('🇺🇸', '美国'),
    'GB': ('🇬🇧', '英国'), 'DE': ('🇩🇪', '德国'), 'FR': ('🇫🇷', '法国'),
    'IT': ('🇮🇹', '意大利'), 'ES': ('🇪🇸', '西班牙'), 'NL': ('🇳🇱', '荷兰'),
    'FI': ('🇫🇮', '芬兰'), 'AU': ('🇦🇺', '澳大利亚'), 'CA': ('🇨🇦', '加拿大'),
    'NZ': ('🇳🇿', '新西兰'), 'BR': ('🇧🇷', '巴西'), 'RU': ('🇷🇺', '俄罗斯'),
    'PL': ('🇵🇱', '波兰'), 'UA': ('🇺🇦', '乌克兰'), 'CZ': ('🇨🇿', '捷克'),
    'HU': ('🇭🇺', '匈牙利'), 'RO': ('🇷🇴', '罗马尼亚'), 'SA': ('🇸🇦', '沙特阿拉伯'),
    'AE': ('🇦🇪', '阿联酋'), 'QA': ('🇶🇦', '卡塔尔'), 'IL': ('🇮🇱', '以色列'),
    'TR': ('🇹🇷', '土耳其'), 'IR': ('🇮🇷', '伊朗'),
    'CN': ('🇨🇳', '中国'), 'BD': ('🇧🇩', '孟加拉国'), 'PK': ('🇵🇰', '巴基斯坦'),
    'LK': ('🇱🇰', '斯里兰卡'), 'NP': ('🇵🇵', '尼泊尔'), 'BT': ('🇧🇹', '不丹'),
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
    'KG': ('🇰🇬', '吉尔吉斯斯坦'), 'TJ': ('�TJ', '塔吉克斯坦'), 'TM': ('🇹🇲', '土库曼斯坦'),
    'GE': ('🇬🇪', '格鲁吉亚'), 'AM': ('🇦🇲', '亚美尼亚'), 'AZ': ('🇦🇿', '阿塞拜疆'),
    'KW': ('🇰🇼', '科威特'), 'BH': ('🇧🇭', '巴林'), 'OM': ('🇴🇲', '阿曼'),
    'JO': ('🇯🇴', '约旦'), 'LB': ('🇱🇧', '黎巴嫩'), 'SY': ('🇸🇾', '叙利亚'),
    'IQ': ('🇮🇶', '伊拉克'), 'YE': ('🇾🇪', '也门'),
    'EE': ('🇪🇪', '爱沙尼亚'), 'LV': ('🇱🇻', '拉脱维亚'), 'LT': ('🇱🇹', '立陶宛')
}
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
    'NORTH KOREA': 'KP', 'KOREA, DEMOCRATIC PEOPLE\'S REPUBLIC OF': 'KP', '朝鲜': 'KP'
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
    
    STATIC_REQUIRED_PACKAGES = ['requests', 'charset-normalizer', 'geoip2==4.8.0', 'maxminddb>=2.0.0']
    
    def get_non_stdlib_imports(script_path):
        stdlib_modules = set(sys.stdlib_module_names)
        imports = set()
        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read(), filename=script_path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for name in node.names:
                        module = name.name.split('.')[0]
                        if module not in stdlib_modules:
                            imports.add(module)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module.split('.')[0] if node.module else None
                    if module and module not in stdlib_modules:
                        imports.add(module)
        except Exception as e:
            logger.warning(f"解析脚本依赖失败: {e}")
        return imports
    
    MODULE_TO_PACKAGE = {
        'requests': 'requests>=2.32.3',
        'charset_normalizer': 'charset-normalizer>=3.4.1',
        'geoip2': 'geoip2==4.8.0',
        'maxminddb': 'maxminddb>=2.0.0',
        'packaging': 'packaging>=21.3',
    }
    
    script_path = os.path.abspath(__file__)
    dynamic_imports = get_non_stdlib_imports(script_path)
    logger.debug(f"动态检测到的非标准库模块: {dynamic_imports}")
    
    REQUIRED_PACKAGES = list(STATIC_REQUIRED_PACKAGES)
    for module in dynamic_imports:
        if module in MODULE_TO_PACKAGE and MODULE_TO_PACKAGE[module] not in REQUIRED_PACKAGES:
            REQUIRED_PACKAGES.append(MODULE_TO_PACKAGE[module])
    logger.debug(f"最终依赖列表: {REQUIRED_PACKAGES}")
    
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
    
    if recreate_venv:
        if venv_path.exists():
            logger.debug("删除现有虚拟环境")
            shutil.rmtree(venv_path, ignore_errors=True)
            logger.debug("成功删除现有虚拟环境")
        
        logger.debug(f"创建虚拟环境: {venv_path}")
        subprocess.run([sys.executable, '-m', 'venv', str(venv_path)], check=True)
        logger.debug("虚拟环境创建成功")
        
        venv_python = str(venv_path / ('Scripts' if system == 'windows' else 'bin') / 'python')
        pip_venv = str(venv_path / ('Scripts' if system == 'windows' else 'bin') / 'pip')
        logger.debug(f"虚拟环境 Python: {venv_python}, pip: {pip_venv}")
        
        try:
            result = subprocess.run([pip_venv, 'install', '--upgrade', 'pip'], check=True, capture_output=True, text=True)
            logger.debug(f"升级 pip 成功: {result.stdout}")
        except subprocess.CalledProcessError as e:
            logger.warning(f"升级 pip 失败: {e}, 输出: {e.output}")
        
        for pkg in REQUIRED_PACKAGES:
            logger.debug(f"安装依赖: {pkg}")
            try:
                result = subprocess.run([pip_venv, 'install', pkg], check=True, capture_output=True, text=True)
                logger.debug(f"成功安装依赖: {pkg}, 输出: {result.stdout}")
            except subprocess.CalledProcessError as e:
                logger.error(f"安装依赖 {pkg} 失败: {e}, 输出: {e.output}")
                sys.exit(1)
    
    venv_site = str(venv_path / ('Lib' if system == 'windows' else 'lib') / 
                    f"python{sys.version_info.major}.{sys.version_info.minor}" / 'site-packages')
    logger.debug(f"虚拟环境 site-packages: {venv_site}")
    if venv_site not in sys.path:
        sys.path.insert(0, venv_site)
    logger.debug("虚拟环境已激活")
    
    for module in list(sys.modules.keys()):
        if module.startswith('geoip2') or module.startswith('maxminddb'):
            del sys.modules[module]
    logger.debug("已清理 geoip2 和 maxminddb 模块缓存")
    
    try:
        import geoip2
        logger.debug(f"geoip2 模块已导入，版本: {geoip2.__version__}")
    except ImportError as e:
        logger.error(f"无法导入 geoip2: {e}", exc_info=True)
        sys.exit(1)
    
    try:
        import geoip2.database
        logger.debug("geoip2.database 模块已成功导入")
    except ImportError as e:
        logger.error(f"无法导入 geoip2.database: {e}", exc_info=True)
        sys.exit(1)
    
    try:
        import maxminddb
        logger.debug(f"maxminddb 模块已导入，版本: {maxminddb.__version__}")
    except ImportError as e:
        logger.error(f"无法导入 maxminddb: {e}", exc_info=True)
        sys.exit(1)
    
    try:
        import packaging
        logger.debug(f"packaging 模块已导入，版本: {packaging.__version__}")
    except ImportError as e:
        logger.error(f"无法导入 packaging: {e}", exc_info=True)
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
    
    # 定义多个代理服务
    proxy_services = [
        ("Ghfast.top", "https://ghfast.top/"),
        ("Gitproxy.clickr", "https://gitproxy.click/"),
        ("Gh-proxy.ygxz", "https://gh-proxy.ygxz.in/"),
        ("Github.ur1.fun", "https://github.ur1.fun/")
    ]
    
    # 首先尝试直接使用原始 URL（无代理）
    urls_to_try = [("无代理", url)]
    # 然后添加所有代理服务
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
        # 删除旧数据库文件（如果存在）
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
        if file_path.stat().st_size < 1024 * 1024:  # 小于 1MB
            logger.warning(f"GeoIP 数据库文件 {file_path} 过小，可能无效")
            return False
        # 检查文件是否过期（例如 30 天）
        mtime = file_path.stat().st_mtime
        current_time = time.time()
        age_days = (current_time - mtime) / (24 * 3600)
        if age_days > 30:
            logger.warning(f"GeoIP 数据库文件 {file_path} 已超过 30 天 ({age_days:.1f} 天)，建议使用 --update-geoip 更新")
        return True
    
    # 如果是离线模式，直接检查本地数据库
    if offline:
        logger.info("离线模式启用，将使用本地 GeoIP 数据库")
        if not GEOIP_DB_PATH.exists():
            logger.error(f"离线模式下未找到本地 GeoIP 数据库: {GEOIP_DB_PATH}")
            sys.exit(1)
    else:
        # 检查是否需要强制更新
        if update_geoip:
            logger.info("检测到 --update-geoip 参数，强制更新 GeoIP 数据库")
            GEOIP_DB_PATH.unlink(missing_ok=True)
        # 检查本地数据库是否存在且有效
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
    
    # 加载数据库
    try:
        import geoip2.database
        logger.debug("geoip2.database 模块已导入")
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
        # 如果加载失败，尝试重新下载
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
    comma_count = sum(1 for line in lines[:5] if ',' in line and line.strip())
    semicolon_count = sum(1 for line in lines[:5] if ';' in line and line.strip())
    tab_count = sum(1 for line in lines[:5] if '\t' in line and line.strip())
    space_count = sum(1 for line in lines[:5] if ' ' in line and line.strip())
    if comma_count > max(semicolon_count, tab_count, space_count) and comma_count > 0:
        return ','
    elif semicolon_count > max(comma_count, tab_count, space_count) and semicolon_count > 0:
        return ';'
    elif tab_count > max(comma_count, semicolon_count, space_count) and tab_count > 0:
        return '\t'
    elif space_count > max(comma_count, semicolon_count, tab_count) and space_count > 0:
        return ' '
    return None

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

def standardize_country(country: str) -> str:
    if not country:
        return ''
    country_clean = re.sub(r'[^a-zA-Z\s]', '', country).strip().upper()
    if country_clean in COUNTRY_LABELS:
        return country_clean
    if country_clean in COUNTRY_ALIASES:
        return COUNTRY_ALIASES[country_clean]
    country_clean = country_clean.replace(' ', '')
    for alias, code in COUNTRY_ALIASES.items():
        alias_clean = alias.replace(' ', '')
        if country_clean == alias_clean:
            return code
    return ''

def find_country_column(lines: List[str], delimiter: str) -> Tuple[int, int, int]:
    country_col = -1
    ip_col = 0
    port_col = 1
    sample_lines = [line for line in lines[:5] if line.strip() and not line.startswith('#')]
    if not sample_lines:
        return ip_col, port_col, country_col

    col_matches = defaultdict(int)
    total_rows = len(sample_lines)
    max_cols = max(len(line.split(delimiter)) for line in sample_lines)

    for line in sample_lines:
        fields = line.split(delimiter)
        for col, field in enumerate(fields):
            field = field.strip()
            if is_country_like(field):
                col_matches[col] += 1

    if col_matches:
        country_col = max(col_matches, key=col_matches.get)
        match_rate = col_matches[country_col] / total_rows
        if match_rate < 0.5:
            country_col = -1
        else:
            logger.info(f"国家列: 第 {country_col + 1} 列 (匹配率: {match_rate:.2%})")

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
        with open(TEMP_FILE, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        progress = (downloaded / total_size) * 100
                        logger.info(f"下载进度: {progress:.2f}%")
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
            ip = item.get('ip', '')
            port = item.get('port', '')
            country = standardize_country(
                item.get('country', '') or
                item.get('countryCode', '') or
                item.get('country_code', '') or
                item.get('location', '') or
                item.get('nation', '') or
                item.get('region', '') or
                item.get('geo', '') or
                item.get('area', '')
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
            if col_lower in ['ip', 'address', 'ip_address', 'ip地址']:
                ip_col = idx
            elif col_lower in ['port', '端口', 'port_number', '端口号']:
                port_col = idx
            elif col_lower in ['country', '国家', 'country_code', 'countrycode', '国际代码', 'nation', 'location', 'region', 'geo', 'area']:
                country_col = idx
        if country_col != -1:
            logger.info(f"检测到国家列: 第 {country_col + 1} 列 (字段名: {header[country_col]})")
            lines_to_process = lines[1:]
        else:
            logger.info("表头中不包含国家列，将逐行逐列搜索国家信息")

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
                            logger.info(f"第 {i} 行: 从第 {col + 1} 列提取国家: {field} -> {country}")
                            break
            if is_valid_port(port):
                server_port_pairs.append((server, int(port), country))
            else:
                invalid_lines.append(f"第 {i} 行: {line} (端口无效)")
            continue
        if delimiter:
            fields = line.split(delimiter)
            if len(fields) < max(ip_col, port_col) + 1:
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
                        logger.info(f"第 {i} 行: 从第 {col + 1} 列提取国家: {field} -> {country}")
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

def write_ip_list(ip_ports: List[Tuple[str, int, str]]) -> str:
    if not ip_ports:
        logger.error(f"没有有效的节点来生成 {IP_LIST_FILE}")
        return None

    start_time = time.time()
    country_cache = load_country_cache()
    filtered_ip_ports = set()
    country_counts = defaultdict(int)
    filtered_counts = defaultdict(int)
    logger.info(f"开始处理 {len(ip_ports)} 个节点...")

    from_source = sum(1 for _, _, country in ip_ports if country)
    logger.info(f"数据源为 {from_source} 个节点提供了国家信息")

    ips_to_query = [ip for ip, _, country in ip_ports if not country]
    if ips_to_query:
        logger.info(f"批量查询 {len(ips_to_query)} 个 IP 的国家信息")
        countries = get_countries_from_ips(ips_to_query, country_cache)
        ip_country_map = dict(zip(ips_to_query, countries))
    else:
        ip_country_map = {}

    supplemented = 0
    for ip, port, country in ip_ports:
        final_country = country
        source = "数据源" if country else "待查询"
        
        if not country:
            final_country = ip_country_map.get(ip, '')
            if final_country:
                supplemented += 1
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
    logger.info(f"生成 {IP_LIST_FILE}，包含 {len(filtered_ip_ports)} 个节点 (耗时: {time.time() - start_time:.2f} 秒)")
    save_country_cache(country_cache)
    return IP_LIST_FILE

def run_speed_test() -> str:
    if not SPEEDTEST_SCRIPT:
        logger.error("未找到测速脚本")
        return None
    if not os.path.exists(IP_LIST_FILE):
        logger.error(f"{IP_LIST_FILE} 不存在")
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

    logger.info("开始测速")
    system = platform.system().lower()
    try:
        if system == "windows":
            command = [SPEEDTEST_SCRIPT]
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
        def read_stream(stream, lines):
            while True:
                line = stream.readline()
                if not line:
                    break
                lines.append(line)
                print(line.strip())
                sys.stdout.flush()
        stdout_thread = threading.Thread(target=read_stream, args=(process.stdout, stdout_lines))
        stderr_thread = threading.Thread(target=read_stream, args=(process.stderr, stderr_lines))
        stdout_thread.start()
        stderr_thread.start()

        return_code = process.wait()
        stdout_thread.join()
        stderr_thread.join()
        stdout = ''.join(stdout_lines)
        stderr = ''.join(stderr_lines)
        if stdout:
            logger.info(f"测速输出: {stdout}")
        if stderr:
            logger.warning(f"测速错误: {stderr}")

        logger.info(f"测速完成，耗时: {time.time() - start_time:.2f} 秒")
        if return_code != 0:
            logger.error(f"测速失败，返回码: {return_code}")
            return None
        if not os.path.exists(FINAL_CSV) or os.path.getsize(FINAL_CSV) < 10:
            logger.error(f"{FINAL_CSV} 未生成或内容无效")
            return None
        with open(FINAL_CSV, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
            node_count = len(lines) - 1 if lines else 0
            logger.info(f"{FINAL_CSV} 包含 {node_count} 个节点")
        return FINAL_CSV
    except Exception as e:
        logger.error(f"测速异常: {e}")
        return None

def filter_speed_and_deduplicate(csv_file: str):
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
    logger.info(f"{csv_file} 处理完成，{len(final_rows)} 个数据节点 (耗时: {time.time() - start_time:.2f} 秒)")
    return len(final_rows)

def generate_ips_file(csv_file: str):
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
                final_nodes.append((ip, int(port), country))
    except Exception as e:
        logger.error(f"无法读取 {csv_file}: {e}")
        return
    if not final_nodes:
        logger.info(f"没有符合条件的节点")
        return
    country_count = defaultdict(int)
    labeled_nodes = []
    for ip, port, country in sorted(final_nodes, key=lambda x: x[2] or 'ZZ'):
        if country:
            country_count[country] += 1
            emoji, name = COUNTRY_LABELS.get(country, ('🌐', '未知'))
            label = f"{emoji}{name}-{country_count[country]}"
            labeled_nodes.append((ip, port, label))
    with open(IPS_FILE, "w", encoding="utf-8-sig") as f:
        for ip, port, label in labeled_nodes:
            f.write(f"{ip}:{port}#{label}\n")
    logger.info(f"生成 {IPS_FILE}，{len(labeled_nodes)} 个数据节点 (耗时: {time.time() - start_time:.2f} 秒)")
    logger.info(f"国家分布: {dict(country_count)}")
    save_country_cache(country_cache)
    return len(labeled_nodes)

def load_config() -> Dict[str, str]:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                required_fields = ['user_name', 'user_email', 'repo_name', 'ssh_key_path', 'git_user_name']
                if all(field in config for field in required_fields):
                    logger.info("已从缓存加载 Git 配置")
                    return config
                else:
                    logger.warning("缓存文件缺少必要字段，将重新提示输入")
        except Exception as e:
            logger.warning(f"无法加载缓存文件 {CONFIG_FILE}: {e}")
    return {}

def save_config(config: Dict[str, str]):
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
        os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)
        logger.info(f"Git 配置已保存到 {CONFIG_FILE}")
    except Exception as e:
        logger.error(f"无法保存缓存文件 {CONFIG_FILE}: {e}")
        sys.exit(1)

def generate_ssh_key() -> str:
    ssh_dir = os.path.expanduser("~/.ssh")
    private_key_path = SSH_KEY_PATH
    public_key_path = f"{private_key_path}.pub"

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        logger.info(f"SSH 密钥已存在: {private_key_path}")
        try:
            result = subprocess.run(
                ["ssh", "-T", "git@github.com"],
                capture_output=True,
                text=True,
                check=False
            )
            if "successfully authenticated" in result.stdout:
                logger.info("SSH 密钥验证成功，可连接到 GitHub")
            else:
                logger.warning(f"SSH 密钥验证失败: {result.stdout or result.stderr}")
                logger.info("请确保公钥已添加到 GitHub: https://github.com/settings/keys")
        except subprocess.CalledProcessError as e:
            logger.warning(f"无法验证 SSH 连接: {e.stderr}")
        return private_key_path  # 修改：返回私钥路径

    try:
        os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
        logger.info("正在生成 SSH 密钥...")
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", private_key_path, "-N", ""],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        os.chmod(private_key_path, stat.S_IRUSR | stat.S_IWUSR)
        os.chmod(public_key_path, stat.S_IRUSR | stat.S_IWUSR)
        logger.info(f"SSH 密钥生成成功: {private_key_path}")

        with open(public_key_path, 'r', encoding='utf-8') as f:
            public_key = f.read().strip()
        logger.info("请将以下公钥添加到 GitHub SSH 密钥设置 (https://github.com/settings/keys):")
        logger.info(public_key)
        logger.info("添加完成后，按回车继续...")
        input()

        return private_key_path  # 修改：返回私钥路径
    except subprocess.CalledProcessError as e:
        logger.error(f"生成 SSH 密钥失败: {e.stderr}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"生成 SSH 密钥时发生异常: {e}")
        sys.exit(1)

def setup_git_config() -> Dict[str, str]:
    config = load_config()
    if config:
        return config

    logger.info("检测到本地运行，需要配置 Git 信息")
    user_name = input("请输入 Git 用户名: ").strip()
    while not user_name:
        logger.warning("用户名不能为空")
        user_name = input("请输入 Git 用户名: ").strip()

    user_email = input("请输入 Git 邮箱: ").strip()
    while not user_email or '@' not in user_email:
        logger.warning("请输入有效的邮箱地址")
        user_email = input("请输入 Git 邮箱: ").strip()

    repo_name = input("请输入 GitHub 仓库名称: ").strip()
    while not repo_name or '/' in repo_name:
        logger.warning("请输入有效的仓库名称（仅输入仓库名称，例如 my-repo）")
        repo_name = input("请输入 GitHub 仓库名称: ").strip()

    try:
        result = subprocess.run(
            ["git", "config", "user.name"],
            capture_output=True,
            text=True,
            check=True
        )
        git_user_name = result.stdout.strip()
        if git_user_name:
            logger.info(f"检测到 Git 配置的用户名: {git_user_name}")
        else:
            git_user_name = user_name
    except subprocess.CalledProcessError:
        logger.warning("无法获取 Git 配置的用户名，将使用输入的用户名")
        git_user_name = user_name

    ssh_key_path = generate_ssh_key()

    config = {
        "user_name": user_name,
        "user_email": user_email,
        "repo_name": repo_name,
        "ssh_key_path": ssh_key_path,
        "git_user_name": git_user_name
    }
    save_config(config)
    return config

def initialize_git_repo():
    git_dir = os.path.join(os.getcwd(), ".git")
    if not os.path.exists(git_dir):
        logger.info("当前目录不是 Git 仓库，执行 git init")
        try:
            subprocess.run(
                ["git", "init"],
                check=True,
                capture_output=True,
                text=True
            )
            logger.info("Git 仓库初始化成功")
        except subprocess.CalledProcessError as e:
            logger.error(f"无法初始化 Git 仓库: {e.stderr}")
            return False
    return True

def detect_environment() -> tuple[str, bool, Dict[str, str]]:
    is_github_actions = os.getenv("GITHUB_ACTIONS") == "true"
    
    try:
        git_version = subprocess.run(
            ["git", "--version"],
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()
        logger.info(f"Git 版本: {git_version}")
    except FileNotFoundError:
        logger.error("Git 未安装，请先安装 Git (https://git-scm.com/downloads)")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        logger.error(f"无法检测 Git 版本: {e.stderr}")
        sys.exit(1)

    if not is_github_actions:
        initialize_git_repo()

    try:
        branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()
        if branch == "HEAD":
            logger.warning("当前处于分离头状态，将尝试切换到默认分支")
            try:
                default_branch = subprocess.run(
                    ["git", "remote", "show", "origin"],
                    capture_output=True,
                    text=True,
                    check=True
                ).stdout
                for line in default_branch.splitlines():
                    if "HEAD branch" in line:
                        branch = line.split(":")[-1].strip()
                        subprocess.run(
                            ["git", "checkout", branch],
                            check=True,
                            capture_output=True,
                            text=True
                        )
                        logger.info(f"已切换到默认分支: {branch}")
                        break
                else:
                    branch = "main"
                    logger.warning(f"无法检测远程默认分支，使用默认分支: {branch}")
                    subprocess.run(
                        ["git", "checkout", "-b", branch],
                        check=True,
                        capture_output=True,
                        text=True
                    )
                    logger.info(f"创建并切换到新分支: {branch}")
            except subprocess.CalledProcessError as e:
                branch = "main"
                logger.warning(f"无法处理分支切换: {e.stderr}，使用默认分支: {branch}")
                subprocess.run(
                    ["git", "checkout", "-b", branch],
                    check=True,
                    capture_output=True,
                    text=True
                )
                logger.info(f"创建并切换到新分支: {branch}")
    except subprocess.CalledProcessError as e:
        branch = "main"
        logger.warning(f"无法检测当前分支: {e.stderr}，使用默认分支: {branch}")
        try:
            subprocess.run(
                ["git", "checkout", "-b", branch],
                check=True,
                capture_output=True,
                text=True
            )
            logger.info(f"创建并切换到新分支: {branch}")
        except subprocess.CalledProcessError as e:
            logger.error(f"无法创建分支 {branch}: {e.stderr}")
            branch = "main"

    git_config = {}
    if not is_github_actions:
        git_config = setup_git_config()
        try:
            subprocess.run(
                ["git", "config", "--local", "user.name", git_config["user_name"]],
                check=True,
                capture_output=True,
                text=True
            )
            subprocess.run(
                ["git", "config", "--local", "user.email", git_config["user_email"]],
                check=True,
                capture_output=True,
                text=True
            )
            logger.info(f"已设置 Git 用户: {git_config['user_name']} <{git_config['user_email']}>")
        except subprocess.CalledProcessError as e:
            logger.warning(f"无法设置 Git 用户配置: {e.stderr}. 继续执行后续步骤")

        try:
            remote_url = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
                check=True
            ).stdout.strip()
            if not remote_url:
                raise subprocess.CalledProcessError(1, "git remote get-url")
            if "github.com" not in remote_url.lower():
                logger.warning(f"远程仓库地址 {remote_url} 不像是 GitHub 仓库")
        except subprocess.CalledProcessError:
            repo_name = git_config["repo_name"]
            git_user_name = git_config["git_user_name"]
            remote_url = f"git@github.com:{git_user_name}/{repo_name}.git"
            logger.info(f"设置远程仓库地址为: {remote_url}")
            try:
                subprocess.run(
                    ["git", "remote", "add", "origin", remote_url],
                    check=True,
                    capture_output=True,
                    text=True
                )
            except subprocess.CalledProcessError as e:
                logger.warning(f"无法设置远程仓库地址: {e.stderr}. 跳过远程操作")

        try:
            subprocess.run(
                ["git", "fetch", "origin"],
                check=True,
                capture_output=True,
                text=True
            )
            logger.info("成功拉取远程仓库")
        except subprocess.CalledProcessError as e:
            logger.warning(f"无法拉取远程仓库: {e.stderr}. 继续本地操作")

    return branch, is_github_actions, git_config

def commit_and_push(branch: str, is_github_actions: bool):
    try:
        # 提交更改
        subprocess.run(
            ["git", "add", IP_LIST_FILE, FINAL_CSV, IPS_FILE],
            check=True,
            capture_output=True,
            text=True
        )
        logger.info("已添加文件到 Git 暂存区")

        commit_message = f"Update IP data - {time.strftime('%Y-%m-%d %H:%M:%S')}"
        result = subprocess.run(
            ["git", "commit", "-m", commit_message],
            check=True,
            capture_output=True,
            text=True
        )
        logger.info(f"已提交更改: {commit_message}, 输出: {result.stdout}")
    except subprocess.CalledProcessError as e:
        if "nothing to commit" in e.stderr:
            logger.info("没有需要提交的更改，无需推送")
            return True  # 直接返回，避免不必要的推送
        else:
            logger.warning(f"无法提交更改: {e.stderr}")
            return False

    if not is_github_actions:
        try:
            # 先拉取远程更改并尝试变基
            logger.info(f"尝试拉取远程分支并变基: {branch}")
            result = subprocess.run(
                ["git", "pull", "--rebase", "origin", branch],
                check=True,
                capture_output=True,
                text=True
            )
            logger.info(f"拉取并变基成功: {result.stdout}")
        except subprocess.CalledProcessError as e:
            logger.error(f"拉取并变基失败: {e.stderr}")
            logger.error("可能存在冲突，请手动解决后再推送")
            return False

        try:
            # 推送
            result = subprocess.run(
                ["git", "push", "origin", branch],
                check=True,
                capture_output=True,
                text=True
            )
            logger.info(f"已推送到远程分支: {branch}, 输出: {result.stdout}")
        except subprocess.CalledProcessError as e:
            logger.error(f"推送失败: {e.stderr}")
            logger.error("推送失败，请检查网络连接或分支状态")
            return False

    return True

def main():
    parser = argparse.ArgumentParser(description="IP 筛选和测速工具")
    parser.add_argument('--input', type=str, default=INPUT_FILE, help="输入文件路径")
    parser.add_argument('--url', type=str, default=INPUT_URL, help="输入 URL")
    parser.add_argument('--offline', action='store_true', help="离线模式，使用本地 GeoIP 数据库，不尝试下载")
    parser.add_argument('--update-geoip', action='store_true', help="强制更新 GeoIP 数据库")
    args = parser.parse_args()

    setup_and_activate_venv()
    # 传递 update_geoip 参数给 init_geoip_reader
    check_dependencies(offline=args.offline, update_geoip=args.update_geoip)

    branch, is_github_actions, git_config = detect_environment()

    input_file = args.input
    if args.url and not os.path.exists(input_file):
        if is_temp_file_valid(TEMP_FILE):
            input_file = TEMP_FILE
        else:
            input_file = fetch_and_save_to_temp_file(args.url)
            if not input_file:
                logger.error("无法下载输入文件，退出")
                sys.exit(1)

    ip_ports = extract_ip_ports_from_file(input_file)
    if not ip_ports:
        logger.error("没有提取到有效的 IP 和端口，退出")
        sys.exit(1)

    ip_list_file = write_ip_list(ip_ports)
    if not ip_list_file:
        logger.error("无法生成 IP 列表，退出")
        sys.exit(1)

    csv_file = run_speed_test()
    if not csv_file:
        logger.error("测速失败，退出")
        sys.exit(1)

    node_count = filter_speed_and_deduplicate(csv_file)
    if not node_count:
        logger.error("过滤后没有有效的节点，退出")
        sys.exit(1)

    final_node_count = generate_ips_file(csv_file)
    if not final_node_count:
        logger.error("无法生成最终的 ips.txt 文件，退出")
        sys.exit(1)

    if not commit_and_push(branch, is_github_actions):
        logger.warning("提交或推送失败，但本地文件已生成")

    logger.info("流程完成！")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("用户中断操作，退出")
        sys.exit(1)
    except Exception as e:
        logger.error(f"程序异常: {e}")
        sys.exit(1)