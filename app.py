# -*- coding: utf-8 -*-
import telebot
from telebot import types
from telebot.apihelper import ApiTelegramException
import subprocess
import os
import zipfile
import tempfile
import shutil
import time
import gc
from datetime import datetime, timedelta
import psutil
import sqlite3
import logging
import threading
import re
import sys
import atexit
import requests
import random
import string
import hashlib
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import signal
from typing import Optional, Dict, List, Tuple, Set, Any, Union
from dataclasses import dataclass, field
from contextlib import contextmanager
from queue import Queue
from collections import deque, defaultdict
from functools import wraps
import json
import traceback

# ==================== CẤU HÌNH ====================
# ⚠️ Khuyến nghị: đặt token qua biến môi trường để tránh lộ token khi share code
# Linux/Mac:  export BOT_TOKEN="123:ABC..."
# Windows:    setx BOT_TOKEN "123:ABC..."
TOKEN = '8505111864:AAGD5gs7qa4lb1wsvPYOwzl6JUTERo5MuuE'
OWNER_ID = "8208489603"
YOUR_USERNAME = "@taolailove2"

if not TOKEN:
    raise RuntimeError("❌ Thiếu BOT_TOKEN/TELEGRAM_BOT_TOKEN. Hãy set biến môi trường chứa token bot Telegram.")
# Cấu hình thư mục
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_BOTS_DIR = os.path.join(BASE_DIR, 'upload_bots')
IROTECH_DIR = os.path.join(BASE_DIR, 'inf')
DATABASE_PATH = os.path.join(IROTECH_DIR, 'bot_data.db')
CAPTCHA_DIR = os.path.join(BASE_DIR, 'captcha_images')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
TEMP_DIR = os.path.join(BASE_DIR, 'temp')

for dir_path in [UPLOAD_BOTS_DIR, IROTECH_DIR, CAPTCHA_DIR, LOGS_DIR, TEMP_DIR]:
    os.makedirs(dir_path, exist_ok=True)

# Giới hạn file
FREE_USER_LIMIT = 10
SUBSCRIBED_USER_LIMIT = 15
ADMIN_LIMIT = 999
OWNER_LIMIT = float('inf')

# Cấu hình hệ thống Coin
REFERRAL_REWARD = 3  # Coin cho mỗi lần giới thiệu thành công
DAILY_COIN_REWARD = 5  # Coin nhận mỗi ngày
DAILY_STREAK_BONUS = 2  # Bonus thêm cho streak
MAX_REFERRALS_PER_USER = 100
CAPTCHA_ATTEMPTS = 5
CAPTCHA_BAN_TIME = 30  # phút
MIN_TREASURE_COINS = 1
MAX_TREASURE_COINS = 10
TREASURE_COOLDOWN = 3600  # giây
REFERRAL_COOLDOWN = 300  # 5 phút giữa các lần refer

# Cấu hình Treo (Pin)
PIN_COST_PER_DAY = 15  # coin / ngày
MAX_PIN_DAYS = 7  # tối đa 7 ngày

# Cấu hình Anti-Spam
SPAM_MAX_ACTIONS = 12  # số hành động tối đa trong cửa sổ
SPAM_WINDOW_SECONDS = 10
SPAM_FILE_UPLOAD_LIMIT = 3  # số lần upload tối đa
SPAM_FILE_UPLOAD_WINDOW = 60  # giây
SPAM_PENALTY_MINUTES = 10  # ban tạm nếu spam nhiều lần

# Cấu hình Antivirus/Anti-botnet (heuristic)
MAX_ZIP_EXTRACT_MB = 100  # giới hạn tổng dung lượng giải nén để chống zip bomb
MAX_ZIP_FILE_COUNT = 300  # giới hạn số file trong zip
VIRUS_SCAN_MAX_BYTES = 2 * 1024 * 1024  # đọc tối đa 2MB mỗi file khi quét


# Cấu hình Anti-Buff
MAX_REFS_PER_IP = 3
MAX_REFS_PER_DAY = 10
SUSPICIOUS_PATTERNS = [
    r'bot\d+',
    r'^[a-f0-9]{10,}$',
    r'^\d{5,}$'
]

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, 'bot.log'), encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==================== KHỞI TẠO BOT ====================
# ==================== KHỞI TẠO BOT ====================
# Tăng số luồng để xử lý mượt hơn (phù hợp đa số host)
try:
    bot = telebot.TeleBot(TOKEN, threaded=True, num_threads=int(os.getenv("BOT_THREADS", "8")))
except TypeError:
    # Fallback cho bản pyTelegramBotAPI cũ
    bot = telebot.TeleBot(TOKEN)

# ==================== SAFE TELEGRAM CALLS ====================
# Tránh crash với các lỗi "không nghiêm trọng" (đặc biệt: message is not modified)
def _should_ignore_telegram_exception(e: Exception) -> bool:
    if not isinstance(e, ApiTelegramException):
        return False

    msg = str(e).lower()

    # Telegram trả 400 khi edit y hệt nội dung/markup cũ
    if "message is not modified" in msg:
        return True

    # Race condition / tin nhắn không còn hợp lệ để edit/delete
    if "message to edit not found" in msg:
        return True
    if "message can't be edited" in msg:
        return True
    if "message to delete not found" in msg:
        return True

    # Callback quá hạn (người dùng bấm nút rất lâu sau)
    if "query is too old" in msg or "response timeout expired" in msg:
        return True

    return False

def _wrap_bot_method_safe(method_name: str):
    original = getattr(bot, method_name, None)
    if not original:
        return

    def wrapper(*args, **kwargs):
        try:
            return original(*args, **kwargs)
        except ApiTelegramException as e:
            if _should_ignore_telegram_exception(e):
                return None
            raise

    setattr(bot, method_name, wrapper)

for _name in ("edit_message_text", "edit_message_reply_markup", "delete_message", "answer_callback_query"):
    _wrap_bot_method_safe(_name)

# Cache bot username để tránh gọi get_me() quá nhiều (giảm lag/rate-limit)
_BOT_USERNAME_CACHE = None

def get_bot_username() -> str:
    global _BOT_USERNAME_CACHE
    if not _BOT_USERNAME_CACHE:
        try:
            _BOT_USERNAME_CACHE = bot.get_me().username
        except Exception:
            _BOT_USERNAME_CACHE = ""
    return _BOT_USERNAME_CACHE or ""
try:
    bot.set_my_commands([
        telebot.types.BotCommand("start", "🚀 Khởi động bot"),
        telebot.types.BotCommand("menu", "📋 Menu chính"),
        telebot.types.BotCommand("daily", "🎁 Nhận coin hàng ngày"),
        telebot.types.BotCommand("balance", "💰 Xem số dư"),
        telebot.types.BotCommand("referral", "👥 Giới thiệu bạn bè"),
        telebot.types.BotCommand("help", "🆘 Trợ giúp")
    ])
except Exception as e:
    logger.warning(f"⚠️ Không thể set_my_commands: {e}")

# ==================== CẤU TRÚC DỮ LIỆU ====================
@dataclass
class UserData:
    user_id: int
    username: str = ""
    first_name: str = ""
    balance: int = 0
    referred_by: Optional[int] = None
    referral_count: int = 0
    referral_earnings: int = 0
    daily_claim_time: Optional[datetime] = None
    daily_streak: int = 0
    is_banned: bool = False
    ban_until: Optional[datetime] = None
    captcha_attempts: int = 0
    last_captcha_time: Optional[datetime] = None
    subscription_expiry: Optional[datetime] = None
    created_at: Optional[datetime] = None
    last_active: Optional[datetime] = None
    total_earned: int = 0
    treasure_last_open: Optional[datetime] = None
    treasure_count: int = 0
    last_referral_time: Optional[datetime] = None
    ip_address: str = ""
    is_suspicious: bool = False
    warning_count: int = 0
    total_daily_claimed: int = 0

@dataclass
class CaptchaData:
    user_id: int
    code: str
    image_path: str
    created_at: datetime
    attempts: int = 0
    challenge_type: str = "referral"  # referral, daily, treasure

@dataclass
class AntiBuffData:
    ip_address: str
    referral_count: int = 0
    last_referral_time: Optional[datetime] = None
    suspicious_activities: int = 0
    is_blocked: bool = False
    block_until: Optional[datetime] = None

# ==================== QUẢN LÝ DATABASE NÂNG CAO ====================
class DatabaseManager:
    _instance = None
    _lock = threading.RLock()
    _connection_pool: Dict[str, sqlite3.Connection] = {}
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialize()
            return cls._instance
    
    def _initialize(self):
        self.db_path = DATABASE_PATH
        self.pool_size = 5
        self._init_db()
        self._migrate_db()
        self._ensure_owner_admin()
        self._start_cleanup_thread()
    
    @contextmanager
    def get_connection(self):
        thread_id = threading.get_ident()
        with self._lock:
            if thread_id not in self._connection_pool:
                conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA foreign_keys=ON")
                self._connection_pool[thread_id] = conn
        
        conn = self._connection_pool[thread_id]
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            pass
    
    def _init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Bảng users mở rộng
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    username TEXT,
                    first_name TEXT,
                    balance INTEGER DEFAULT 0,
                    referred_by INTEGER,
                    referral_count INTEGER DEFAULT 0,
                    referral_earnings INTEGER DEFAULT 0,
                    daily_claim_time TIMESTAMP,
                    daily_streak INTEGER DEFAULT 0,
                    is_banned INTEGER DEFAULT 0,
                    ban_until TIMESTAMP,
                    captcha_attempts INTEGER DEFAULT 0,
                    last_captcha_time TIMESTAMP,
                    subscription_expiry TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    total_earned INTEGER DEFAULT 0,
                    treasure_last_open TIMESTAMP,
                    treasure_count INTEGER DEFAULT 0,
                    last_referral_time TIMESTAMP,
                    ip_address TEXT,
                    is_suspicious INTEGER DEFAULT 0,
                    warning_count INTEGER DEFAULT 0,
                    total_daily_claimed INTEGER DEFAULT 0
                )
            ''')
            
            # Bảng referrals chi tiết
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS referrals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    referrer_id INTEGER,
                    referred_id INTEGER,
                    reward_given INTEGER DEFAULT 0,
                    ip_address TEXT,
                    user_agent TEXT,
                    status TEXT DEFAULT 'pending',
                    verified_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(referrer_id, referred_id)
                )
            ''')
            
            # Bảng transactions
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    amount INTEGER,
                    type TEXT,
                    description TEXT,
                    balance_after INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Bảng user files
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_files (
                    user_id INTEGER,
                    file_name TEXT,
                    file_type TEXT,
                    file_size INTEGER,
                    is_running INTEGER DEFAULT 0,
                    process_id INTEGER,
                    last_started TIMESTAMP,
                    last_stopped TIMESTAMP,
                    run_count INTEGER DEFAULT 0,
                    pinned_until TIMESTAMP,
                    pinned_by INTEGER,
                    pinned_at TIMESTAMP,
                    PRIMARY KEY (user_id, file_name)
                )
            ''')
            
            # Bảng active users
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS active_users (
                    user_id INTEGER PRIMARY KEY,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Bảng admins
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS admins (
                    user_id INTEGER PRIMARY KEY,
                    added_by INTEGER,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Bảng captcha
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS captcha (
                    user_id INTEGER PRIMARY KEY,
                    code TEXT,
                    image_path TEXT,
                    created_at TIMESTAMP,
                    attempts INTEGER DEFAULT 0,
                    challenge_type TEXT DEFAULT 'referral'
                )
            ''')
            
            # Bảng anti-buff
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS anti_buff (
                    ip_address TEXT PRIMARY KEY,
                    referral_count INTEGER DEFAULT 0,
                    last_referral_time TIMESTAMP,
                    suspicious_activities INTEGER DEFAULT 0,
                    is_blocked INTEGER DEFAULT 0,
                    block_until TIMESTAMP
                )
            ''')
            
            # Bảng banned_ips
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS banned_ips (
                    ip_address TEXT PRIMARY KEY,
                    reason TEXT,
                    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    banned_by INTEGER
                )
            ''')
            
            # Bảng daily_rewards
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS daily_rewards (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    amount INTEGER,
                    streak_day INTEGER,
                    claimed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # Tạo indexes
            indexes = [
                'CREATE INDEX IF NOT EXISTS idx_users_referred_by ON users(referred_by)',
                'CREATE INDEX IF NOT EXISTS idx_users_created ON users(created_at)',
                'CREATE INDEX IF NOT EXISTS idx_users_last_active ON users(last_active)',
                'CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals(referrer_id)',
                'CREATE INDEX IF NOT EXISTS idx_referrals_referred ON referrals(referred_id)',
                'CREATE INDEX IF NOT EXISTS idx_referrals_created ON referrals(created_at)',
                'CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id)',
                'CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type)',
                'CREATE INDEX IF NOT EXISTS idx_transactions_created ON transactions(created_at)',
                'CREATE INDEX IF NOT EXISTS idx_user_files_running ON user_files(is_running)',
                'CREATE INDEX IF NOT EXISTS idx_user_files_pinned_until ON user_files(pinned_until)',
                'CREATE INDEX IF NOT EXISTS idx_captcha_created ON captcha(created_at)',
                'CREATE INDEX IF NOT EXISTS idx_anti_buff_blocked ON anti_buff(is_blocked)'
            ]
            
            for idx in indexes:
                try:
                    cursor.execute(idx)
                except sqlite3.OperationalError as e:
                    logger.warning(f"Không thể tạo index: {e}")
    
    def _migrate_db(self):
        """Migration an toàn với kiểm tra cột tồn tại"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                def column_exists(table, column):
                    cursor.execute(f"PRAGMA table_info({table})")
                    return any(row[1] == column for row in cursor.fetchall())
                
                # Thêm cột mới cho users
                user_columns = [
                    ('daily_streak', 'INTEGER DEFAULT 0'),
                    ('last_referral_time', 'TIMESTAMP'),
                    ('ip_address', 'TEXT'),
                    ('is_suspicious', 'INTEGER DEFAULT 0'),
                    ('warning_count', 'INTEGER DEFAULT 0'),
                    ('total_daily_claimed', 'INTEGER DEFAULT 0')
                ]
                
                for col_name, col_def in user_columns:
                    if not column_exists('users', col_name):
                        try:
                            cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")
                            logger.info(f"Đã thêm cột {col_name} vào bảng users")
                        except sqlite3.OperationalError as e:
                            logger.warning(f"Không thể thêm cột {col_name}: {e}")
                
                # Thêm cột cho referrals
                referral_columns = [
                    ('ip_address', 'TEXT'),
                    ('user_agent', 'TEXT'),
                    ('status', 'TEXT DEFAULT "pending"'),
                    ('verified_at', 'TIMESTAMP')
                ]
                
                for col_name, col_def in referral_columns:
                    if not column_exists('referrals', col_name):
                        try:
                            cursor.execute(f"ALTER TABLE referrals ADD COLUMN {col_name} {col_def}")
                        except sqlite3.OperationalError as e:
                            logger.warning(f"Không thể thêm cột {col_name} vào referrals: {e}")
                
                # Thêm cột cho user_files
                file_columns = [
                    ('file_size', 'INTEGER'),
                    ('last_stopped', 'TIMESTAMP'),
                    ('run_count', 'INTEGER DEFAULT 0'),
                    ('pinned_until', 'TIMESTAMP'),
                    ('pinned_by', 'INTEGER'),
                    ('pinned_at', 'TIMESTAMP')
                ]
                
                for col_name, col_def in file_columns:
                    if not column_exists('user_files', col_name):
                        try:
                            cursor.execute(f"ALTER TABLE user_files ADD COLUMN {col_name} {col_def}")
                        except sqlite3.OperationalError as e:
                            logger.warning(f"Không thể thêm cột {col_name} vào user_files: {e}")

                # Thêm cột cho admins (fix DB cũ thiếu added_by)
                admin_columns = [
                    ('added_by', 'INTEGER'),
                    ('added_at', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
                ]

                for col_name, col_def in admin_columns:
                    if not column_exists('admins', col_name):
                        try:
                            cursor.execute(f"ALTER TABLE admins ADD COLUMN {col_name} {col_def}")
                            logger.info(f"Đã thêm cột {col_name} vào bảng admins")
                        except sqlite3.OperationalError as e:
                            logger.warning(f"Không thể thêm cột {col_name} vào admins: {e}")

        except Exception as e:
            logger.error(f"Lỗi migration database: {e}")
    


    def _ensure_owner_admin(self):
        """Đảm bảo OWNER luôn nằm trong bảng admins (an toàn với DB cũ)."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Kiểm tra cột tồn tại
                cursor.execute("PRAGMA table_info(admins)")
                cols = [row[1] for row in cursor.fetchall()]

                if 'added_by' in cols:
                    cursor.execute('''
                        INSERT OR IGNORE INTO admins (user_id, added_by)
                        VALUES (?, ?)
                    ''', (OWNER_ID, OWNER_ID))
                else:
                    # Fallback cho DB rất cũ (chưa có added_by)
                    cursor.execute('''
                        INSERT OR IGNORE INTO admins (user_id)
                        VALUES (?)
                    ''', (OWNER_ID,))
        except Exception as e:
            logger.error(f"Lỗi đảm bảo owner admin: {e}")
    def _start_cleanup_thread(self):
        def cleanup_old_data():
            while True:
                time.sleep(3600)  # 1 giờ
                try:
                    with self.get_connection() as conn:
                        cursor = conn.cursor()
                        
                        # Xóa captcha cũ hơn 1 giờ
                        cursor.execute('''
                            DELETE FROM captcha 
                            WHERE created_at < datetime('now', '-1 hour')
                        ''')
                        
                        # Xóa active users cũ hơn 7 ngày
                        cursor.execute('''
                            DELETE FROM active_users 
                            WHERE last_seen < datetime('now', '-7 days')
                        ''')
                        
                        # Cập nhật trạng thái banned hết hạn
                        cursor.execute('''
                            UPDATE users 
                            SET is_banned = 0, ban_until = NULL 
                            WHERE is_banned = 1 AND ban_until < datetime('now')
                        ''')
                        
                        # Xóa treo hết hạn
                        cursor.execute('''
                            UPDATE user_files
                            SET pinned_until = NULL, pinned_by = NULL, pinned_at = NULL
                            WHERE pinned_until IS NOT NULL AND datetime(replace(pinned_until,'T',' ')) < datetime('now')
                        ''')

                        conn.commit()
                except Exception as e:
                    logger.error(f"Lỗi cleanup database: {e}")
        
        thread = threading.Thread(target=cleanup_old_data, daemon=True)
        thread.start()
    
    # ==================== USER METHODS NÂNG CAO ====================
    def get_user(self, user_id: int) -> Optional[UserData]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
            row = cursor.fetchone()
            
            if row:
                return UserData(
                    user_id=row['user_id'],
                    username=row['username'] or '',
                    first_name=row['first_name'] or '',
                    balance=row['balance'],
                    referred_by=row['referred_by'],
                    referral_count=row['referral_count'],
                    referral_earnings=row['referral_earnings'],
                    daily_claim_time=self._parse_datetime(row['daily_claim_time']),
                    daily_streak=row['daily_streak'],
                    is_banned=bool(row['is_banned']),
                    ban_until=self._parse_datetime(row['ban_until']),
                    captcha_attempts=row['captcha_attempts'],
                    last_captcha_time=self._parse_datetime(row['last_captcha_time']),
                    subscription_expiry=self._parse_datetime(row['subscription_expiry']),
                    created_at=self._parse_datetime(row['created_at']),
                    last_active=self._parse_datetime(row['last_active']),
                    total_earned=row['total_earned'],
                    treasure_last_open=self._parse_datetime(row['treasure_last_open']),
                    treasure_count=row['treasure_count'],
                    last_referral_time=self._parse_datetime(row['last_referral_time']),
                    ip_address=row['ip_address'] or '',
                    is_suspicious=bool(row['is_suspicious']),
                    warning_count=row['warning_count'],
                    total_daily_claimed=row['total_daily_claimed']
                )
            return None
    
    def _parse_datetime(self, value) -> Optional[datetime]:
        if value:
            try:
                return datetime.fromisoformat(value)
            except (ValueError, TypeError):
                return None
        return None
    
    def create_user(self, user_id: int, username: str = "", first_name: str = "", ip: str = "") -> UserData:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now()
            
            cursor.execute('''
                INSERT OR IGNORE INTO users 
                (user_id, username, first_name, created_at, last_active, ip_address)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, username, first_name, now.isoformat(), now.isoformat(), ip))
            
            return self.get_user(user_id)
    
    def update_user(self, user: UserData):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET
                    username = ?,
                    first_name = ?,
                    balance = ?,
                    referred_by = ?,
                    referral_count = ?,
                    referral_earnings = ?,
                    daily_claim_time = ?,
                    daily_streak = ?,
                    is_banned = ?,
                    ban_until = ?,
                    captcha_attempts = ?,
                    last_captcha_time = ?,
                    subscription_expiry = ?,
                    last_active = ?,
                    total_earned = ?,
                    treasure_last_open = ?,
                    treasure_count = ?,
                    last_referral_time = ?,
                    ip_address = ?,
                    is_suspicious = ?,
                    warning_count = ?,
                    total_daily_claimed = ?
                WHERE user_id = ?
            ''', (
                user.username, user.first_name, user.balance,
                user.referred_by, user.referral_count, user.referral_earnings,
                user.daily_claim_time.isoformat() if user.daily_claim_time else None,
                user.daily_streak,
                1 if user.is_banned else 0,
                user.ban_until.isoformat() if user.ban_until else None,
                user.captcha_attempts,
                user.last_captcha_time.isoformat() if user.last_captcha_time else None,
                user.subscription_expiry.isoformat() if user.subscription_expiry else None,
                datetime.now().isoformat(),
                user.total_earned,
                user.treasure_last_open.isoformat() if user.treasure_last_open else None,
                user.treasure_count,
                user.last_referral_time.isoformat() if user.last_referral_time else None,
                user.ip_address,
                1 if user.is_suspicious else 0,
                user.warning_count,
                user.total_daily_claimed,
                user.user_id
            ))
    
    def add_transaction(self, user_id: int, amount: int, type_: str, description: str, balance_after: int):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO transactions (user_id, amount, type, description, balance_after)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, amount, type_, description, balance_after))
    
    # ==================== REFERRAL METHODS NÂNG CAO ====================
    def add_referral(self, referrer_id: int, referred_id: int, reward: int, 
                     ip_address: str = "", user_agent: str = "") -> Tuple[bool, str]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Kiểm tra tồn tại
            cursor.execute('''
                SELECT id, status FROM referrals 
                WHERE referrer_id = ? AND referred_id = ?
            ''', (referrer_id, referred_id))
            
            existing = cursor.fetchone()
            if existing:
                if existing['status'] == 'completed':
                    return False, "❌ Người dùng này đã được giới thiệu trước đó!"
                elif existing['status'] == 'pending':
                    return False, "⏳ Giao dịch giới thiệu đang chờ xử lý!"
            
            # Kiểm tra anti-buff
            if ip_address:
                check, msg = self.check_anti_buff(ip_address, referrer_id)
                if not check:
                    return False, msg
            
            # Thêm referral
            cursor.execute('''
                INSERT INTO referrals (referrer_id, referred_id, reward_given, ip_address, user_agent, status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (referrer_id, referred_id, reward, ip_address, user_agent, 'completed'))
            
            # Cập nhật user referrer
            cursor.execute('''
                UPDATE users 
                SET referral_count = referral_count + 1,
                    referral_earnings = referral_earnings + ?,
                    balance = balance + ?,
                    total_earned = total_earned + ?,
                    last_referral_time = ?
                WHERE user_id = ?
            ''', (reward, reward, reward, datetime.now().isoformat(), referrer_id))
            
            # Cập nhật anti-buff
            if ip_address:
                cursor.execute('''
                    INSERT INTO anti_buff (ip_address, referral_count, last_referral_time)
                    VALUES (?, 1, ?)
                    ON CONFLICT(ip_address) DO UPDATE SET
                        referral_count = referral_count + 1,
                        last_referral_time = ?
                ''', (ip_address, datetime.now().isoformat(), datetime.now().isoformat()))
            
            return True, "✅ Thêm referral thành công!"
    
    def get_referrals(self, user_id: int, limit: int = 50) -> List[Dict]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT r.*, u.username, u.first_name, u.created_at as user_created
                FROM referrals r
                JOIN users u ON r.referred_id = u.user_id
                WHERE r.referrer_id = ?
                ORDER BY r.created_at DESC
                LIMIT ?
            ''', (user_id, limit))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_referral_stats(self, user_id: int) -> Dict:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Tổng quan
            cursor.execute('''
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                    SUM(reward_given) as total_rewards,
                    MAX(created_at) as last_referral
                FROM referrals 
                WHERE referrer_id = ?
            ''', (user_id,))
            
            stats = dict(cursor.fetchone())
            
            # Theo ngày
            cursor.execute('''
                SELECT DATE(created_at) as date, COUNT(*) as count
                FROM referrals
                WHERE referrer_id = ? AND created_at >= DATE('now', '-7 days')
                GROUP BY DATE(created_at)
                ORDER BY date DESC
            ''', (user_id,))
            
            stats['daily'] = [dict(row) for row in cursor.fetchall()]
            
            return stats
    
    # ==================== ANTI-BUFF METHODS ====================
    def check_anti_buff(self, ip_address: str, referrer_id: int) -> Tuple[bool, str]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Kiểm tra IP bị block
            cursor.execute('SELECT * FROM banned_ips WHERE ip_address = ?', (ip_address,))
            if cursor.fetchone():
                return False, "🚫 IP của bạn đã bị cấm do gian lận!"
            
            # Kiểm tra anti-buff
            cursor.execute('SELECT * FROM anti_buff WHERE ip_address = ?', (ip_address,))
            buff_data = cursor.fetchone()
            
            if buff_data:
                if buff_data['is_blocked']:
                    block_until = self._parse_datetime(buff_data['block_until'])
                    if block_until and block_until > datetime.now():
                        remaining = (block_until - datetime.now()).seconds // 60
                        return False, f"⛔ IP đã bị chặn! Còn {remaining} phút."
                    elif block_until and block_until <= datetime.now():
                        cursor.execute('DELETE FROM anti_buff WHERE ip_address = ?', (ip_address,))
                
                # Kiểm tra số lượng refer
                if buff_data['referral_count'] >= MAX_REFS_PER_IP:
                    return False, f"⚠️ IP đã đạt giới hạn refer ({MAX_REFS_PER_IP})!"
                
                # Kiểm tra thời gian
                last_time = self._parse_datetime(buff_data['last_referral_time'])
                if last_time and (datetime.now() - last_time).seconds < REFERRAL_COOLDOWN:
                    remaining = REFERRAL_COOLDOWN - (datetime.now() - last_time).seconds
                    return False, f"⏳ Vui lòng đợi {remaining} giây giữa các lần refer!"
            
            return True, "OK"
    
    def mark_suspicious(self, user_id: int, reason: str):
        user = self.get_user(user_id)
        if user:
            user.warning_count += 1
            user.is_suspicious = user.warning_count >= 3
            self.update_user(user)
            
            if user.is_suspicious:
                self.ban_user(user_id, 24*60, f"Tự động ban do hành vi đáng ngờ: {reason}")
    
    def ban_user(self, user_id: int, minutes: int, reason: str = ""):
        user = self.get_user(user_id)
        if user:
            user.is_banned = True
            user.ban_until = datetime.now() + timedelta(minutes=minutes)
            self.update_user(user)
            
            # Log
            logger.warning(f"User {user_id} bị ban {minutes} phút. Lý do: {reason}")
    
    # ==================== DAILY REWARD METHODS ====================
    def claim_daily(self, user_id: int) -> Tuple[bool, int, int, str]:
        user = self.get_user(user_id)
        if not user:
            return False, 0, 0, "❌ User không tồn tại!"
        
        now = datetime.now()
        
        # Kiểm tra đã claim hôm nay chưa
        if user.daily_claim_time:
            last_claim = user.daily_claim_time
            if last_claim.date() == now.date():
                next_claim = datetime.combine(now.date(), datetime.min.time()) + timedelta(days=1)
                hours_left = (next_claim - now).seconds // 3600
                minutes_left = ((next_claim - now).seconds % 3600) // 60
                return False, 0, 0, f"⏳ Đã nhận hôm nay! Còn {hours_left}h {minutes_left}p"
        
        # Tính streak
        if user.daily_claim_time and user.daily_claim_time.date() == (now - timedelta(days=1)).date():
            user.daily_streak += 1
        else:
            user.daily_streak = 1
        
        # Tính thưởng
        base_reward = DAILY_COIN_REWARD
        streak_bonus = min(user.daily_streak * DAILY_STREAK_BONUS, 20)  # Max 20 bonus
        total_reward = base_reward + streak_bonus
        
        # Bonus đặc biệt cho streak
        if user.daily_streak == 7:
            total_reward += 10
            message = f"🎉 TUẦN THÀNH CÔNG! +10 Coin thưởng!"
        elif user.daily_streak == 30:
            total_reward += 50
            message = f"🏆 THÁNG THÀNH CÔNG! +50 Coin thưởng!"
        else:
            message = f"🔥 Streak {user.daily_streak} ngày!"
        
        # Cập nhật user
        user.balance += total_reward
        user.total_earned += total_reward
        user.daily_claim_time = now
        user.total_daily_claimed += 1
        self.update_user(user)
        
        # Thêm giao dịch
        self.add_transaction(
            user_id,
            total_reward,
            'daily',
            f'Daily reward (Streak: {user.daily_streak})',
            user.balance
        )
        
        # Lưu daily reward
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO daily_rewards (user_id, amount, streak_day)
                VALUES (?, ?, ?)
            ''', (user_id, total_reward, user.daily_streak))
        
        return True, total_reward, user.daily_streak, message
    
    # ==================== CAPTCHA METHODS ====================
    def save_captcha(self, user_id: int, code: str, image_path: str, challenge_type: str = "referral"):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO captcha (user_id, code, image_path, created_at, attempts, challenge_type)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, code, image_path, datetime.now().isoformat(), 0, challenge_type))
    
    def get_captcha(self, user_id: int) -> Optional[Dict]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM captcha WHERE user_id = ?', (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def update_captcha_attempts(self, user_id: int, attempts: int):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE captcha SET attempts = ? WHERE user_id = ?', (attempts, user_id))
    
    def delete_captcha(self, user_id: int):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Lấy thông tin trước khi xóa để còn xóa file ảnh
            cursor.execute('SELECT image_path FROM captcha WHERE user_id = ?', (user_id,))
            row = cursor.fetchone()
            image_path = None
            try:
                if row:
                    image_path = row['image_path']  # sqlite3.Row
            except Exception:
                try:
                    image_path = row[0] if row else None
                except Exception:
                    image_path = None

            cursor.execute('DELETE FROM captcha WHERE user_id = ?', (user_id,))

            # Xóa file ảnh
            if image_path and os.path.exists(image_path):
                try:
                    os.remove(image_path)
                except:
                    pass
    
    # ==================== ADMIN METHODS ====================
    def get_all_users(self, page: int = 1, limit: int = 20) -> Tuple[List[Dict], int]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Đếm tổng
            cursor.execute('SELECT COUNT(*) as total FROM users')
            total = cursor.fetchone()['total']
            
            # Lấy dữ liệu phân trang
            offset = (page - 1) * limit
            cursor.execute('''
                SELECT *, 
                    (SELECT COUNT(*) FROM referrals WHERE referrer_id = users.user_id) as total_referrals,
                    (SELECT COUNT(*) FROM transactions WHERE user_id = users.user_id) as total_transactions,
                    (SELECT SUM(amount) FROM transactions WHERE user_id = users.user_id AND amount > 0) as total_earned
                FROM users 
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            ''', (limit, offset))
            
            return [dict(row) for row in cursor.fetchall()], total
    
    def search_users(self, query: str) -> List[Dict]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM users 
                WHERE user_id LIKE ? OR username LIKE ? OR first_name LIKE ?
                ORDER BY created_at DESC
                LIMIT 20
            ''', (f'%{query}%', f'%{query}%', f'%{query}%'))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def is_admin(self, user_id: int) -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM admins WHERE user_id = ?', (user_id,))
            return cursor.fetchone() is not None
    
    def add_admin(self, user_id: int, added_by: int):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT OR IGNORE INTO admins (user_id, added_by) VALUES (?, ?)', (user_id, added_by))
    
    def remove_admin(self, user_id: int):
        if user_id != OWNER_ID:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM admins WHERE user_id = ?', (user_id,))
    
    def get_admins(self) -> List[Dict]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT a.*, u.username, u.first_name 
                FROM admins a
                JOIN users u ON a.user_id = u.user_id
            ''')
            return [dict(row) for row in cursor.fetchall()]
    
    # ==================== FILE METHODS ====================
    def add_user_file(self, user_id: int, file_name: str, file_type: str, file_size: int = 0):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO user_files (user_id, file_name, file_type, file_size, run_count)
                VALUES (?, ?, ?, ?, COALESCE((SELECT run_count + 1 FROM user_files WHERE user_id = ? AND file_name = ?), 0))
            ''', (user_id, file_name, file_type, file_size, user_id, file_name))
    
    def remove_user_file(self, user_id: int, file_name: str):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM user_files WHERE user_id = ? AND file_name = ?', (user_id, file_name))
    
    def get_user_files(self, user_id: int) -> List[Dict]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM user_files 
                WHERE user_id = ?
                ORDER BY last_started DESC
            ''', (user_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    def update_file_status(self, user_id: int, file_name: str, is_running: bool, process_id: int = None):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if is_running:
                cursor.execute('''
                    UPDATE user_files 
                    SET is_running = ?, process_id = ?, last_started = ?, run_count = run_count + 1
                    WHERE user_id = ? AND file_name = ?
                ''', (1 if is_running else 0, process_id, datetime.now().isoformat(), user_id, file_name))
            else:
                cursor.execute('''
                    UPDATE user_files 
                    SET is_running = ?, process_id = NULL, last_stopped = ?
                    WHERE user_id = ? AND file_name = ?
                ''', (0, datetime.now().isoformat(), user_id, file_name))
    

    # ==================== PIN/TREO METHODS ====================
    def get_user_file(self, user_id: int, file_name: str) -> Optional[Dict]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM user_files
                WHERE user_id = ? AND file_name = ?
            ''', (user_id, file_name))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_file_pinned_until(self, user_id: int, file_name: str) -> Optional[datetime]:
        info = self.get_user_file(user_id, file_name)
        if not info:
            return None
        return self._parse_datetime(info.get('pinned_until'))

    def set_file_pin(self, user_id: int, file_name: str, until: Optional[datetime], pinned_by: Optional[int] = None):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if until:
                cursor.execute('''
                    UPDATE user_files
                    SET pinned_until = ?, pinned_by = ?, pinned_at = ?
                    WHERE user_id = ? AND file_name = ?
                ''', (until.isoformat(), pinned_by, datetime.now().isoformat(), user_id, file_name))
            else:
                cursor.execute('''
                    UPDATE user_files
                    SET pinned_until = NULL, pinned_by = NULL, pinned_at = NULL
                    WHERE user_id = ? AND file_name = ?
                ''', (user_id, file_name))

    def clear_file_pin(self, user_id: int, file_name: str):
        self.set_file_pin(user_id, file_name, None, None)

    def get_pinned_files(self, limit: int = 20, page: int = 1) -> Tuple[List[Dict], int]:
        """Danh sách file đang treo (pinned) để admin quản lý."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now().isoformat()

            cursor.execute('''
                SELECT COUNT(*) as total
                FROM user_files
                WHERE pinned_until IS NOT NULL AND pinned_until > ?
            ''', (now,))
            total = cursor.fetchone()['total']

            offset = (page - 1) * limit
            cursor.execute('''
                SELECT uf.*, u.username, u.first_name
                FROM user_files uf
                LEFT JOIN users u ON uf.user_id = u.user_id
                WHERE uf.pinned_until IS NOT NULL AND uf.pinned_until > ?
                ORDER BY uf.pinned_until DESC
                LIMIT ? OFFSET ?
            ''', (now, limit, offset))

            return [dict(row) for row in cursor.fetchall()], total

    # ==================== ACTIVE USERS ====================
    def add_active_user(self, user_id: int):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO active_users (user_id, last_seen)
                VALUES (?, ?)
            ''', (user_id, datetime.now().isoformat()))
    
    def get_active_users(self, minutes: int = 60) -> List[int]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT user_id FROM active_users 
                WHERE last_seen > datetime('now', ?)
            ''', (f'-{minutes} minutes',))
            return [row['user_id'] for row in cursor.fetchall()]
    
    def get_statistics(self) -> Dict:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            stats = {}
            
            # Tổng users
            cursor.execute('SELECT COUNT(*) as total FROM users')
            stats['total_users'] = cursor.fetchone()['total']
            
            # Users active hôm nay
            cursor.execute('''
                SELECT COUNT(*) as total FROM users 
                WHERE last_active > datetime('now', '-1 day')
            ''')
            stats['active_today'] = cursor.fetchone()['total']
            
            # Users mới hôm nay
            cursor.execute('''
                SELECT COUNT(*) as total FROM users 
                WHERE created_at > datetime('now', '-1 day')
            ''')
            stats['new_today'] = cursor.fetchone()['total']
            
            # Tổng coin
            cursor.execute('SELECT SUM(balance) as total FROM users')
            stats['total_coins'] = cursor.fetchone()['total'] or 0
            
            # Tổng referrals
            cursor.execute('SELECT COUNT(*) as total FROM referrals WHERE status = "completed"')
            stats['total_referrals'] = cursor.fetchone()['total']
            
            # Scripts đang chạy
            cursor.execute('SELECT COUNT(*) as total FROM user_files WHERE is_running = 1')
            stats['running_scripts'] = cursor.fetchone()['total']
            
            # Users bị ban
            cursor.execute('SELECT COUNT(*) as total FROM users WHERE is_banned = 1')
            stats['banned_users'] = cursor.fetchone()['total']
            
            return stats

# ==================== KHỞI TẠO DATABASE ====================
db = DatabaseManager()

# ==================== CAPTCHA MANAGER NÂNG CAO ====================
class CaptchaManager:
    def __init__(self):
        self.active_captchas: Dict[int, CaptchaData] = {}
        self.lock = threading.RLock()
        self.font_path = self._get_font()
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
    
    def _get_font(self):
        fonts = [
            '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
            '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf',
            '/System/Library/Fonts/Helvetica.ttc',
            'C:\\Windows\\Fonts\\Arial.ttf',
            'C:\\Windows\\Fonts\\segoeui.ttf'
        ]
        for font in fonts:
            if os.path.exists(font):
                return font
        return None
    
    def _cleanup_loop(self):
        while True:
            time.sleep(300)  # 5 phút
            with self.lock:
                now = datetime.now()
                expired = []
                for user_id, captcha in self.active_captchas.items():
                    if now - captcha.created_at > timedelta(minutes=5):
                        expired.append(user_id)
                
                for user_id in expired:
                    self._cleanup_captcha(user_id)
    
    def generate_captcha(self, user_id: int, challenge_type: str = "referral") -> Tuple[str, str]:
        with self.lock:
            self._cleanup_captcha(user_id)
            
            # Tạo mã captcha
            code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            
            # Tạo ảnh với nhiều hiệu ứng
            width, height = 400, 150
            image = Image.new('RGB', (width, height), color=(255, 255, 255))
            draw = ImageDraw.Draw(image)
            
            # Vẽ background gradient
            for i in range(height):
                color = (255 - i//2, 255 - i//3, 255)
                draw.line([(0, i), (width, i)], fill=color)
            
            # Vẽ nhiễu
            for _ in range(random.randint(10, 20)):
                x1 = random.randint(0, width)
                y1 = random.randint(0, height)
                x2 = random.randint(0, width)
                y2 = random.randint(0, height)
                draw.line([(x1, y1), (x2, y2)], fill=(random.randint(150, 200),) * 3, width=random.randint(1, 2))
            
            # Vẽ chấm nhiễu
            for _ in range(random.randint(200, 300)):
                x = random.randint(0, width)
                y = random.randint(0, height)
                draw.point((x, y), fill=(random.randint(100, 200),) * 3)
            
            # Vẽ text xoay
            try:
                if self.font_path:
                    font_size = random.randint(40, 50)
                    font = ImageFont.truetype(self.font_path, font_size)
                else:
                    font = ImageFont.load_default()
                
                chars = list(code)
                x = random.randint(30, 50)
                y_base = random.randint(40, 60)
                
                for i, char in enumerate(chars):
                    # Tạo ảnh riêng cho từng chữ để xoay
                    char_img = Image.new('RGBA', (50, 70), (255, 255, 255, 0))
                    char_draw = ImageDraw.Draw(char_img)
                    
                    # Màu ngẫu nhiên
                    color = (
                        random.randint(0, 100),
                        random.randint(0, 100),
                        random.randint(0, 100)
                    )
                    
                    char_draw.text((10, 10), char, fill=color, font=font)
                    
                    # Xoay chữ
                    angle = random.randint(-30, 30)
                    rotated = char_img.rotate(angle, expand=1, fillcolor=(255, 255, 255, 0))
                    
                    # Dán vào ảnh chính
                    y_offset = random.randint(-10, 10)
                    image.paste(rotated, (x, y_base + y_offset), rotated)
                    x += rotated.width - random.randint(5, 15)
                
            except Exception as e:
                logger.error(f"Lỗi vẽ captcha: {e}")
                draw.text((50, 50), code, fill=(0, 0, 0), font=ImageFont.load_default())
            
            # Thêm filter làm mờ nhẹ
            image = image.filter(ImageFilter.GaussianBlur(radius=0.5))
            
            # Lưu ảnh
            image_path = os.path.join(CAPTCHA_DIR, f"captcha_{user_id}_{int(time.time())}_{random.randint(1000, 9999)}.png")
            image.save(image_path, 'PNG', optimize=True)
            
            # Lưu vào database
            db.save_captcha(user_id, code, image_path, challenge_type)
            
            # Lưu cache
            self.active_captchas[user_id] = CaptchaData(
                user_id=user_id,
                code=code,
                image_path=image_path,
                created_at=datetime.now(),
                attempts=0,
                challenge_type=challenge_type
            )
            
            return code, image_path
    
    def verify_captcha(self, user_id: int, input_code: str) -> Tuple[bool, str, Optional[str]]:
        with self.lock:
            # Lấy từ cache
            captcha_data = self.active_captchas.get(user_id)
            
            if not captcha_data:
                # Lấy từ database
                captcha_db = db.get_captcha(user_id)
                if captcha_db:
                    captcha_data = CaptchaData(
                        user_id=user_id,
                        code=captcha_db['code'],
                        image_path=captcha_db['image_path'],
                        created_at=datetime.fromisoformat(captcha_db['created_at']),
                        attempts=captcha_db['attempts'],
                        challenge_type=captcha_db.get('challenge_type', 'referral')
                    )
                    self.active_captchas[user_id] = captcha_data
                else:
                    return False, "❌ Không tìm thấy captcha. Vui lòng thử lại!", None
            
            # Kiểm tra thời gian
            if datetime.now() - captcha_data.created_at > timedelta(minutes=5):
                self._cleanup_captcha(user_id)
                return False, "⏰ Captcha đã hết hạn. Vui lòng thử lại!", None
            
            # Tăng số lần thử
            captcha_data.attempts += 1
            db.update_captcha_attempts(user_id, captcha_data.attempts)
            
            # Kiểm tra số lần thử
            remaining = CAPTCHA_ATTEMPTS - captcha_data.attempts
            if captcha_data.attempts > CAPTCHA_ATTEMPTS:
                challenge_type = captcha_data.challenge_type
                self._cleanup_captcha(user_id)
                
                # Ban user
                user = db.get_user(user_id) or db.create_user(user_id)
                user.is_banned = True
                user.ban_until = datetime.now() + timedelta(minutes=CAPTCHA_BAN_TIME)
                db.update_user(user)
                
                return False, f"🚫 Bạn đã nhập sai {CAPTCHA_ATTEMPTS} lần. Bị cấm trong {CAPTCHA_BAN_TIME} phút!", challenge_type
            
            # So sánh mã
            if input_code.upper() == captcha_data.code:
                challenge_type = captcha_data.challenge_type
                self._cleanup_captcha(user_id)
                return True, "✅ Xác thực thành công!", challenge_type
            
            return False, f"❌ Sai mã! Còn {remaining} lần thử.", captcha_data.challenge_type
    
    def _cleanup_captcha(self, user_id: int):
        if user_id in self.active_captchas:
            try:
                if os.path.exists(self.active_captchas[user_id].image_path):
                    os.remove(self.active_captchas[user_id].image_path)
            except:
                pass
            del self.active_captchas[user_id]
        db.delete_captcha(user_id)

# ==================== KHỞI TẠO CAPTCHA ====================
captcha_manager = CaptchaManager()

# ==================== BOT SCRIPT MANAGER NÂNG CAO ====================
class BotScriptManager:
    def __init__(self):
        self.running_scripts: Dict[str, Dict] = {}
        self.lock = threading.RLock()
        # lưu lịch sử auto-restart để chống loop crash
        self.restart_history: Dict[str, deque] = defaultdict(deque)
        self.monitor_thread = threading.Thread(target=self._monitor_scripts, daemon=True)
        self.monitor_thread.start()

    def _restart_allowed(self, script_key: str, max_restarts: int = 5, window_seconds: int = 600) -> bool:
        """Giới hạn auto-restart để tránh loop crash."""
        now = time.time()
        dq = self.restart_history[script_key]
        while dq and now - dq[0] > window_seconds:
            dq.popleft()
        if len(dq) >= max_restarts:
            return False
        dq.append(now)
        return True

    def _spawn_script_process(self, script_path: str, user_id: int, folder: str, file_name: str, script_type: str, reason: str = "") -> bool:
        """Spawn process (không gửi reply). Dùng cho auto-restart."""
        try:
            if not os.path.exists(script_path):
                return False

            if self.is_running(user_id, file_name):
                return False

            # Tạo file log
            log_path = os.path.join(folder, f"{os.path.splitext(file_name)[0]}.log")
            log_file = open(log_path, 'a', encoding='utf-8', errors='ignore')
            tag = "AUTO-RESTART" if reason else "BẮT ĐẦU"
            log_file.write(f"\n--- {tag} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {reason} ---\n")
            log_file.flush()

            # Chạy script
            startupinfo = None
            creationflags = 0
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                creationflags = subprocess.CREATE_NO_WINDOW

            cmd = [sys.executable, script_path] if script_type == 'py' else ['node', script_path]
            process = subprocess.Popen(
                cmd,
                cwd=folder,
                stdout=log_file,
                stderr=log_file,
                stdin=subprocess.PIPE,
                startupinfo=startupinfo,
                encoding='utf-8',
                errors='ignore',
                creationflags=creationflags
            )

            script_key = f"{user_id}_{file_name}"
            with self.lock:
                self.running_scripts[script_key] = {
                    'process': process,
                    'log_file': log_file,
                    'file_name': file_name,
                    'user_id': user_id,
                    'start_time': datetime.now(),
                    'folder': folder,
                    'type': script_type,
                    'pid': process.pid
                }

            db.update_file_status(user_id, file_name, True, process.pid)
            return True
        except Exception as e:
            logger.error(f"Lỗi spawn process {user_id}_{file_name}: {e}")
            return False

    def _maybe_auto_restart(self, script_key: str, last_info: Dict):
        """Nếu file đang TREO còn hạn -> tự restart khi crash."""
        try:
            user_id = last_info.get('user_id')
            file_name = last_info.get('file_name')
            folder = last_info.get('folder') or os.path.join(UPLOAD_BOTS_DIR, str(user_id))
            script_type = last_info.get('type') or ('py' if str(file_name).endswith('.py') else 'js')

            if not user_id or not file_name:
                return

            # kiểm tra treo còn hạn
            pin_until = db.get_file_pinned_until(user_id, file_name)
            if not pin_until or pin_until <= datetime.now():
                return

            script_path = os.path.join(folder, file_name)
            if not os.path.exists(script_path):
                # file mất -> hủy treo
                try:
                    db.clear_file_pin(user_id, file_name)
                except Exception:
                    pass
                return

            if not self._restart_allowed(script_key):
                try:
                    bot.send_message(
                        user_id,
                        f"⚠️ Script `{file_name}` đang TREO bị crash liên tục. Hệ thống tạm dừng auto-restart.\n👉 Vui lòng xem Logs và chạy lại thủ công.",
                        parse_mode='Markdown'
                    )
                except Exception:
                    pass
                return

            ok = self._spawn_script_process(script_path, user_id, folder, file_name, script_type, reason="(TREO)")
            if ok:
                try:
                    bot.send_message(
                        user_id,
                        f"♻️ Auto-restart: Script `{file_name}` đã được chạy lại (do đang TREO).",
                        parse_mode='Markdown'
                    )
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"Lỗi auto restart {script_key}: {e}")

    def _monitor_scripts(self):
        while True:
            time.sleep(10)
            ended: List[Tuple[str, Dict]] = []

            with self.lock:
                for script_key, script_info in list(self.running_scripts.items()):
                    try:
                        proc = script_info.get('process')
                        if not proc:
                            ended.append((script_key, script_info))
                            continue

                        # proc.poll() != None nghĩa là đã kết thúc
                        if proc.poll() is not None:
                            ended.append((script_key, script_info))
                            continue

                        p = psutil.Process(proc.pid)
                        if (not p.is_running()) or p.status() == psutil.STATUS_ZOMBIE:
                            ended.append((script_key, script_info))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        ended.append((script_key, script_info))
                    except Exception:
                        ended.append((script_key, script_info))

                # Cleanup trong lock (đóng log + remove dict)
                for k, info in ended:
                    try:
                        try:
                            self._kill_process_tree(info)
                        except Exception:
                            pass
                        self._cleanup_script(k)
                    except Exception:
                        pass

            # cập nhật DB + auto-restart ngoài lock
            for k, info in ended:
                try:
                    db.update_file_status(info.get('user_id'), info.get('file_name'), False)
                except Exception:
                    pass
                self._maybe_auto_restart(k, info)

    def is_running(self, user_id: int, file_name: str) -> bool:
        script_key = f"{user_id}_{file_name}"
        with self.lock:
            return script_key in self.running_scripts
    
    def run_python_script(self, script_path: str, user_id: int, folder: str, 
                          file_name: str, message) -> bool:
        script_key = f"{user_id}_{file_name}"
        
        try:
            if not os.path.exists(script_path):
                return False
            
            if self.is_running(user_id, file_name):
                bot.reply_to(message, "⚠️ Script đang chạy!")
                return False
            
            # Kiểm tra và cài đặt dependencies
            if not self._check_python_deps(script_path, folder, message):
                return False
            
            # Tạo file log
            log_path = os.path.join(folder, f"{os.path.splitext(file_name)[0]}.log")
            log_file = open(log_path, 'a', encoding='utf-8', errors='ignore')
            log_file.write(f"\n--- BẮT ĐẦU CHẠY {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
            log_file.flush()
            
            # Chạy script
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            process = subprocess.Popen(
                [sys.executable, script_path],
                cwd=folder,
                stdout=log_file,
                stderr=log_file,
                stdin=subprocess.PIPE,
                startupinfo=startupinfo,
                encoding='utf-8',
                errors='ignore',
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            with self.lock:
                self.running_scripts[script_key] = {
                    'process': process,
                    'log_file': log_file,
                    'file_name': file_name,
                    'user_id': user_id,
                    'start_time': datetime.now(),
                    'folder': folder,
                    'type': 'py',
                    'pid': process.pid
                }
            
            db.update_file_status(user_id, file_name, True, process.pid)
            
            # Gửi thông báo
            bot.reply_to(
                message,
                f"✅ **Đã chạy script Python**\n\n"
                f"📄 **File:** `{file_name}`\n"
                f"🆔 **PID:** `{process.pid}`\n"
                f"👤 **User:** `{user_id}`\n"
                f"📝 **Log:** Xem trong menu quản lý",
                parse_mode='Markdown'
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Lỗi chạy Python script {script_key}: {e}")
            bot.reply_to(message, f"❌ Lỗi khi chạy script: {str(e)}")
            return False
    
    def run_js_script(self, script_path: str, user_id: int, folder: str,
                      file_name: str, message) -> bool:
        script_key = f"{user_id}_{file_name}"
        
        try:
            if not os.path.exists(script_path):
                return False
            
            if self.is_running(user_id, file_name):
                bot.reply_to(message, "⚠️ Script đang chạy!")
                return False
            
            # Kiểm tra Node.js
            if not self._check_node_installed():
                bot.reply_to(message, "❌ Node.js chưa được cài đặt!")
                return False
            
            # Kiểm tra và cài đặt dependencies
            if not self._check_node_deps(folder, message):
                return False
            
            # Tạo file log
            log_path = os.path.join(folder, f"{os.path.splitext(file_name)[0]}.log")
            log_file = open(log_path, 'a', encoding='utf-8', errors='ignore')
            log_file.write(f"\n--- BẮT ĐẦU CHẠY {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
            log_file.flush()
            
            # Chạy script
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            process = subprocess.Popen(
                ['node', script_path],
                cwd=folder,
                stdout=log_file,
                stderr=log_file,
                stdin=subprocess.PIPE,
                startupinfo=startupinfo,
                encoding='utf-8',
                errors='ignore',
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            with self.lock:
                self.running_scripts[script_key] = {
                    'process': process,
                    'log_file': log_file,
                    'file_name': file_name,
                    'user_id': user_id,
                    'start_time': datetime.now(),
                    'folder': folder,
                    'type': 'js',
                    'pid': process.pid
                }
            
            db.update_file_status(user_id, file_name, True, process.pid)
            
            bot.reply_to(
                message,
                f"✅ **Đã chạy script JavaScript**\n\n"
                f"📄 **File:** `{file_name}`\n"
                f"🆔 **PID:** `{process.pid}`\n"
                f"👤 **User:** `{user_id}`\n"
                f"📝 **Log:** Xem trong menu quản lý",
                parse_mode='Markdown'
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Lỗi chạy JS script {script_key}: {e}")
            bot.reply_to(message, f"❌ Lỗi khi chạy script: {str(e)}")
            return False
    
    def stop_script(self, user_id: int, file_name: str) -> bool:
        script_key = f"{user_id}_{file_name}"
        
        with self.lock:
            if script_key in self.running_scripts:
                script_info = self.running_scripts[script_key]
                
                # Ghi log kết thúc
                try:
                    if 'log_file' in script_info:
                        script_info['log_file'].write(
                            f"\n--- DỪNG LÚC {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n"
                        )
                        script_info['log_file'].flush()
                except:
                    pass
                
                # Kill process
                self._kill_process_tree(script_info)
                
                # Dọn dẹp
                self._cleanup_script(script_key)
                db.update_file_status(user_id, file_name, False)
                return True
        
        return False

    def _check_python_deps(self, script_path: str, folder: str, message) -> bool:
        """Kiểm tra import trong script và cài pip an toàn khi thiếu thư viện.

        - Có timeout để tránh treo
        - Dùng --no-cache-dir để giảm RAM/Disk (hạn chế OOM)
        - Báo lỗi rõ ràng thay vì làm bot crash
        """
        try:
            with open(script_path, 'r', encoding='utf-8', errors='ignore') as f:
                file_content = f.read()
        except Exception as e:
            bot.reply_to(message, f"❌ Không đọc được file script: {e}")
            return False

        try:
            imports = re.findall(r'^import (\w+)|^from (\w+) import', file_content, re.MULTILINE)
            modules = set()
            for imp in imports:
                mod = imp[0] or imp[1]
                if mod:
                    modules.add(mod)

            core_modules = {
                'os', 'sys', 'time', 'datetime', 'json', 're', 'math',
                'random', 'threading', 'subprocess', 'logging', 'traceback',
                'collections', 'functools', 'itertools', 'copy', 'enum',
                'typing', 'dataclasses', 'contextlib', 'queue', 'hashlib'
            }

            for module in modules:
                if module in core_modules:
                    continue

                try:
                    __import__(module)
                except ImportError:
                    package = self._get_pip_package(module)
                    if not package:
                        bot.reply_to(
                            message,
                            f"⚠️ Thiếu module `{module}` nhưng không xác định được pip package. "
                            f"Hãy cài thủ công hoặc thêm vào requirements.txt."
                        )
                        return False

                    bot.reply_to(message, f"📦 Thiếu thư viện `{package}`. Đang cài đặt...")

                    try:
                        result = subprocess.run(
                            [
                                sys.executable, '-m', 'pip', 'install',
                                '--disable-pip-version-check',
                                '--no-cache-dir',
                                '--user', package
                            ],
                            capture_output=True,
                            text=True,
                            timeout=300
                        )
                    except subprocess.TimeoutExpired:
                        bot.reply_to(
                            message,
                            f"⏱️ Cài `{package}` quá lâu (timeout). "
                            f"Hãy thử lại hoặc thêm `{package}` vào requirements.txt."
                        )
                        return False
                    except Exception as e:
                        bot.reply_to(message, f"❌ Lỗi khi cài `{package}`: {e}")
                        return False

                    if result.returncode != 0:
                        err = (result.stderr or result.stdout or '').strip()
                        if len(err) > 1200:
                            err = err[-1200:]
                        bot.reply_to(
                            message,
                            f"❌ Không cài được `{package}`.\n"
                            f"🧾 Log (rút gọn):\n{err or 'No stderr'}"
                        )
                        logger.error(f"Pip error ({package}): {result.stderr}")
                        return False

            return True

        except Exception as e:
            logger.error(f"Lỗi kiểm tra dependencies: {e}", exc_info=True)
            bot.reply_to(message, f"❌ Lỗi kiểm tra thư viện: {e}")
            return False

    def _check_node_deps(self, folder: str, message) -> bool:
        package_json = os.path.join(folder, 'package.json')
        
        if os.path.exists(package_json):
            bot.reply_to(message, "📦 Đang cài đặt Node.js dependencies...")
            
            result = subprocess.run(
                ['npm', 'install', '--no-fund', '--no-audit'],
                cwd=folder,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                bot.reply_to(message, f"❌ Lỗi cài đặt npm packages")
                logger.error(f"NPM error: {result.stderr}")
                return False
        
        return True
    
    def _check_node_installed(self) -> bool:
        try:
            result = subprocess.run(['node', '--version'], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def _get_pip_package(self, module: str) -> str:
        package_map = {
            'telebot': 'pyTelegramBotAPI',
            'telegram': 'python-telegram-bot',
            'aiogram': 'aiogram',
            'pyrogram': 'pyrogram',
            'telethon': 'telethon',
            'requests': 'requests',
            'bs4': 'beautifulsoup4',
            'pillow': 'Pillow',
            'PIL': 'Pillow',
            'cv2': 'opencv-python',
            'numpy': 'numpy',
            'pandas': 'pandas',
            'flask': 'Flask',
            'django': 'Django',
            'psutil': 'psutil',
            'aiohttp': 'aiohttp',
            'asyncpg': 'asyncpg',
            'redis': 'redis',
            'pymongo': 'pymongo',
            'sqlalchemy': 'sqlalchemy',
            'discord': 'discord.py',
            'selenium': 'selenium',
            'beautifulsoup': 'beautifulsoup4',
            'matplotlib': 'matplotlib',
            'scipy': 'scipy',
            'sklearn': 'scikit-learn',
            'tensorflow': 'tensorflow',
            'torch': 'torch',
            'transformers': 'transformers',
        }
        return package_map.get(module, module)
    
    def _kill_process_tree(self, script_info: Dict):
        try:
            if 'log_file' in script_info:
                try:
                    script_info['log_file'].close()
                except:
                    pass
            
            process = script_info.get('process')
            if process and process.pid:
                try:
                    parent = psutil.Process(process.pid)
                    children = parent.children(recursive=True)
                    
                    for child in children:
                        try:
                            child.kill()
                        except:
                            pass
                    
                    parent.kill()
                    parent.wait(timeout=3)
                    
                except psutil.NoSuchProcess:
                    pass
                except psutil.TimeoutExpired:
                    try:
                        parent.kill()
                    except:
                        pass
                    
        except Exception as e:
            logger.error(f"Lỗi kill process: {e}")
    
    def _cleanup_script(self, script_key: str):
        if script_key in self.running_scripts:
            script_info = self.running_scripts[script_key]
            try:
                if 'log_file' in script_info:
                    script_info['log_file'].close()
            except:
                pass
            del self.running_scripts[script_key]
    
    def get_logs(self, user_id: int, file_name: str, lines: int = 100) -> Optional[str]:
        folder = get_user_folder(user_id)
        log_path = os.path.join(folder, f"{os.path.splitext(file_name)[0]}.log")
        
        if os.path.exists(log_path):
            try:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.readlines()
                    
                    # Lấy N dòng cuối
                    if len(content) > lines:
                        content = content[-lines:]
                    
                    result = ''.join(content)
                    
                    # Giới hạn độ dài
                    if len(result) > 3500:
                        result = "...\n" + result[-3500:]
                    
                    return result
            except Exception as e:
                return f"❌ Không thể đọc file log: {e}"
        
        return "📭 Chưa có logs"
    
    def get_all_running(self) -> List[Dict]:
        running = []
        with self.lock:
            for script_key, script_info in list(self.running_scripts.items()):
                running.append({
                    'user_id': script_info['user_id'],
                    'file_name': script_info['file_name'],
                    'type': script_info['type'],
                    'start_time': script_info['start_time'],
                    'pid': script_info.get('pid')
                })
        return running
    
    def get_stats(self) -> Dict:
        with self.lock:
            return {
                'total_running': len(self.running_scripts),
                'python': sum(1 for s in self.running_scripts.values() if s['type'] == 'py'),
                'javascript': sum(1 for s in self.running_scripts.values() if s['type'] == 'js'),
                'scripts': [
                    {
                        'user_id': s['user_id'],
                        'file': s['file_name'],
                        'type': s['type'],
                        'uptime': (datetime.now() - s['start_time']).seconds // 60
                    }
                    for s in self.running_scripts.values()
                ]
            }

# ==================== KHỞI TẠO SCRIPT MANAGER ====================
script_manager = BotScriptManager()

# ==================== ANTI-SPAM & FILE SECURITY ====================
class SpamProtector:
    """Chống spam cơ bản (in-memory).

    - Giới hạn callback spam và upload spam.
    - Tăng mức phạt nếu vi phạm liên tục.
    """
    def __init__(self):
        self._actions = defaultdict(deque)  # (user_id, key) -> deque[timestamps]
        self._violations = defaultdict(int)  # user_id -> count
        self._lock = threading.RLock()

    def check(self, user_id: int, key: str, limit: int, window_seconds: int, ban_minutes: int = SPAM_PENALTY_MINUTES) -> Tuple[bool, str]:
        now = time.time()
        k = (user_id, key)

        with self._lock:
            dq = self._actions[k]
            # clear old
            while dq and now - dq[0] > window_seconds:
                dq.popleft()

            if len(dq) >= limit:
                self._violations[user_id] += 1
                vio = self._violations[user_id]

                # Phạt tăng dần
                if vio >= 3:
                    try:
                        db.ban_user(user_id, ban_minutes, f"Auto-ban spam ({key})")
                    except Exception:
                        pass
                    return False, f"🚫 Spam quá nhanh! Bạn bị ban tạm {ban_minutes} phút."

                wait = max(1, window_seconds - int(now - dq[0])) if dq else window_seconds
                return False, f"⚠️ Bạn thao tác quá nhanh! Đợi {wait}s rồi thử lại."

            dq.append(now)
            return True, ""


class FileSecurityScanner:
    """Quét heuristic để chặn file có dấu hiệu botnet/virus.

    Lưu ý: Đây là lớp phòng thủ cơ bản, tránh tải/host các file có hành vi nguy hiểm rõ ràng.
    """

    # Các đuôi file nguy hiểm/không cần thiết cho hệ thống host .py/.js
    BLOCK_EXTS = {
        '.exe', '.dll', '.so', '.dylib', '.bin', '.elf', '.apk', '.ipa',
        '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.jar', '.com', '.msi'
    }

    # Pattern nguy hiểm (ưu tiên chặn những hành vi download & execute, miner, ddos)
    HIGH_RISK_PATTERNS = [
        # download & execute
        r"\b(curl|wget)\b[^\n]{0,200}\b(sh|bash)\b",
        r"\b(curl|wget)\b[^\n]{0,200}\|\s*(sh|bash)\b",
        r"\bchmod\s*\+x\b[^\n]{0,120}\b(\./|/tmp/)\S+",
        r"\b(/tmp/|/var/tmp/)\S+\b",

        # reverse shell common
        r"\b(nc|netcat)\b[^\n]{0,120}\s-\s*e\b",
        r"\b/bash\s+-i\b",
        r"\b0\.0\.0\.0\b\s*:\s*\d{2,5}",

        # miner keywords
        r"\b(xmrig|minerd|stratum\+tcp|cryptonight|monero)\b",

        # ddos keywords
        r"\b(udp\s*flood|syn\s*flood|http\s*flood|ddos)\b",

        # destructive commands
        r"\brm\s+-rf\s+/\b",
        r"\bmkfs\.",
        r"\bdd\s+if=",
    ]

    MEDIUM_RISK_PATTERNS = [
        r"\bchild_process\.(exec|spawn)\b",
        r"\bos\.system\b",
        r"\bsubprocess\.(Popen|call|run)\b",
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bbase64\.b64decode\b",
        r"\bFunction\s*\(",
    ]

    BASE64_LONG_RE = re.compile(r"[A-Za-z0-9+/]{800,}={0,2}")

    def __init__(self):
        self._high = [re.compile(p, re.IGNORECASE) for p in self.HIGH_RISK_PATTERNS]
        self._medium = [re.compile(p, re.IGNORECASE) for p in self.MEDIUM_RISK_PATTERNS]

    def _is_binary(self, data: bytes) -> bool:
        # Null byte thường là binary
        if b'\x00' in data:
            return True
        # Heuristic: tỷ lệ ký tự không in được
        sample = data[:4096]
        if not sample:
            return False
        nontext = sum(1 for b in sample if b < 9 or (b > 13 and b < 32))
        return (nontext / len(sample)) > 0.30

    def scan_bytes(self, file_name: str, data: bytes) -> Tuple[bool, str]:
        ext = os.path.splitext(file_name)[1].lower()

        if ext in self.BLOCK_EXTS:
            return False, f"🚫 File bị chặn do định dạng nguy hiểm: {ext}"

        # Chỉ quét nội dung text cơ bản
        if ext in {'.py', '.js', '.txt', '.md', '.json', '.yml', '.yaml', '.ini', '.cfg', '.env'}:
            if self._is_binary(data):
                return False, "🚫 File có dấu hiệu binary/đính kèm mã độc."

            try:
                content = data[:VIRUS_SCAN_MAX_BYTES].decode('utf-8', errors='ignore')
            except Exception:
                content = str(data[:VIRUS_SCAN_MAX_BYTES])

            # Base64 dài bất thường
            if self.BASE64_LONG_RE.search(content):
                # không chắc độc, nhưng thường dùng để che payload
                return False, "🚫 Phát hiện chuỗi Base64 rất dài (nguy cơ payload ẩn)."

            for rgx in self._high:
                if rgx.search(content):
                    return False, "🚫 Phát hiện mẫu hành vi nguy hiểm (botnet/virus/miner)."

            # Medium risk: chỉ cảnh báo nếu nhiều pattern
            medium_hits = sum(1 for rgx in self._medium if rgx.search(content))
            if medium_hits >= 3:
                return False, "🚫 Script chứa nhiều hành vi nguy hiểm (exec/subprocess/eval...)."

            return True, ""

        # File khác (ảnh, font...) cho phép, nhưng không chạy
        return True, ""

    def scan_zip_safely(self, zip_path: str) -> Tuple[bool, str]:
        """Quét zip: chống zip bomb + chặn file nguy hiểm + quét sơ nội dung file text."""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                infos = zf.infolist()
                if len(infos) > MAX_ZIP_FILE_COUNT:
                    return False, f"🚫 Zip quá nhiều file ({len(infos)}), nghi zip-bomb."

                total_size = sum(i.file_size for i in infos)
                if total_size > MAX_ZIP_EXTRACT_MB * 1024 * 1024:
                    return False, f"🚫 Zip giải nén vượt {MAX_ZIP_EXTRACT_MB}MB (nghi zip-bomb)."

                for i in infos:
                    name = i.filename
                    ext = os.path.splitext(name)[1].lower()
                    if ext in self.BLOCK_EXTS:
                        return False, f"🚫 Zip chứa file nguy hiểm: {name}"

                    # Quét nhanh file text nhỏ
                    if ext in {'.py', '.js', '.txt', '.md', '.json', '.yml', '.yaml', '.ini', '.cfg', '.env'} and i.file_size <= VIRUS_SCAN_MAX_BYTES:
                        try:
                            with zf.open(i, 'r') as fp:
                                data = fp.read(VIRUS_SCAN_MAX_BYTES)
                            ok, msg = self.scan_bytes(name, data)
                            if not ok:
                                return False, msg + f" (trong zip: {name})"
                        except Exception:
                            # Nếu không đọc được thì bỏ qua quét nội dung, vẫn an toàn vì đã chặn ext nguy hiểm
                            pass

            return True, ""
        except zipfile.BadZipFile:
            return False, "🚫 Zip lỗi/không hợp lệ."
        except Exception as e:
            return False, f"🚫 Không quét được zip: {e}"


spam_protector = SpamProtector()
file_scanner = FileSecurityScanner()

# ==================== HÀM TIỆN ÍCH ====================
def get_user_folder(user_id: int) -> str:
    folder = os.path.join(UPLOAD_BOTS_DIR, str(user_id))
    os.makedirs(folder, exist_ok=True)
    return folder

def sanitize_filename(file_name: str) -> str:
    """Chống path traversal, chuẩn hóa tên file."""
    if not file_name:
        return ""
    # bỏ đường dẫn nếu có
    file_name = os.path.basename(file_name)
    # thay ký tự nguy hiểm
    file_name = file_name.replace('\x00', '')
    file_name = file_name.replace('/', '_').replace('\\', '_')
    # giới hạn độ dài để tránh callback_data quá dài / FS issues
    if len(file_name) > 120:
        base, ext = os.path.splitext(file_name)
        file_name = base[:100] + ext
    return file_name

def parse_iso_datetime(val) -> Optional[datetime]:
    try:
        if not val:
            return None
        return datetime.fromisoformat(val)
    except Exception:
        return None

def is_pin_active(pin_until: Optional[datetime]) -> bool:
    return bool(pin_until and pin_until > datetime.now())

def pin_remaining_days(pin_until: Optional[datetime]) -> int:
    if not pin_until:
        return 0
    diff = pin_until - datetime.now()
    if diff.total_seconds() <= 0:
        return 0
    # làm tròn lên theo ngày
    return int((diff.total_seconds() + 86399) // 86400)


def get_user_file_limit(user_id: int) -> float:
    user = db.get_user(user_id)
    
    if user_id == OWNER_ID:
        return OWNER_LIMIT
    
    if db.is_admin(user_id):
        return ADMIN_LIMIT
    
    if user and user.subscription_expiry and user.subscription_expiry > datetime.now():
        return SUBSCRIBED_USER_LIMIT
    
    return FREE_USER_LIMIT

def get_user_file_count(user_id: int) -> int:
    return len(db.get_user_files(user_id))

def format_number(num: int) -> str:
    if num >= 1_000_000_000:
        return f"{num/1_000_000_000:.1f}B"
    elif num >= 1_000_000:
        return f"{num/1_000_000:.1f}M"
    elif num >= 1_000:
        return f"{num/1_000:.1f}K"
    return str(num)

def check_ban(user_id: int) -> Tuple[bool, str]:
    user = db.get_user(user_id)
    
    if not user:
        return False, ""
    
    if user.is_banned:
        if user.ban_until and user.ban_until > datetime.now():
            remaining = (user.ban_until - datetime.now()).seconds // 60
            return True, f"🚫 **Bạn đã bị cấm**\n\n⏰ Còn lại: `{remaining}` phút\n📅 Hết hạn: {user.ban_until.strftime('%H:%M %d/%m/%Y')}"
        else:
            user.is_banned = False
            user.ban_until = None
            db.update_user(user)
    
    return False, ""

def check_and_update_user(user_id: int, username: str = "", first_name: str = "", ip: str = "") -> UserData:
    user = db.get_user(user_id)
    
    if not user:
        user = db.create_user(user_id, username, first_name, ip)
    
    user.username = username
    user.first_name = first_name
    user.last_active = datetime.now()
    if ip and not user.ip_address:
        user.ip_address = ip
    
    db.update_user(user)
    db.add_active_user(user_id)
    
    return user

def get_client_ip(message) -> str:
    """Lấy IP client (nếu có)"""
    try:
        # Telegram không cung cấp IP trực tiếp, dùng forwarding info nếu có
        if hasattr(message, 'forward_from') and message.forward_from:
            return f"forwarded_{message.forward_from.id}"
        return f"tg_{message.chat.id}"
    except:
        return f"unknown_{int(time.time())}"

def check_suspicious(user: UserData) -> bool:
    """Kiểm tra hành vi đáng ngờ"""
    suspicious = False
    reasons = []
    
    # Kiểm tra username
    if user.username:
        for pattern in SUSPICIOUS_PATTERNS:
            if re.match(pattern, user.username, re.IGNORECASE):
                suspicious = True
                reasons.append(f"username khả nghi: {user.username}")
                break
    
    # Kiểm tra tốc độ refer
    if user.last_referral_time:
        time_diff = (datetime.now() - user.last_referral_time).seconds
        if time_diff < 60 and user.referral_count > 5:
            suspicious = True
            reasons.append(f"refer quá nhanh: {time_diff}s, {user.referral_count} ref")
    
    # Kiểm tra tỷ lệ
    if user.referral_count > 20 and user.total_earned < user.referral_count * REFERRAL_REWARD:
        suspicious = True
        reasons.append("tỷ lệ earn/ref bất thường")
    
    if suspicious:
        db.mark_suspicious(user.user_id, ", ".join(reasons))
    
    return suspicious

# ==================== TẠO MENU BUTTONS ====================
def create_main_menu(user_id: int) -> types.ReplyKeyboardMarkup:
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    
    user = db.get_user(user_id)
    balance = user.balance if user else 0
    is_admin = db.is_admin(user_id)
    
    # Hàng 1
    markup.row(
        types.KeyboardButton(f"💰 {format_number(balance)} Coin"),
        types.KeyboardButton("🎁 Daily Reward")
    )
    
    # Hàng 2
    markup.row(
        types.KeyboardButton("👥 Giới Thiệu"),
        types.KeyboardButton("📊 Thống Kê")
    )
    
    # Hàng 3
    markup.row(
        types.KeyboardButton("📤 Upload File"),
        types.KeyboardButton("📁 File Của Tôi")
    )
    
    # Hàng 4
    markup.row(
        types.KeyboardButton("⚡ Tốc Độ"),
        types.KeyboardButton("📞 Support")
    )
    
    # Hàng 5 (Admin)
    if is_admin:
        markup.row(
            types.KeyboardButton("👑 Admin"),
            types.KeyboardButton("📢 Broadcast")
        )
    
    return markup

def create_inline_main_menu(user_id: int) -> types.InlineKeyboardMarkup:
    markup = types.InlineKeyboardMarkup(row_width=2)
    
    user = db.get_user(user_id)
    balance = user.balance if user else 0
    
    buttons = [
        [
            types.InlineKeyboardButton(f"💰 {format_number(balance)} Coin", callback_data="balance"),
            types.InlineKeyboardButton("🎁 Daily", callback_data="daily")
        ],
        [
            types.InlineKeyboardButton("👥 Giới Thiệu", callback_data="referral"),
            types.InlineKeyboardButton("📊 Stats", callback_data="stats")
        ],
        [
            types.InlineKeyboardButton("📤 Upload", callback_data="upload"),
            types.InlineKeyboardButton("📁 My Files", callback_data="my_files")
        ],
        [
            types.InlineKeyboardButton("⚡ Ping", callback_data="speed"),
            types.InlineKeyboardButton("📞 Support", url=f"https://t.me/{YOUR_USERNAME.replace('@', '')}")
        ]
    ]
    
    if db.is_admin(user_id):
        buttons.append([
            types.InlineKeyboardButton("👑 Admin Panel", callback_data="admin_panel"),
            types.InlineKeyboardButton("📢 Broadcast", callback_data="broadcast")
        ])
    
    for row in buttons:
        markup.row(*row)
    
    return markup

def create_files_menu(user_id: int) -> types.InlineKeyboardMarkup:
    markup = types.InlineKeyboardMarkup(row_width=1)
    
    files = db.get_user_files(user_id)
    
    if files:
        for file in files:
            file_name = file['file_name']
            file_type = file['file_type']
            is_running = script_manager.is_running(user_id, file_name)
            
            status_emoji = "🟢" if is_running else "🔴"

            
            run_count = file.get('run_count', 0)


            
            pin_until = parse_iso_datetime(file.get('pinned_until'))

            
            pin_tag = ""

            
            if is_pin_active(pin_until):

            
                pin_tag = f" 📌{pin_remaining_days(pin_until)}d"


            
            markup.row(

            
                types.InlineKeyboardButton(

            
                    f"{status_emoji} {file_name} ({file_type}) | {run_count} lần chạy{pin_tag}",

            
                    callback_data=f"file_{user_id}_{file_name}"

            
                )

            
            )
    
    markup.row(
        types.InlineKeyboardButton("🔙 Quay Lại", callback_data="main_menu")
    )
    
    return markup

def create_file_control_menu(user_id: int, file_name: str) -> types.InlineKeyboardMarkup:
    markup = types.InlineKeyboardMarkup(row_width=2)
    
    is_running = script_manager.is_running(user_id, file_name)
    
    if is_running:
        markup.row(
            types.InlineKeyboardButton("⏹️ Dừng", callback_data=f"stop_{user_id}_{file_name}"),
            types.InlineKeyboardButton("🔄 Restart", callback_data=f"restart_{user_id}_{file_name}")
        )
    else:
        markup.row(
            types.InlineKeyboardButton("▶️ Chạy", callback_data=f"start_{user_id}_{file_name}"),
            types.InlineKeyboardButton("🗑️ Xóa", callback_data=f"delete_{user_id}_{file_name}")
        )
    
    markup.row(
        types.InlineKeyboardButton("📜 Logs", callback_data=f"logs_{user_id}_{file_name}"),
        types.InlineKeyboardButton("📥 Download", callback_data=f"download_{user_id}_{file_name}")
    )
    
    # Treo (pin) file: 15 coin/ngày, tối đa 7 ngày
    pin_until = db.get_file_pinned_until(user_id, file_name)
    if is_pin_active(pin_until):
        days_left = pin_remaining_days(pin_until)
        markup.row(
            types.InlineKeyboardButton(f"📌 Đang treo: {days_left}d", callback_data=f"pininfo_{user_id}_{file_name}"),
            types.InlineKeyboardButton("❌ Hủy treo", callback_data=f"unpin_{user_id}_{file_name}")
        )
    else:
        markup.row(
            types.InlineKeyboardButton("📌 Treo (15 coin/ngày)", callback_data=f"pin_{user_id}_{file_name}")
        )

    
    markup.row(
        types.InlineKeyboardButton("🔙 Quay Lại", callback_data="my_files")
    )
    
    return markup

def create_admin_panel_menu() -> types.InlineKeyboardMarkup:
    markup = types.InlineKeyboardMarkup(row_width=2)
    
    buttons = [
        [
            types.InlineKeyboardButton("👥 Users", callback_data="admin_users"),
            types.InlineKeyboardButton("💰 Coin", callback_data="admin_coins")
        ],
        [
            types.InlineKeyboardButton("➕ Add Admin", callback_data="admin_add"),
            types.InlineKeyboardButton("➖ Remove Admin", callback_data="admin_remove")
        ],
        [
            types.InlineKeyboardButton("📊 Stats", callback_data="admin_stats"),
            types.InlineKeyboardButton("🚫 Ban", callback_data="admin_ban")
        ],
        [
            types.InlineKeyboardButton("🔍 Check IP", callback_data="admin_check_ip"),
            types.InlineKeyboardButton("📈 Scripts", callback_data="admin_scripts")
        ],
        [
            types.InlineKeyboardButton("📌 Treo", callback_data="admin_pins"),
            types.InlineKeyboardButton("🧹 Clear RAM", callback_data="admin_clear_ram")
        ],
        [
            types.InlineKeyboardButton("🔙 Quay Lại", callback_data="main_menu")
        ]
    ]
    
    for row in buttons:
        markup.row(*row)
    
    return markup

def create_referral_menu(user_id: int) -> types.InlineKeyboardMarkup:
    markup = types.InlineKeyboardMarkup(row_width=1)
    
    bot_username = get_bot_username()
    ref_link = f"https://t.me/{bot_username}?start=ref_{user_id}"
    
    markup.row(
        types.InlineKeyboardButton("🔗 Copy Link", callback_data=f"copy_ref_{user_id}")
    )
    
    markup.row(
        types.InlineKeyboardButton("👥 Danh Sách Ref", callback_data="my_referrals")
    )
    
    markup.row(
        types.InlineKeyboardButton("📊 Thống Kê Ref", callback_data="ref_stats")
    )
    
    markup.row(
        types.InlineKeyboardButton("🏆 Bảng Xếp Hạng", callback_data="ref_leaderboard")
    )
    
    markup.row(
        types.InlineKeyboardButton("🔙 Quay Lại", callback_data="main_menu")
    )
    
    return markup

# ==================== COMMAND HANDLERS ====================
@bot.message_handler(commands=['start'])
def cmd_start(message):
    user_id = message.from_user.id
    username = message.from_user.username or ""
    first_name = message.from_user.first_name or ""
    ip = get_client_ip(message)
    
    # Kiểm tra ban
    banned, ban_msg = check_ban(user_id)
    if banned:
        bot.reply_to(message, ban_msg)
        return
    
    # Kiểm tra và cập nhật user
    user = check_and_update_user(user_id, username, first_name, ip)
    
    # Kiểm tra suspicious
    check_suspicious(user)
    
    # Xử lý referral
    if message.text and len(message.text.split()) > 1:
        ref_param = message.text.split()[1]
        
        if ref_param.startswith('ref_'):
            try:
                referrer_id = int(ref_param.replace('ref_', ''))
                
                if referrer_id != user_id and not user.referred_by:
                    # Kiểm tra đã refer chưa
                    existing = db.get_referrals(referrer_id)
                    already_referred = any(r['referred_id'] == user_id for r in existing)
                    
                    if not already_referred:
                        # Tạo captcha
                        code, image_path = captcha_manager.generate_captcha(user_id, "referral")
                        
                        with open(image_path, 'rb') as f:
                            bot.send_photo(
                                user_id,
                                f,
                                caption=(
                                    "🔐 **XÁC THỰC GIỚI THIỆU**\n\n"
                                    f"👤 **Người giới thiệu:** `{referrer_id}`\n"
                                    f"💰 **Phần thưởng:** `+{REFERRAL_REWARD}` Coin cho người giới thiệu\n\n"
                                    "📝 **Vui lòng nhập mã captcha bên dưới:**\n"
                                    f"⏳ Có `{CAPTCHA_ATTEMPTS}` lần thử"
                                ),
                                parse_mode='Markdown'
                            )
                        
                        bot.register_next_step_handler(
                            message,
                            process_referral_captcha,
                            referrer_id,
                            user_id,
                            ip
                        )
                        return
                    else:
                        referrer_info = db.get_user(existing[0]['referrer_id'])
                        bot.reply_to(
                            message,
                            f"👋 **Chào mừng {first_name}!**\n\n"
                            f"⚠️ Bạn đã được giới thiệu bởi **{referrer_info.first_name or referrer_info.user_id}**",
                            parse_mode='Markdown',
                            reply_markup=create_main_menu(user_id)
                        )
                else:
                    bot.reply_to(
                        message,
                        f"👋 **Chào mừng {first_name}!**",
                        reply_markup=create_main_menu(user_id)
                    )
            except Exception as e:
                logger.error(f"Lỗi xử lý referral: {e}")
                bot.reply_to(
                    message,
                    f"👋 **Chào mừng {first_name}!**",
                    reply_markup=create_main_menu(user_id)
                )
        else:
            bot.reply_to(
                message,
                f"👋 **Chào mừng {first_name}!**",
                reply_markup=create_main_menu(user_id)
            )
    else:
        bot.reply_to(
            message,
            f"👋 **CHÀO MỪNG ĐẾN VỚI MARCO BOT!**\n\n"
            f"🆔 **ID:** `{user_id}`\n"
            f"💰 **Số dư:** `{format_number(user.balance)}` Coin\n"
            f"👥 **Đã giới thiệu:** `{user.referral_count}` người\n"
            f"🔥 **Streak daily:** `{user.daily_streak}` ngày\n\n"
            f"✨ **TÍNH NĂNG NỔI BẬT:**\n"
            f"• 🤖 **Host Python/JavaScript**\n"
            f"• 💰 **Kiếm coin qua giới thiệu**\n"
            f"• 🎁 **Daily reward + streak bonus**\n"
            f"• 📊 **Thống kê chi tiết**\n"
            f"• 🛡️ **Chống buff tự động**\n\n"
            f"👇 **Chọn chức năng bên dưới:**",
            parse_mode='Markdown',
            reply_markup=create_main_menu(user_id)
        )


def process_referral_captcha(message, referrer_id: int, referred_id: int, ip: str):
    user_id = message.from_user.id
    input_code = (message.text or "").strip()

    # Xác thực captcha
    success, msg, challenge_type = captcha_manager.verify_captcha(user_id, input_code)

    if success:
        # Thêm referral (CHỈ thưởng cho người giới thiệu)
        success_ref, ref_msg = db.add_referral(referrer_id, referred_id, REFERRAL_REWARD, ip)

        if success_ref:
            # Chỉ ghi nhận người đã được giới thiệu (KHÔNG cộng coin)
            referred_user = db.get_user(referred_id)
            if referred_user:
                referred_user.referred_by = referrer_id
                db.update_user(referred_user)

            bot.reply_to(
                message,
                f"✅ **XÁC THỰC THÀNH CÔNG!**\n\n"
                f"👤 **Người giới thiệu:** `{referrer_id}`\n"
                f"📌 Bạn đã được ghi nhận là người được giới thiệu.\n\n"
                f"🎁 **Phần thưởng:** Người giới thiệu nhận `+{REFERRAL_REWARD}` Coin\n\n"
                f"✨ Dùng /daily để nhận thưởng mỗi ngày!",
                parse_mode='Markdown',
                reply_markup=create_main_menu(user_id)
            )

            # Thông báo cho người giới thiệu
            try:
                referrer = db.get_user(referrer_id)
                if referrer:
                    bot.send_message(
                        referrer_id,
                        f"🎉 **GIỚI THIỆU THÀNH CÔNG!**\n\n"
                        f"👤 **Người dùng mới:** `{referred_id}`\n"
                        f"💰 **Bạn nhận:** `+{REFERRAL_REWARD}` Coin\n"
                        f"👥 **Tổng ref:** `{referrer.referral_count}` người\n"
                        f"💎 **Số dư mới:** `{format_number(referrer.balance)}` Coin",
                        parse_mode='Markdown'
                    )
            except Exception as e:
                logger.error(f"Không thể gửi thông báo cho referrer {referrer_id}: {e}")
        else:
            bot.reply_to(
                message,
                f"❌ **LỖI**\n\n{ref_msg}",
                parse_mode='Markdown',
                reply_markup=create_main_menu(user_id)
            )
    else:
        if "bị cấm" in msg:
            bot.reply_to(
                message,
                msg,
                reply_markup=create_main_menu(user_id)
            )
        else:
            bot.reply_to(message, msg)

            # Nếu còn lượt thử thì gửi lại captcha
            try:
                if "Còn" in msg and int(msg.split("Còn")[1].split()[0]) > 0:
                    code, image_path = captcha_manager.generate_captcha(user_id, "referral")
                    with open(image_path, 'rb') as f:
                        bot.send_photo(
                            user_id,
                            f,
                            caption=f"🔐 **NHẬP LẠI MÃ CAPTCHA**\n\n{msg}",
                            parse_mode='Markdown'
                        )

                    bot.register_next_step_handler(
                        message,
                        process_referral_captcha,
                        referrer_id,
                        referred_id,
                        ip
                    )
            except Exception as e:
                logger.error(f"Lỗi gửi lại captcha: {e}")

@bot.message_handler(commands=['menu'])
def cmd_menu(message):
    user_id = message.from_user.id
    
    banned, ban_msg = check_ban(user_id)
    if banned:
        bot.reply_to(message, ban_msg)
        return
    
    user = check_and_update_user(
        user_id,
        message.from_user.username or "",
        message.from_user.first_name or ""
    )
    
    bot.send_message(
        user_id,
        "📋 **MENU CHÍNH**\n\nChọn chức năng bên dưới:",
        parse_mode='Markdown',
        reply_markup=create_main_menu(user_id)
    )

@bot.message_handler(commands=['daily'])
def cmd_daily(message):
    user_id = message.from_user.id
    
    banned, ban_msg = check_ban(user_id)
    if banned:
        bot.reply_to(message, ban_msg)
        return
    
    user = check_and_update_user(
        user_id,
        message.from_user.username or "",
        message.from_user.first_name or ""
    )
    
    success, amount, streak, msg = db.claim_daily(user_id)
    
    if success:
        bot.reply_to(
            message,
            f"🎁 **DAILY REWARD**\n\n"
            f"💰 **Nhận được:** `+{amount}` Coin\n"
            f"🔥 **Streak:** `{streak}` ngày\n"
            f"💎 **Số dư mới:** `{format_number(user.balance + amount)}` Coin\n\n"
            f"{msg}",
            parse_mode='Markdown'
        )
    else:
        bot.reply_to(message, msg)

@bot.message_handler(commands=['balance'])
def cmd_balance(message):
    user_id = message.from_user.id
    
    banned, ban_msg = check_ban(user_id)
    if banned:
        bot.reply_to(message, ban_msg)
        return
    
    user = check_and_update_user(
        user_id,
        message.from_user.username or "",
        message.from_user.first_name or ""
    )
    
    markup = types.InlineKeyboardMarkup()
    markup.row(
        types.InlineKeyboardButton("📊 Lịch Sử", callback_data="transactions"),
        types.InlineKeyboardButton("🔙 Menu", callback_data="main_menu")
    )
    
    bot.reply_to(
        message,
        f"💰 **VÍ COIN**\n\n"
        f"💎 **Số dư:** `{format_number(user.balance)}` Coin\n"
        f"📈 **Đã kiếm:** `{format_number(user.total_earned)}` Coin\n"
        f"👥 **Hoa hồng ref:** `{format_number(user.referral_earnings)}` Coin\n"
        f"🤝 **Đã giới thiệu:** `{user.referral_count}` người\n"
        f"🔥 **Daily streak:** `{user.daily_streak}` ngày\n\n"
        f"✨ **CÁCH KIẾM COIN:**\n"
        f"• 👥 Giới thiệu bạn bè: `+{REFERRAL_REWARD}` coin/người\n"
        f"• 🎁 Daily reward: `+{DAILY_COIN_REWARD}` coin + bonus streak\n"
        f"• 🤖 Treo bot: Tự động kiếm coin",
        parse_mode='Markdown',
        reply_markup=markup
    )

@bot.message_handler(commands=['referral'])
def cmd_referral(message):
    user_id = message.from_user.id
    
    banned, ban_msg = check_ban(user_id)
    if banned:
        bot.reply_to(message, ban_msg)
        return
    
    user = check_and_update_user(
        user_id,
        message.from_user.username or "",
        message.from_user.first_name or ""
    )
    
    show_referral_info(message, user)

@bot.message_handler(commands=['help'])
def cmd_help(message):
    user_id = message.from_user.id
    
    banned, ban_msg = check_ban(user_id)
    if banned:
        bot.reply_to(message, ban_msg)
        return
    
    help_text = (
        "🆘 **TRỢ GIÚP**\n\n"
        "**📋 CÁC LỆNH:**\n"
        "/start - Khởi động bot\n"
        "/menu - Menu chính\n"
        "/daily - Nhận thưởng hàng ngày\n"
        "/balance - Xem số dư\n"
        "/referral - Giới thiệu bạn bè\n"
        "/help - Trợ giúp này\n\n"
        
        "**💎 KIẾM COIN:**\n"
        "• Giới thiệu bạn bè: +3 coin/người\n"
        "• Daily reward: +5 coin + bonus streak\n"
        "• Mở kho báu: Random 1-10 coin\n\n"
        
        "**📤 UPLOAD FILE:**\n"
        "• Python (.py)\n"
        "• JavaScript (.js)\n"
        "• ZIP (chứa script chính)\n\n"
        
        "**📌 LƯU Ý:**\n"
        "• Cần xác thực captcha khi giới thiệu\n"
        "• Sai captcha 5 lần = ban 30 phút\n"
        "• Phát hiện buff = ban vĩnh viễn\n\n"
        
        f"📞 **LIÊN HỆ:** {YOUR_USERNAME}"
    )
    
    bot.reply_to(message, help_text, parse_mode='Markdown')

# ==================== BUTTON HANDLERS ====================
@bot.message_handler(func=lambda message: message.text in [
    "💰", "💰 Coin", "💰 0 Coin", "💰 1K Coin", "💰 1M Coin",
    "🎁 Daily Reward", "👥 Giới Thiệu", "📊 Thống Kê",
    "📤 Upload File", "📁 File Của Tôi", "⚡ Tốc Độ", "📞 Support",
    "👑 Admin", "📢 Broadcast"
])
def handle_menu_buttons(message):
    user_id = message.from_user.id
    text = message.text
    
    # Xử lý button balance có dynamic
    if text.startswith("💰"):
        text = "💰 Ví Coin"
    
    banned, ban_msg = check_ban(user_id)
    if banned:
        bot.reply_to(message, ban_msg)
        return
    
    user = check_and_update_user(
        user_id,
        message.from_user.username or "",
        message.from_user.first_name or ""
    )
    
    handlers = {
        "💰 Ví Coin": lambda: show_balance(message, user),
        "🎁 Daily Reward": lambda: cmd_daily(message),
        "👥 Giới Thiệu": lambda: show_referral_info(message, user),
        "📊 Thống Kê": lambda: show_stats(message, user),
        "📤 Upload File": lambda: upload_file_prompt(message, user),
        "📁 File Của Tôi": lambda: show_my_files(message, user),
        "⚡ Tốc Độ": lambda: check_speed(message, user),
        "📞 Support": lambda: contact_support(message),
        "👑 Admin": lambda: show_admin_panel(message),
        "📢 Broadcast": lambda: start_broadcast(message) if db.is_admin(user_id) else None
    }
    
    handler = handlers.get(text)
    if handler:
        handler()

def show_balance(message, user: UserData):
    markup = types.InlineKeyboardMarkup()
    markup.row(
        types.InlineKeyboardButton("📊 Lịch Sử", callback_data="transactions"),
        types.InlineKeyboardButton("🔙 Menu", callback_data="main_menu")
    )
    
    bot.reply_to(
        message,
        f"💰 **VÍ COIN**\n\n"
        f"💎 **Số dư:** `{format_number(user.balance)}` Coin\n"
        f"📈 **Đã kiếm:** `{format_number(user.total_earned)}` Coin\n"
        f"👥 **Hoa hồng ref:** `{format_number(user.referral_earnings)}` Coin\n"
        f"🤝 **Đã giới thiệu:** `{user.referral_count}` người\n"
        f"🔥 **Daily streak:** `{user.daily_streak}` ngày",
        parse_mode='Markdown',
        reply_markup=markup
    )

def show_referral_info(message, user: UserData):
    bot_username = get_bot_username()
    ref_link = f"https://t.me/{bot_username}?start=ref_{user.user_id}"
    
    markup = create_referral_menu(user.user_id)
    
    stats = db.get_referral_stats(user.user_id)
    
    bot.reply_to(
        message,
        f"👥 **CHƯƠNG TRÌNH GIỚI THIỆU**\n\n"
        f"🔗 **LINK CỦA BẠN:**\n"
        f"`{ref_link}`\n\n"
        f"📊 **THỐNG KÊ:**\n"
        f"• 🤝 **Đã giới thiệu:** `{stats['total'] or 0}` người\n"
        f"• ✅ **Thành công:** `{stats['completed'] or 0}` người\n"
        f"• ⏳ **Chờ xử lý:** `{stats['pending'] or 0}` người\n"
        f"• 💰 **Hoa hồng:** `{format_number(stats['total_rewards'] or 0)}` Coin\n\n"
        f"🎁 **PHẦN THƯỞNG:**\n"
        f"• Mỗi người giới thiệu: `+{REFERRAL_REWARD}` Coin cho người giới thiệu\n"
        f"• Người được giới thiệu: `+0` Coin\n\n"
        f"🛡️ **CHỐNG GIAN LẬN:**\n"
        f"• Cần xác thực captcha\n"
        f"• Giới hạn IP: {MAX_REFS_PER_IP} ref/IP\n"
        f"• Phát hiện buff = ban vĩnh viễn",
        parse_mode='Markdown',
        reply_markup=markup
    )

def show_stats(message, user: UserData):
    stats = db.get_statistics()
    running_stats = script_manager.get_stats()
    
    bot.reply_to(
        message,
        f"📊 **THỐNG KÊ HỆ THỐNG**\n\n"
        f"👥 **NGƯỜI DÙNG:**\n"
        f"• Tổng: `{stats['total_users']}`\n"
        f"• Hoạt động hôm nay: `{stats['active_today']}`\n"
        f"• Mới hôm nay: `{stats['new_today']}`\n"
        f"• Bị ban: `{stats['banned_users']}`\n\n"
        f"💰 **KINH TẾ:**\n"
        f"• Tổng coin: `{format_number(stats['total_coins'])}`\n"
        f"• Tổng referrals: `{stats['total_referrals']}`\n\n"
        f"🤖 **SCRIPTS:**\n"
        f"• Đang chạy: `{running_stats['total_running']}`\n"
        f"• Python: `{running_stats['python']}`\n"
        f"• JavaScript: `{running_stats['javascript']}`\n\n"
        f"👤 **CÁ NHÂN:**\n"
        f"• Coin: `{format_number(user.balance)}`\n"
        f"• Đã kiếm: `{format_number(user.total_earned)}`\n"
        f"• Ref: `{user.referral_count}` người\n"
        f"• Streak: `{user.daily_streak}` ngày",
        parse_mode='Markdown'
    )

def upload_file_prompt(message, user: UserData):
    file_limit = get_user_file_limit(user.user_id)
    current_files = get_user_file_count(user.user_id)
    
    if current_files >= file_limit:
        limit_str = str(file_limit) if file_limit != float('inf') else "∞"
        bot.reply_to(
            message,
            f"⚠️ **ĐẠT GIỚI HẠN FILE!**\n\n"
            f"Hiện tại: `{current_files}/{limit_str}`\n"
            f"Vui lòng xóa bớt file cũ để upload tiếp.",
            parse_mode='Markdown'
        )
        return
    
    bot.reply_to(
        message,
        f"📤 **UPLOAD FILE**\n\n"
        f"Gửi file:\n"
        f"• Python (`.py`)\n"
        f"• JavaScript (`.js`)\n"
        f"• ZIP (`.zip`) chứa script chính\n\n"
        f"📌 **LƯU Ý:**\n"
        f"• File tối đa 20MB\n"
        f"• ZIP sẽ tự động giải nén\n"
        f"• Có requirements.txt/package.json sẽ tự cài đặt\n"
        f"• Giới hạn: `{current_files}/{file_limit}` file",
        parse_mode='Markdown'
    )

def show_my_files(message, user: UserData):
    files = db.get_user_files(user.user_id)
    
    if not files:
        bot.reply_to(
            message,
            "📁 **FILE CỦA BẠN**\n\n"
            "Bạn chưa upload file nào.\n"
            "Sử dụng nút 📤 Upload File để bắt đầu!",
            parse_mode='Markdown'
        )
        return
    
    markup = create_files_menu(user.user_id)
    
    total_size = sum(f.get('file_size', 0) for f in files) / (1024*1024)
    
    bot.reply_to(
        message,
        f"📁 **FILE CỦA BẠN** (Tổng: {len(files)})\n\n"
        f"🟢 = Đang chạy\n"
        f"🔴 = Đã dừng\n"
        f"📦 Tổng dung lượng: `{total_size:.2f} MB`\n\n"
        f"Chọn file để quản lý:",
        parse_mode='Markdown',
        reply_markup=markup
    )

def check_speed(message, user: UserData):
    start = time.time()
    msg = bot.reply_to(message, "⏳ Đang kiểm tra tốc độ...")
    end = time.time()
    
    response_time = round((end - start) * 1000, 2)
    
    status = "🟢 Tuyệt vời"
    if response_time > 1000:
        status = "🟡 Chậm"
    elif response_time > 500:
        status = "🟠 Trung bình"
    elif response_time < 200:
        status = "💚 Siêu nhanh"
    
    bot.edit_message_text(
        f"⚡ **KIỂM TRA TỐC ĐỘ**\n\n"
        f"📡 **Ping:** `{response_time}ms`\n"
        f"🚦 **Trạng thái:** {status}\n"
        f"👤 **User ID:** `{user.user_id}`\n"
        f"💰 **Số dư:** `{format_number(user.balance)}` Coin\n"
        f"🖥️ **Scripts đang chạy:** `{len(script_manager.get_all_running())}`",
        chat_id=message.chat.id,
        message_id=msg.message_id,
        parse_mode='Markdown'
    )

def contact_support(message):
    markup = types.InlineKeyboardMarkup()
    markup.row(
        types.InlineKeyboardButton("📞 Chat với Owner", url=f"https://t.me/{YOUR_USERNAME.replace('@', '')}")
    )
    markup.row(
        types.InlineKeyboardButton("📢 Channel", url=f"https://t.me/{YOUR_USERNAME.replace('@', '')}"),
        types.InlineKeyboardButton("💬 Group", url=f"https://t.me/{YOUR_USERNAME.replace('@', '')}")
    )
    
    bot.reply_to(
        message,
        f"📞 **LIÊN HỆ SUPPORT**\n\n"
        f"👤 **Owner:** {YOUR_USERNAME}\n"
        f"🆔 **ID:** `{message.from_user.id}`\n\n"
        f"📌 **HƯỚNG DẪN:**\n"
        f"• Bấm nút bên dưới để chat với Owner\n"
        f"• Mô tả chi tiết vấn đề bạn gặp phải\n"
        f"• Cung cấp screenshot nếu có lỗi",
        parse_mode='Markdown',
        reply_markup=markup
    )

def show_admin_panel(message):
    if not db.is_admin(message.from_user.id):
        bot.reply_to(message, "⛔ Bạn không phải admin!")
        return
    
    markup = create_admin_panel_menu()
    
    stats = db.get_statistics()
    
    bot.reply_to(
        message,
        f"👑 **ADMIN PANEL**\n\n"
        f"📊 **THỐNG KÊ NHANH:**\n"
        f"• 👥 Users: {stats['total_users']}\n"
        f"• 💰 Tổng coin: {format_number(stats['total_coins'])}\n"
        f"• 🤖 Scripts: {stats['running_scripts']}\n"
        f"• 🚫 Banned: {stats['banned_users']}\n\n"
        f"Chọn chức năng bên dưới:",
        parse_mode='Markdown',
        reply_markup=markup
    )

def start_broadcast(message):
    if not db.is_admin(message.from_user.id):
        bot.reply_to(message, "⛔ Bạn không phải admin!")
        return
    
    msg = bot.reply_to(
        message,
        "📢 **GỬI TIN NHẮN BROADCAST**\n\n"
        "Nhập nội dung cần gửi đến tất cả users:\n"
        "(Có thể gửi text, ảnh, video, file...)\n\n"
        "Gửi /cancel để hủy",
        parse_mode='Markdown'
    )
    
    bot.register_next_step_handler(msg, process_broadcast)

def process_broadcast(message):
    if message.text and message.text.lower() == '/cancel':
        bot.reply_to(
            message,
            "❌ Đã hủy broadcast",
            reply_markup=create_main_menu(message.from_user.id)
        )
        return
    
    active_users = db.get_active_users(60*24*7)  # 7 ngày
    total = len(active_users)
    
    markup = types.InlineKeyboardMarkup()
    markup.row(
        types.InlineKeyboardButton("✅ Xác Nhận", callback_data=f"confirm_broadcast_{message.message_id}"),
        types.InlineKeyboardButton("❌ Hủy", callback_data="cancel_broadcast")
    )
    
    # Lưu nội dung broadcast
    broadcast_data = {
        'user_id': message.from_user.id,
        'chat_id': message.chat.id,
        'message_id': message.message_id,
        'content_type': message.content_type,
        'text': message.text if message.content_type == 'text' else None,
        'caption': message.caption if message.content_type != 'text' else None,
        'file_id': None
    }
    
    if message.content_type == 'photo':
        broadcast_data['file_id'] = message.photo[-1].file_id
    elif message.content_type == 'video':
        broadcast_data['file_id'] = message.video.file_id
    elif message.content_type == 'document':
        broadcast_data['file_id'] = message.document.file_id
    elif message.content_type == 'audio':
        broadcast_data['file_id'] = message.audio.file_id
    elif message.content_type == 'voice':
        broadcast_data['file_id'] = message.voice.file_id
    
    with open(os.path.join(TEMP_DIR, 'broadcast_temp.json'), 'w', encoding='utf-8') as f:
        json.dump(broadcast_data, f, ensure_ascii=False)
    
    preview = message.text[:200] if message.text else f"[{message.content_type.upper()}]"
    
    bot.reply_to(
        message,
        f"📢 **XÁC NHẬN BROADCAST**\n\n"
        f"📊 **Số người nhận:** `{total}` users\n"
        f"📝 **Nội dung:**\n```\n{preview}\n```\n\n"
        f"⏱️ **Thời gian dự kiến:** ~{total//20 + 1} phút\n\n"
        f"Xác nhận gửi?",
        parse_mode='Markdown',
        reply_markup=markup
    )

# ==================== CALLBACK HANDLERS ====================
@bot.callback_query_handler(func=lambda call: True)
def handle_callbacks(call):
    user_id = call.from_user.id
    data = call.data
    
    try:
        # Kiểm tra ban
        banned, ban_msg = check_ban(user_id)
        if banned:
            bot.answer_callback_query(call.id, ban_msg, show_alert=True)
            return
        
        # Cập nhật user
        user = check_and_update_user(
            user_id,
            call.from_user.username or "",
            call.from_user.first_name or ""
        )
        
        # Anti-spam callback
        ok_spam, spam_msg = spam_protector.check(user_id, "callback", SPAM_MAX_ACTIONS, SPAM_WINDOW_SECONDS)
        if not ok_spam:
            bot.answer_callback_query(call.id, spam_msg, show_alert=True)
            return

# MAIN MENU
        if data == "main_menu":
            bot.edit_message_text(
                f"👋 **CHÀO MỪNG TRỞ LẠI!**\n\n"
                f"💰 **Số dư:** `{format_number(user.balance)}` Coin\n"
                f"👥 **Đã giới thiệu:** `{user.referral_count}` người\n"
                f"🔥 **Streak:** `{user.daily_streak}` ngày\n\n"
                f"👇 Chọn chức năng:",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=create_inline_main_menu(user_id)
            )
            bot.answer_callback_query(call.id)
        
        # BALANCE
        elif data == "balance":
            bot.answer_callback_query(call.id)
            bot.edit_message_text(
                f"💰 **VÍ COIN**\n\n"
                f"💎 **Số dư:** `{format_number(user.balance)}`\n"
                f"📈 **Đã kiếm:** `{format_number(user.total_earned)}`\n"
                f"👥 **Hoa hồng ref:** `{format_number(user.referral_earnings)}`\n"
                f"🔥 **Daily streak:** `{user.daily_streak}` ngày",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=ikb_row(
                    types.InlineKeyboardButton("📊 Lịch Sử", callback_data="transactions"),
                    types.InlineKeyboardButton("🔙 Quay Lại", callback_data="main_menu")
                )
            )
        
        # DAILY
        elif data == "daily":
            bot.answer_callback_query(call.id, "🔄 Đang xử lý...")
            
            success, amount, streak, msg = db.claim_daily(user_id)
            
            if success:
                bot.edit_message_text(
                    f"🎁 **DAILY REWARD**\n\n"
                    f"💰 **Nhận được:** `+{amount}` Coin\n"
                    f"🔥 **Streak:** `{streak}` ngày\n"
                    f"💎 **Số dư mới:** `{format_number(user.balance + amount)}` Coin\n\n"
                    f"{msg}",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    parse_mode='Markdown',
                    reply_markup=ikb_row(
                        types.InlineKeyboardButton("🔙 Quay Lại", callback_data="main_menu")
                    )
                )
            else:
                bot.answer_callback_query(call.id, msg, show_alert=True)
        
        # REFERRAL
        elif data == "referral":
            bot.answer_callback_query(call.id)
            bot_username = get_bot_username()
            ref_link = f"https://t.me/{bot_username}?start=ref_{user_id}"
            
            stats = db.get_referral_stats(user_id)
            
            bot.edit_message_text(
                f"👥 **GIỚI THIỆU BẠN BÈ**\n\n"
                f"🔗 **LINK CỦA BẠN:**\n`{ref_link}`\n\n"
                f"📊 **THỐNG KÊ:**\n"
                f"• 🤝 Đã giới thiệu: `{stats['total'] or 0}` người\n"
                f"• 💰 Hoa hồng: `{format_number(stats['total_rewards'] or 0)}` Coin\n\n"
                f"🎁 Mỗi người: `+{REFERRAL_REWARD}` Coin cho người giới thiệu",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=create_referral_menu(user_id)
            )
        
        # COPY REF LINK
        elif data.startswith("copy_ref_"):
            referrer_id = int(data.replace("copy_ref_", ""))
            bot_username = get_bot_username()
            ref_link = f"https://t.me/{bot_username}?start=ref_{referrer_id}"
            
            bot.answer_callback_query(call.id, "✅ Đã copy link!", show_alert=True)
            
            bot.send_message(
                user_id,
                f"🔗 **LINK GIỚI THIỆU CỦA BẠN:**\n`{ref_link}`\n\n"
                f"📤 Gửi link này cho bạn bè để nhận thưởng!",
                parse_mode='Markdown'
            )
        
        # MY REFERRALS
        elif data == "my_referrals":
            bot.answer_callback_query(call.id)
            referrals = db.get_referrals(user_id, 20)
            
            if not referrals:
                bot.edit_message_text(
                    "📭 **BẠN CHƯA GIỚI THIỆU AI**\n\n"
                    "Hãy chia sẻ link giới thiệu để nhận thưởng!",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    parse_mode='Markdown',
                    reply_markup=ikb_row(
                        types.InlineKeyboardButton("🔙 Quay Lại", callback_data="referral")
                    )
                )
                return
            
            text = "👥 **DANH SÁCH ĐÃ GIỚI THIỆU:**\n\n"
            for i, ref in enumerate(referrals, 1):
                name = ref['first_name'] or ref['username'] or f"User {ref['referred_id']}"
                date = datetime.fromisoformat(ref['created_at']).strftime('%d/%m/%Y')
                status = "✅" if ref['status'] == 'completed' else "⏳"
                text += f"{i}. {status} **{name}**\n"
                text += f"   📅 {date} | 💰 +{ref['reward_given']} Coin\n"
            
            if len(referrals) >= 20:
                text += f"\n... và {db.get_referral_stats(user_id)['total'] - 20} người khác"
            
            bot.edit_message_text(
                text,
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=ikb_row(
                    types.InlineKeyboardButton("🔙 Quay Lại", callback_data="referral")
                )
            )
        
        # REF STATS
        elif data == "ref_stats":
            bot.answer_callback_query(call.id)
            stats = db.get_referral_stats(user_id)
            
            text = f"📊 **THỐNG KÊ GIỚI THIỆU**\n\n"
            text += f"👥 **Tổng số:** `{stats['total'] or 0}` người\n"
            text += f"✅ **Thành công:** `{stats['completed'] or 0}` người\n"
            text += f"⏳ **Chờ xác thực:** `{stats['pending'] or 0}` người\n"
            text += f"💰 **Đã kiếm:** `{format_number(stats['total_rewards'] or 0)}` Coin\n"
            text += f"💎 **TB mỗi ref:** `{(stats['total_rewards'] or 0) // max(1, stats['completed'] or 1)}` Coin\n\n"
            
            text += f"📅 **7 NGÀY GẦN NHẤT:**\n"
            for day in stats.get('daily', []):
                text += f"• {day['date']}: `{day['count']}` ref\n"
            
            bot.edit_message_text(
                text,
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=ikb_row(
                    types.InlineKeyboardButton("🔙 Quay Lại", callback_data="referral")
                )
            )
        
        # REF LEADERBOARD
        elif data == "ref_leaderboard":
            bot.answer_callback_query(call.id)
            
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT user_id, first_name, username, referral_count, referral_earnings
                    FROM users
                    WHERE referral_count > 0
                    ORDER BY referral_count DESC
                    LIMIT 10
                ''')
                top_refs = cursor.fetchall()
            
            if not top_refs:
                bot.edit_message_text(
                    "🏆 **BẢNG XẾP HẠNG**\n\nChưa có dữ liệu!",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    parse_mode='Markdown',
                    reply_markup=ikb_row(
                        types.InlineKeyboardButton("🔙 Quay Lại", callback_data="referral")
                    )
                )
                return
            
            text = "🏆 **BẢNG XẾP HẠNG GIỚI THIỆU**\n\n"
            medals = ["🥇", "🥈", "🥉"]
            
            for i, row in enumerate(top_refs, 1):
                medal = medals[i-1] if i <= 3 else f"{i}."
                name = row['first_name'] or row['username'] or f"User {row['user_id']}"
                text += f"{medal} **{name}**\n"
                text += f"   👥 {row['referral_count']} ref | 💰 {format_number(row['referral_earnings'])} Coin\n"
            
            # Xếp hạng của user
            user_rank = next((i for i, r in enumerate(top_refs) if r['user_id'] == user_id), None)
            if user_rank is not None:
                text += f"\n📊 **Bạn đang đứng thứ {user_rank + 1}**"
            elif user.referral_count > 0:
                text += f"\n📊 **Bạn có {user.referral_count} ref**"
            
            bot.edit_message_text(
                text,
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=ikb_row(
                    types.InlineKeyboardButton("🔙 Quay Lại", callback_data="referral")
                )
            )
        
        # STATS
        elif data == "stats":
            bot.answer_callback_query(call.id)
            stats = db.get_statistics()
            running_stats = script_manager.get_stats()
            
            bot.edit_message_text(
                f"📊 **THỐNG KÊ HỆ THỐNG**\n\n"
                f"👥 **NGƯỜI DÙNG:**\n"
                f"• Tổng: `{stats['total_users']}`\n"
                f"• Hoạt động: `{stats['active_today']}`\n"
                f"• Mới hôm nay: `{stats['new_today']}`\n"
                f"• Bị ban: `{stats['banned_users']}`\n\n"
                f"💰 **KINH TẾ:**\n"
                f"• Tổng coin: `{format_number(stats['total_coins'])}`\n"
                f"• Tổng referrals: `{stats['total_referrals']}`\n\n"
                f"🤖 **SCRIPTS:**\n"
                f"• Đang chạy: `{running_stats['total_running']}`\n"
                f"• Python: `{running_stats['python']}`\n"
                f"• JavaScript: `{running_stats['javascript']}`",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=ikb_row(
                    types.InlineKeyboardButton("🔙 Quay Lại", callback_data="main_menu")
                )
            )
        
        # UPLOAD
        elif data == "upload":
            bot.answer_callback_query(call.id)
            
            file_limit = get_user_file_limit(user_id)
            current_files = get_user_file_count(user_id)
            
            if current_files >= file_limit:
                limit_str = str(file_limit) if file_limit != float('inf') else "∞"
                bot.edit_message_text(
                    f"⚠️ **ĐẠT GIỚI HẠN FILE!**\n\n"
                    f"Hiện tại: `{current_files}/{limit_str}`\n"
                    f"Vui lòng xóa bớt file cũ.",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    parse_mode='Markdown',
                    reply_markup=ikb_row(
                        types.InlineKeyboardButton("🔙 Quay Lại", callback_data="main_menu")
                    )
                )
                return
            
            bot.edit_message_text(
                f"📤 **UPLOAD FILE**\n\n"
                f"Gửi file `.py`, `.js`, hoặc `.zip`\n\n"
                f"📌 **Lưu ý:**\n"
                f"• File tối đa 20MB\n"
                f"• ZIP sẽ tự động giải nén\n"
                f"• Có requirements.txt sẽ tự cài đặt",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=ikb_row(
                    types.InlineKeyboardButton("🔙 Quay Lại", callback_data="main_menu")
                )
            )
        
        # MY FILES
        elif data == "my_files":
            bot.answer_callback_query(call.id)
            
            files = db.get_user_files(user_id)
            
            if not files:
                bot.edit_message_text(
                    "📁 **FILE CỦA BẠN**\n\n"
                    "Bạn chưa upload file nào.",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    parse_mode='Markdown',
                    reply_markup=ikb_row(
                        types.InlineKeyboardButton("🔙 Quay Lại", callback_data="main_menu")
                    )
                )
                return
            
            markup = create_files_menu(user_id)
            
            bot.edit_message_text(
                f"📁 **FILE CỦA BẠN** (Tổng: {len(files)})\n\n"
                f"🟢 = Đang chạy | 🔴 = Đã dừng\n\n"
                f"Chọn file để quản lý:",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=markup
            )
        
        # SPEED
        elif data == "speed":
            bot.answer_callback_query(call.id, "🔄 Đang kiểm tra...")
            
            start = time.time()
            bot.edit_message_text(
                "⏳ Đang kiểm tra tốc độ...",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id
            )
            end = time.time()
            
            response_time = round((end - start) * 1000, 2)
            
            status = "🟢 Online"
            if response_time > 1000:
                status = "🟡 Chậm"
            elif response_time > 500:
                status = "🟠 Trung bình"
            elif response_time < 200:
                status = "💚 Siêu nhanh"
            
            bot.edit_message_text(
                f"⚡ **KIỂM TRA TỐC ĐỘ**\n\n"
                f"📡 **Ping:** `{response_time}ms`\n"
                f"🚦 **Trạng thái:** {status}\n"
                f"👤 **User ID:** `{user_id}`\n"
                f"💰 **Số dư:** `{format_number(user.balance)}` Coin",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=ikb_row(
                    types.InlineKeyboardButton("🔙 Quay Lại", callback_data="main_menu")
                )
            )
        
        # TRANSACTIONS
        elif data == "transactions":
            bot.answer_callback_query(call.id)
            
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM transactions 
                    WHERE user_id = ? 
                    ORDER BY created_at DESC 
                    LIMIT 10
                ''', (user_id,))
                transactions = cursor.fetchall()
            
            if not transactions:
                bot.edit_message_text(
                    "📭 **CHƯA CÓ GIAO DỊCH**",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    parse_mode='Markdown',
                    reply_markup=ikb_row(
                        types.InlineKeyboardButton("🔙 Quay Lại", callback_data="balance")
                    )
                )
                return
            
            text = "📊 **10 GIAO DỊCH GẦN NHẤT:**\n\n"
            for t in transactions:
                date = datetime.fromisoformat(t['created_at']).strftime('%d/%m %H:%M')
                symbol = "➕" if t['amount'] > 0 else "➖"
                text += f"{symbol} `{t['amount']:+d}` Coin - {t['description']}\n"
                text += f"   📅 {date}\n\n"
            
            bot.edit_message_text(
                text,
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=ikb_row(
                    types.InlineKeyboardButton("🔙 Quay Lại", callback_data="balance")
                )
            )
        
        # FILE CONTROL
        elif data.startswith("file_"):
            _, file_user_id, file_name = data.split('_', 2)
            file_user_id = int(file_user_id)
            
            if user_id != file_user_id and not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không có quyền!", show_alert=True)
                return
            
            is_running = script_manager.is_running(file_user_id, file_name)
            status = "🟢 Đang chạy" if is_running else "🔴 Đã dừng"
            
            file_info = next((f for f in db.get_user_files(file_user_id) if f['file_name'] == file_name), {})
            run_count = file_info.get('run_count', 0)

            pin_until = db.get_file_pinned_until(file_user_id, file_name)
            pin_line = ""
            if is_pin_active(pin_until):
                pin_line = f"📌 **Treo tới:** {pin_until.strftime('%H:%M %d/%m/%Y')} (còn {pin_remaining_days(pin_until)} ngày)\n"

            markup = create_file_control_menu(file_user_id, file_name)
            
            bot.edit_message_text(
                f"📁 **QUẢN LÝ FILE**\n\n"
                f"📄 **File:** `{file_name}`\n"
                f"👤 **User:** `{file_user_id}`\n"
                f"📊 **Trạng thái:** {status}\n"
                f"{pin_line}"
                f"🔄 **Đã chạy:** `{run_count}` lần\n\n"
                f"Chọn thao tác:",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=markup
            )
            
            bot.answer_callback_query(call.id)
        

        # PIN/TREO - CHỌN SỐ NGÀY
        elif data.startswith("pin_"):
            _, script_user_id, file_name = data.split('_', 2)
            script_user_id = int(script_user_id)

            if user_id != script_user_id and not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không có quyền!", show_alert=True)
                return

            # kiểm tra file tồn tại
            folder = get_user_folder(script_user_id)
            file_path = os.path.join(folder, file_name)
            if not os.path.exists(file_path):
                bot.answer_callback_query(call.id, "❌ File không tồn tại!", show_alert=True)
                try:
                    db.remove_user_file(script_user_id, file_name)
                except Exception:
                    pass
                return

            pin_until = db.get_file_pinned_until(script_user_id, file_name)
            remaining = pin_remaining_days(pin_until) if is_pin_active(pin_until) else 0
            allowed_add = max(0, MAX_PIN_DAYS - remaining)

            if allowed_add <= 0:
                bot.answer_callback_query(call.id, f"⚠️ File đã treo tối đa {MAX_PIN_DAYS} ngày.", show_alert=True)
                return

            markup = types.InlineKeyboardMarkup(row_width=2)
            # tạo nút chọn ngày (tối đa allowed_add)
            for d in range(1, allowed_add + 1):
                cost = d * PIN_COST_PER_DAY
                markup.insert(
                    types.InlineKeyboardButton(
                        f"{d} ngày - {cost} coin",
                        callback_data=f"pinbuy_{script_user_id}_{d}_{file_name}"
                    )
                )

            markup.row(
                types.InlineKeyboardButton("🔙 Quay Lại", callback_data=f"file_{script_user_id}_{file_name}")
            )

            info_txt = (
                f"📌 **TREO FILE**\n\n"
                f"📄 **File:** `{file_name}`\n"
                f"💸 **Giá:** `{PIN_COST_PER_DAY}` coin/ngày\n"
                f"⏳ **Tối đa:** `{MAX_PIN_DAYS}` ngày\n"
            )
            if remaining > 0:
                info_txt += f"📌 **Đang treo:** còn `{remaining}` ngày\n"
                info_txt += f"👉 Có thể gia hạn thêm tối đa `{allowed_add}` ngày\n"
            info_txt += "\nChọn số ngày treo:"

            bot.edit_message_text(
                info_txt,
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=markup
            )
            bot.answer_callback_query(call.id)

        # PIN/TREO - MUA
        elif data.startswith("pinbuy_"):
            try:
                _, script_user_id, days_str, file_name = data.split('_', 3)
                script_user_id = int(script_user_id)
                days = int(days_str)
            except Exception:
                bot.answer_callback_query(call.id, "❌ Dữ liệu không hợp lệ!", show_alert=True)
                return

            if days < 1 or days > MAX_PIN_DAYS:
                bot.answer_callback_query(call.id, f"❌ Chỉ được treo 1-{MAX_PIN_DAYS} ngày!", show_alert=True)
                return

            if user_id != script_user_id and not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không có quyền!", show_alert=True)
                return

            # kiểm tra file tồn tại
            folder = get_user_folder(script_user_id)
            file_path = os.path.join(folder, file_name)
            if not os.path.exists(file_path):
                bot.answer_callback_query(call.id, "❌ File không tồn tại!", show_alert=True)
                try:
                    db.remove_user_file(script_user_id, file_name)
                except Exception:
                    pass
                return

            pin_until = db.get_file_pinned_until(script_user_id, file_name)
            remaining = pin_remaining_days(pin_until) if is_pin_active(pin_until) else 0
            allowed_add = max(0, MAX_PIN_DAYS - remaining)
            if days > allowed_add:
                bot.answer_callback_query(
                    call.id,
                    f"⚠️ Tối đa {MAX_PIN_DAYS} ngày treo. Hiện còn {remaining}d, chỉ gia hạn thêm tối đa {allowed_add}d.",
                    show_alert=True
                )
                return

            cost = days * PIN_COST_PER_DAY
            target_user = db.get_user(script_user_id)
            if not target_user:
                bot.answer_callback_query(call.id, "❌ User không tồn tại!", show_alert=True)
                return

            if target_user.balance < cost:
                bot.answer_callback_query(
                    call.id,
                    f"❌ Không đủ coin! Cần {cost} coin, bạn có {target_user.balance} coin.",
                    show_alert=True
                )
                return

            # trừ coin
            target_user.balance -= cost
            db.update_user(target_user)
            try:
                db.add_transaction(
                    script_user_id,
                    -cost,
                    'pin',
                    f'Treo file {file_name} {days} ngày',
                    target_user.balance
                )
            except Exception:
                pass

            now = datetime.now()
            base = pin_until if (pin_until and pin_until > now) else now
            new_until = base + timedelta(days=days)

            # lưu pin
            db.set_file_pin(script_user_id, file_name, new_until, pinned_by=user_id)

            bot.answer_callback_query(call.id, "✅ Đã treo file!")

            # Auto-start nếu chưa chạy
            if not script_manager.is_running(script_user_id, file_name):
                file_type = 'py' if file_name.endswith('.py') else 'js'
                if file_type == 'py':
                    script_manager.run_python_script(file_path, script_user_id, folder, file_name, call.message)
                else:
                    script_manager.run_js_script(file_path, script_user_id, folder, file_name, call.message)

            markup = create_file_control_menu(script_user_id, file_name)
            bot.edit_message_text(
                f"✅ **TREO THÀNH CÔNG!**\n\n"
                f"📄 **File:** `{file_name}`\n"
                f"⏳ **Treo tới:** `{new_until.strftime('%H:%M %d/%m/%Y')}`\n"
                f"💸 **Đã trừ:** `-{cost}` coin\n"
                f"💰 **Số dư:** `{format_number(target_user.balance)}` coin\n\n"
                f"⚙️ Hệ thống sẽ **auto-restart** nếu script crash trong thời gian treo.",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=markup
            )

        # PIN/TREO - THÔNG TIN
        elif data.startswith("pininfo_"):
            _, script_user_id, file_name = data.split('_', 2)
            script_user_id = int(script_user_id)

            if user_id != script_user_id and not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không có quyền!", show_alert=True)
                return

            pin_until = db.get_file_pinned_until(script_user_id, file_name)
            if not is_pin_active(pin_until):
                bot.answer_callback_query(call.id, "ℹ️ File hiện không treo.", show_alert=True)
                return

            days_left = pin_remaining_days(pin_until)
            markup = types.InlineKeyboardMarkup(row_width=2)
            markup.row(
                types.InlineKeyboardButton("➕ Gia hạn", callback_data=f"pin_{script_user_id}_{file_name}"),
                types.InlineKeyboardButton("❌ Hủy treo", callback_data=f"unpin_{script_user_id}_{file_name}")
            )
            markup.row(
                types.InlineKeyboardButton("🔙 Quay Lại", callback_data=f"file_{script_user_id}_{file_name}")
            )

            bot.edit_message_text(
                f"📌 **THÔNG TIN TREO**\n\n"
                f"📄 **File:** `{file_name}`\n"
                f"⏳ **Treo tới:** `{pin_until.strftime('%H:%M %d/%m/%Y')}`\n"
                f"🕒 **Còn:** `{days_left}` ngày\n\n"
                f"Trong thời gian treo, hệ thống sẽ auto-restart nếu script crash.",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=markup
            )
            bot.answer_callback_query(call.id)

        # PIN/TREO - HỦY
        elif data.startswith("unpin_"):
            _, script_user_id, file_name = data.split('_', 2)
            script_user_id = int(script_user_id)

            if user_id != script_user_id and not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không có quyền!", show_alert=True)
                return

            db.clear_file_pin(script_user_id, file_name)

            bot.answer_callback_query(call.id, "✅ Đã hủy treo!")
            markup = create_file_control_menu(script_user_id, file_name)
            bot.edit_message_reply_markup(
                call.message.chat.id,
                call.message.message_id,
                reply_markup=markup
            )

        # START SCRIPT
        elif data.startswith("start_"):
            _, script_user_id, file_name = data.split('_', 2)
            script_user_id = int(script_user_id)
            
            if user_id != script_user_id and not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không có quyền!", show_alert=True)
                return
            
            bot.answer_callback_query(call.id, "🔄 Đang khởi chạy...")
            
            folder = get_user_folder(script_user_id)
            file_path = os.path.join(folder, file_name)
            
            if not os.path.exists(file_path):
                bot.edit_message_text(
                    f"❌ **FILE KHÔNG TỒN TẠI!**",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    parse_mode='Markdown',
                    reply_markup=ikb_row(
                        types.InlineKeyboardButton("🔙 Quay Lại", callback_data="my_files")
                    )
                )
                db.remove_user_file(script_user_id, file_name)
                return
            
            file_type = 'py' if file_name.endswith('.py') else 'js'
            
            if file_type == 'py':
                success = script_manager.run_python_script(
                    file_path, script_user_id, folder, file_name, call.message
                )
            else:
                success = script_manager.run_js_script(
                    file_path, script_user_id, folder, file_name, call.message
                )
            
            if success:
                markup = create_file_control_menu(script_user_id, file_name)
                bot.edit_message_reply_markup(
                    call.message.chat.id,
                    call.message.message_id,
                    reply_markup=markup
                )
        
        # STOP SCRIPT
        elif data.startswith("stop_"):
            _, script_user_id, file_name = data.split('_', 2)
            script_user_id = int(script_user_id)
            
            if user_id != script_user_id and not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không có quyền!", show_alert=True)
                return
            
            if script_manager.stop_script(script_user_id, file_name):
                bot.answer_callback_query(call.id, "✅ Đã dừng script!")
                
                markup = create_file_control_menu(script_user_id, file_name)
                bot.edit_message_reply_markup(
                    call.message.chat.id,
                    call.message.message_id,
                    reply_markup=markup
                )
            else:
                bot.answer_callback_query(call.id, "❌ Script không đang chạy!", show_alert=True)
        
        # RESTART SCRIPT
        elif data.startswith("restart_"):
            _, script_user_id, file_name = data.split('_', 2)
            script_user_id = int(script_user_id)
            
            if user_id != script_user_id and not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không có quyền!", show_alert=True)
                return
            
            bot.answer_callback_query(call.id, "🔄 Đang restart...")
            
            script_manager.stop_script(script_user_id, file_name)
            time.sleep(2)
            
            folder = get_user_folder(script_user_id)
            file_path = os.path.join(folder, file_name)
            file_type = 'py' if file_name.endswith('.py') else 'js'
            
            if file_type == 'py':
                script_manager.run_python_script(
                    file_path, script_user_id, folder, file_name, call.message
                )
            else:
                script_manager.run_js_script(
                    file_path, script_user_id, folder, file_name, call.message
                )
            
            markup = create_file_control_menu(script_user_id, file_name)
            bot.edit_message_reply_markup(
                call.message.chat.id,
                call.message.message_id,
                reply_markup=markup
            )
        
        # DELETE SCRIPT
        elif data.startswith("delete_"):
            _, script_user_id, file_name = data.split('_', 2)
            script_user_id = int(script_user_id)
            
            if user_id != script_user_id and not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không có quyền!", show_alert=True)
                return
            
            script_manager.stop_script(script_user_id, file_name)
            
            folder = get_user_folder(script_user_id)
            file_path = os.path.join(folder, file_name)
            log_path = os.path.join(folder, f"{os.path.splitext(file_name)[0]}.log")
            
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                if os.path.exists(log_path):
                    os.remove(log_path)
            except Exception as e:
                logger.error(f"Lỗi xóa file: {e}")
            
            db.remove_user_file(script_user_id, file_name)
            
            bot.answer_callback_query(call.id, "✅ Đã xóa file!")
            
            files = db.get_user_files(user_id)
            
            if files:
                markup = create_files_menu(user_id)
                bot.edit_message_text(
                    f"📁 **FILE CỦA BẠN** (Tổng: {len(files)})\n\n"
                    f"Chọn file để quản lý:",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    parse_mode='Markdown',
                    reply_markup=markup
                )
            else:
                bot.edit_message_text(
                    "📁 **FILE CỦA BẠN**\n\nBạn chưa có file nào.",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    parse_mode='Markdown',
                    reply_markup=ikb_row(
                        types.InlineKeyboardButton("🔙 Quay Lại", callback_data="main_menu")
                    )
                )
        
        # VIEW LOGS
        elif data.startswith("logs_"):
            _, script_user_id, file_name = data.split('_', 2)
            script_user_id = int(script_user_id)
            
            if user_id != script_user_id and not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không có quyền!", show_alert=True)
                return
            
            logs = script_manager.get_logs(script_user_id, file_name, 50)
            
            bot.answer_callback_query(call.id)
            
            # Gửi log dưới dạng file nếu quá dài
            if len(logs) > 3500:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False, encoding='utf-8') as f:
                    f.write(logs)
                    temp_path = f.name
                
                with open(temp_path, 'rb') as f:
                    bot.send_document(
                        user_id,
                        f,
                        caption=f"📜 Logs của `{file_name}`",
                        parse_mode='Markdown'
                    )
                
                os.unlink(temp_path)
            else:
                bot.send_message(
                    user_id,
                    f"📜 **LOGS CỦA `{file_name}`**\n\n```\n{logs}\n```",
                    parse_mode='Markdown'
                )
        
        # DOWNLOAD FILE
        elif data.startswith("download_"):
            _, script_user_id, file_name = data.split('_', 2)
            script_user_id = int(script_user_id)
            
            if user_id != script_user_id and not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không có quyền!", show_alert=True)
                return
            
            folder = get_user_folder(script_user_id)
            file_path = os.path.join(folder, file_name)
            
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    bot.send_document(
                        user_id,
                        f,
                        caption=f"📥 File `{file_name}`",
                        parse_mode='Markdown'
                    )
                bot.answer_callback_query(call.id, "✅ Đã gửi file!")
            else:
                bot.answer_callback_query(call.id, "❌ File không tồn tại!", show_alert=True)
        
        # ADMIN PANEL
        elif data == "admin_panel":
            if not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không phải admin!", show_alert=True)
                return
            
            bot.answer_callback_query(call.id)
            stats = db.get_statistics()
            
            bot.edit_message_text(
                f"👑 **ADMIN PANEL**\n\n"
                f"📊 **THỐNG KÊ NHANH:**\n"
                f"• 👥 Users: {stats['total_users']}\n"
                f"• 💰 Tổng coin: {format_number(stats['total_coins'])}\n"
                f"• 🤖 Scripts: {stats['running_scripts']}\n"
                f"• 🚫 Banned: {stats['banned_users']}",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=create_admin_panel_menu()
            )
        

        # ADMIN - CLEAR RAM
        elif data == "admin_clear_ram":
            if not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không phải admin!", show_alert=True)
                return

            bot.answer_callback_query(call.id, "🧹 Đang dọn RAM...")
            proc = psutil.Process(os.getpid())
            before = proc.memory_info().rss

            # dọn rác python
            try:
                gc.collect()
            except Exception:
                pass

            # cố gắng trả heap về OS (Linux)
            trimmed = False
            try:
                import ctypes
                libc = ctypes.CDLL("libc.so.6")
                if hasattr(libc, "malloc_trim"):
                    libc.malloc_trim(0)
                    trimmed = True
            except Exception:
                trimmed = False

            # dọn temp file cũ
            removed = 0
            try:
                now_ts = time.time()
                for fn in os.listdir(TEMP_DIR):
                    fp = os.path.join(TEMP_DIR, fn)
                    try:
                        if os.path.isfile(fp):
                            if now_ts - os.path.getmtime(fp) > 24 * 3600:
                                os.remove(fp)
                                removed += 1
                    except Exception:
                        pass
            except Exception:
                pass

            after = proc.memory_info().rss
            diff = before - after

            bot.edit_message_text(
                f"🧹 **CLEAR RAM**\n\n"
                f"📌 **RSS trước:** `{before/1024/1024:.2f} MB`\n"
                f"📌 **RSS sau:** `{after/1024/1024:.2f} MB`\n"
                f"📉 **Giảm:** `{diff/1024/1024:.2f} MB`\n"
                f"🧠 **malloc_trim:** `{trimmed}`\n"
                f"🗑️ **Xóa temp cũ:** `{removed}` file\n",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=create_admin_panel_menu()
            )

        # ADMIN - PIN/TREO MANAGER
        elif data == "admin_pins" or data.startswith("admin_pins_page_"):
            if not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không phải admin!", show_alert=True)
                return

            if data.startswith("admin_pins_page_"):
                try:
                    page = int(data.split('_')[-1])
                except Exception:
                    page = 1
            else:
                page = 1

            limit = 5
            pins, total = db.get_pinned_files(limit, page)
            max_page = max(1, (total + limit - 1) // limit)

            text_p = f"📌 **DANH SÁCH FILE ĐANG TREO**\n\n"
            text_p += f"📄 Tổng: `{total}` | Trang: `{page}/{max_page}`\n\n"

            if not pins:
                text_p += "📭 Không có file nào đang treo."
            else:
                for i, p in enumerate(pins, 1):
                    until = parse_iso_datetime(p.get('pinned_until'))
                    days_left = pin_remaining_days(until) if is_pin_active(until) else 0
                    name = p.get('first_name') or p.get('username') or ''
                    who = f"{name}" if name else str(p.get('user_id'))
                    text_p += (
                        f"{i}. 👤 `{p.get('user_id')}` ({who})\n"
                        f"   📄 `{p.get('file_name')}`\n"
                        f"   ⏳ Tới: `{until.strftime('%H:%M %d/%m/%Y') if until else 'N/A'}` (còn `{days_left}`d)\n\n"
                    )

            markup = types.InlineKeyboardMarkup(row_width=3)

            # nút hủy theo index
            if pins:
                for i, p in enumerate(pins, 1):
                    markup.add(types.InlineKeyboardButton(f"❌ Hủy #{i}", callback_data=f"unpin_{p.get('user_id')}_{p.get('file_name')}"))

            # phân trang
            prev_cb = f"admin_pins_page_{page-1}" if page > 1 else "noop"
            next_cb = f"admin_pins_page_{page+1}" if page < max_page else "noop"
            markup.row(
                types.InlineKeyboardButton("⏮️", callback_data=prev_cb),
                types.InlineKeyboardButton(f"{page}/{max_page}", callback_data="noop"),
                types.InlineKeyboardButton("⏭️", callback_data=next_cb)
            )
            markup.row(
                types.InlineKeyboardButton("🔙 Quay Lại", callback_data="admin_panel")
            )

            bot.edit_message_text(
                text_p,
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=markup
            )
            bot.answer_callback_query(call.id)

        # ADMIN - USERS
        elif data == "admin_users":
            if not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không phải admin!", show_alert=True)
                return
            
            bot.answer_callback_query(call.id)
            users, total = db.get_all_users(1, 5)
            
            text = f"👥 **DANH SÁCH USERS** (Tổng: {total})\n\n"
            for u in users:
                status = "🟢" if not u['is_banned'] else "🔴"
                name = u['first_name'] or u['username'] or f"User {u['user_id']}"
                text += f"{status} **{name}**\n"
                text += f"   📝 ID: `{u['user_id']}` | 💰 {u['balance']} Coin\n"
                text += f"   👥 Ref: {u['referral_count']} | 📅 {datetime.fromisoformat(u['created_at']).strftime('%d/%m/%Y') if u['created_at'] else 'N/A'}\n\n"
            
            markup = types.InlineKeyboardMarkup(row_width=3)
            markup.row(
                types.InlineKeyboardButton("⏮️", callback_data="admin_users_page_1"),
                types.InlineKeyboardButton(f"1/{(total+4)//5}", callback_data="noop"),
                types.InlineKeyboardButton("⏭️", callback_data=f"admin_users_page_2")
            )
            markup.row(
                types.InlineKeyboardButton("🔍 Tìm kiếm", callback_data="admin_search"),
                types.InlineKeyboardButton("🔙 Quay Lại", callback_data="admin_panel")
            )
            
            bot.edit_message_text(
                text,
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=markup
            )
        
        # ADMIN - COINS
        elif data == "admin_coins":
            if not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không phải admin!", show_alert=True)
                return
            
            bot.answer_callback_query(call.id)
            
            bot.edit_message_text(
                "💰 **QUẢN LÝ COIN**\n\n"
                "**Các lệnh:**\n"
                "• `/addcoin user_id amount` - Cộng coin\n"
                "• `/removecoin user_id amount` - Trừ coin\n"
                "• `/setcoin user_id amount` - Set coin\n\n"
                "**Ví dụ:**\n"
                "`/addcoin 12345678 100`",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=ikb_row(
                    types.InlineKeyboardButton("🔙 Quay Lại", callback_data="admin_panel")
                )
            )
        
        # ADMIN - ADD ADMIN
        elif data == "admin_add":
            if user_id != OWNER_ID:
                bot.answer_callback_query(call.id, "⛔ Chỉ Owner mới có quyền này!", show_alert=True)
                return
            
            bot.answer_callback_query(call.id)
            
            msg = bot.send_message(
                user_id,
                "👑 **THÊM ADMIN MỚI**\n\nNhập ID của user cần thêm làm admin:"
            )
            bot.register_next_step_handler(msg, process_add_admin)
        
        # ADMIN - REMOVE ADMIN
        elif data == "admin_remove":
            if user_id != OWNER_ID:
                bot.answer_callback_query(call.id, "⛔ Chỉ Owner mới có quyền này!", show_alert=True)
                return
            
            bot.answer_callback_query(call.id)
            
            admins = db.get_admins()
            admin_list = "\n".join([f"• `{a['user_id']}` - {a['first_name'] or a['username']}" for a in admins if a['user_id'] != OWNER_ID])
            
            msg = bot.send_message(
                user_id,
                f"👑 **XÓA ADMIN**\n\n**Danh sách admin hiện tại:**\n{admin_list}\n\nNhập ID của admin cần xóa:"
            )
            bot.register_next_step_handler(msg, process_remove_admin)
        
        # ADMIN - STATS
        elif data == "admin_stats":
            if not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không phải admin!", show_alert=True)
                return
            
            bot.answer_callback_query(call.id)
            stats = db.get_statistics()
            running_stats = script_manager.get_stats()
            
            # Thống kê chi tiết
            with db.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('SELECT AVG(balance) as avg FROM users')
                avg_balance = cursor.fetchone()['avg'] or 0
                
                cursor.execute('SELECT COUNT(*) FROM users WHERE created_at > datetime("now", "-7 days")')
                new_week = cursor.fetchone()[0]
                
                cursor.execute('''
                    SELECT type, COUNT(*) as count, SUM(amount) as total 
                    FROM transactions 
                    WHERE created_at > datetime("now", "-7 days")
                    GROUP BY type
                ''')
                tx_stats = cursor.fetchall()
            
            text = f"📊 **ADMIN STATISTICS**\n\n"
            text += f"👥 **USERS:**\n"
            text += f"• Tổng: {stats['total_users']}\n"
            text += f"• Mới 7 ngày: {new_week}\n"
            text += f"• Active hôm nay: {stats['active_today']}\n"
            text += f"• Banned: {stats['banned_users']}\n\n"
            
            text += f"💰 **COIN:**\n"
            text += f"• Tổng: {format_number(stats['total_coins'])}\n"
            text += f"• Trung bình: {format_number(int(avg_balance))}\n"
            text += f"• Tổng referrals: {stats['total_referrals']}\n\n"
            
            text += f"🤖 **SCRIPTS:**\n"
            text += f"• Đang chạy: {running_stats['total_running']}\n"
            text += f"• Python: {running_stats['python']}\n"
            text += f"• JavaScript: {running_stats['javascript']}\n\n"
            
            text += f"📈 **GIAO DỊCH 7 NGÀY:**\n"
            for tx in tx_stats:
                text += f"• {tx['type']}: {tx['count']} gd | {format_number(tx['total'])} Coin\n"
            
            bot.edit_message_text(
                text,
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=ikb_row(
                    types.InlineKeyboardButton("🔙 Quay Lại", callback_data="admin_panel")
                )
            )
        
        # ADMIN - BAN
        elif data == "admin_ban":
            if not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không phải admin!", show_alert=True)
                return
            
            bot.answer_callback_query(call.id)
            
            msg = bot.send_message(
                user_id,
                "🚫 **BAN USER**\n\nNhập: `user_id minutes reason`\n"
                "Ví dụ: `12345678 30 Spam`\n"
                "(minutes = 0 để unban)"
            )
            bot.register_next_step_handler(msg, process_ban_user)
        
        # ADMIN - CHECK IP
        elif data == "admin_check_ip":
            if not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không phải admin!", show_alert=True)
                return
            
            bot.answer_callback_query(call.id)
            
            msg = bot.send_message(
                user_id,
                "🔍 **CHECK IP**\n\nNhập IP hoặc User ID để kiểm tra:"
            )
            bot.register_next_step_handler(msg, process_check_ip)
        
        # ADMIN - SCRIPTS
        elif data == "admin_scripts":
            if not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không phải admin!", show_alert=True)
                return
            
            bot.answer_callback_query(call.id)
            running = script_manager.get_all_running()
            
            if not running:
                bot.edit_message_text(
                    "📭 **KHÔNG CÓ SCRIPT NÀO ĐANG CHẠY**",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    parse_mode='Markdown',
                    reply_markup=ikb_row(
                        types.InlineKeyboardButton("🔙 Quay Lại", callback_data="admin_panel")
                    )
                )
                return
            
            text = "🤖 **SCRIPTS ĐANG CHẠY:**\n\n"
            for s in running:
                uptime = (datetime.now() - s['start_time']).seconds
                hours = uptime // 3600
                minutes = (uptime % 3600) // 60
                text += f"• **{s['file_name']}** ({s['type']})\n"
                text += f"  👤 User: `{s['user_id']}` | 🆔 PID: {s['pid']}\n"
                text += f"  ⏱️ Uptime: {hours}h{minutes}m\n\n"
            
            bot.edit_message_text(
                text,
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=ikb_row(
                    types.InlineKeyboardButton("🔙 Quay Lại", callback_data="admin_panel")
                )
            )
        
        # BROADCAST
        elif data == "broadcast":
            if not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không phải admin!", show_alert=True)
                return
            
            bot.answer_callback_query(call.id)
            start_broadcast(call.message)
        
        # CONFIRM BROADCAST
        elif data.startswith("confirm_broadcast_"):
            if not db.is_admin(user_id):
                bot.answer_callback_query(call.id, "⛔ Bạn không phải admin!", show_alert=True)
                return
            
            bot.answer_callback_query(call.id, "🔄 Đang gửi broadcast...")
            
            try:
                with open(os.path.join(TEMP_DIR, 'broadcast_temp.json'), 'r', encoding='utf-8') as f:
                    broadcast_data = json.load(f)
            except:
                bot.edit_message_text(
                    "❌ **LỖI**\n\nKhông tìm thấy nội dung broadcast!",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    parse_mode='Markdown'
                )
                return
            
            active_users = db.get_active_users(60*24*7)  # 7 ngày
            sent = 0
            failed = 0
            
            progress_msg = bot.send_message(
                user_id,
                f"📢 Đang gửi broadcast... 0/{len(active_users)}"
            )
            
            for i, target_id in enumerate(active_users, 1):
                try:
                    if broadcast_data['content_type'] == 'text':
                        bot.send_message(target_id, broadcast_data['text'])
                    elif broadcast_data['content_type'] == 'photo':
                        bot.send_photo(
                            target_id,
                            broadcast_data['file_id'],
                            caption=broadcast_data['caption']
                        )
                    elif broadcast_data['content_type'] == 'video':
                        bot.send_video(
                            target_id,
                            broadcast_data['file_id'],
                            caption=broadcast_data['caption']
                        )
                    elif broadcast_data['content_type'] == 'document':
                        bot.send_document(
                            target_id,
                            broadcast_data['file_id'],
                            caption=broadcast_data['caption']
                        )
                    elif broadcast_data['content_type'] == 'audio':
                        bot.send_audio(
                            target_id,
                            broadcast_data['file_id'],
                            caption=broadcast_data['caption']
                        )
                    elif broadcast_data['content_type'] == 'voice':
                        bot.send_voice(
                            target_id,
                            broadcast_data['file_id'],
                            caption=broadcast_data['caption']
                        )
                    sent += 1
                    
                    if i % 10 == 0:
                        bot.edit_message_text(
                            f"📢 Đang gửi broadcast... {i}/{len(active_users)}",
                            progress_msg.chat.id,
                            progress_msg.message_id
                        )
                    
                    time.sleep(0.1)  # Tránh rate limit
                    
                except Exception as e:
                    failed += 1
                    logger.error(f"Lỗi gửi broadcast đến {target_id}: {e}")
            
            try:
                os.remove(os.path.join(TEMP_DIR, 'broadcast_temp.json'))
                bot.delete_message(progress_msg.chat.id, progress_msg.message_id)
            except:
                pass
            
            bot.edit_message_text(
                f"📢 **BROADCAST HOÀN TẤT**\n\n"
                f"✅ **Thành công:** `{sent}` users\n"
                f"❌ **Thất bại:** `{failed}` users\n"
                f"👥 **Tổng:** `{len(active_users)}` users",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=ikb_row(
                    types.InlineKeyboardButton("🔙 Quay Lại", callback_data="admin_panel")
                )
            )
        
        # CANCEL BROADCAST
        elif data == "cancel_broadcast":
            bot.answer_callback_query(call.id, "❌ Đã hủy broadcast")
            bot.delete_message(call.message.chat.id, call.message.message_id)
            
            try:
                os.remove(os.path.join(TEMP_DIR, 'broadcast_temp.json'))
            except:
                pass
        
        # NOOP (nút giả)
        elif data == "noop":
            bot.answer_callback_query(call.id)
        
        # UNKNOWN
        else:
            bot.answer_callback_query(call.id, "❓ Không xác định")
    
    except Exception as e:
        logger.error(f"Lỗi xử lý callback '{data}': {e}", exc_info=True)
        try:
            bot.answer_callback_query(call.id, "❌ Có lỗi xảy ra!", show_alert=True)
        except:
            pass

# Helper function for inline keyboard row
def ikb_row(*buttons):
    markup = types.InlineKeyboardMarkup()
    if buttons:
        markup.row(*buttons)
    return markup

# ==================== ADMIN PROCESSORS ====================
def process_add_admin(message):
    user_id = message.from_user.id
    
    if user_id != OWNER_ID:
        bot.reply_to(message, "⛔ Chỉ Owner mới có quyền này!")
        return
    
    try:
        new_admin_id = int(message.text.strip())
        
        if new_admin_id <= 0:
            bot.reply_to(message, "❌ ID không hợp lệ!")
            return
        
        if new_admin_id == user_id:
            bot.reply_to(message, "❌ Bạn đã là Owner rồi!")
            return
        
        db.add_admin(new_admin_id, user_id)
        
        bot.reply_to(
            message,
            f"✅ **ĐÃ THÊM ADMIN**\n\n"
            f"👤 User `{new_admin_id}` đã trở thành admin!",
            parse_mode='Markdown',
            reply_markup=create_main_menu(user_id)
        )
        
        try:
            bot.send_message(
                new_admin_id,
                "🎉 **BẠN ĐÃ ĐƯỢC THÊM LÀM ADMIN!**\n\n"
                "Sử dụng nút 👑 Admin để quản lý bot.",
                parse_mode='Markdown'
            )
        except:
            pass
            
    except ValueError:
        bot.reply_to(message, "❌ Vui lòng nhập ID hợp lệ!")

def process_remove_admin(message):
    user_id = message.from_user.id
    
    if user_id != OWNER_ID:
        bot.reply_to(message, "⛔ Chỉ Owner mới có quyền này!")
        return
    
    try:
        admin_id = int(message.text.strip())
        
        if admin_id == OWNER_ID:
            bot.reply_to(message, "❌ Không thể xóa Owner!")
            return
        
        db.remove_admin(admin_id)
        
        bot.reply_to(
            message,
            f"✅ **ĐÃ XÓA ADMIN**\n\n"
            f"👤 User `{admin_id}` không còn là admin!",
            parse_mode='Markdown',
            reply_markup=create_main_menu(user_id)
        )
        
        try:
            bot.send_message(
                admin_id,
                "ℹ️ **BẠN ĐÃ BỊ XÓA KHỎI DANH SÁCH ADMIN.**",
                parse_mode='Markdown'
            )
        except:
            pass
            
    except ValueError:
        bot.reply_to(message, "❌ Vui lòng nhập ID hợp lệ!")

def process_ban_user(message):
    user_id = message.from_user.id
    
    if not db.is_admin(user_id):
        bot.reply_to(message, "⛔ Bạn không phải admin!")
        return
    
    try:
        parts = message.text.strip().split(maxsplit=2)
        target_id = int(parts[0])
        minutes = int(parts[1]) if len(parts) > 1 else 30
        reason = parts[2] if len(parts) > 2 else "Không rõ lý do"
        
        if target_id == OWNER_ID:
            bot.reply_to(message, "❌ Không thể ban Owner!")
            return
        
        user = db.get_user(target_id)
        if not user:
            bot.reply_to(message, "❌ User không tồn tại!")
            return
        
        if minutes == 0:
            # Unban
            user.is_banned = False
            user.ban_until = None
            db.update_user(user)
            
            bot.reply_to(
                message,
                f"✅ **ĐÃ UNBAN USER**\n\n"
                f"👤 User: `{target_id}`",
                parse_mode='Markdown'
            )
            
            try:
                bot.send_message(
                    target_id,
                    "🎉 **BẠN ĐÃ ĐƯỢC UNBAN!**\n\n"
                    "Có thể sử dụng bot bình thường.",
                    parse_mode='Markdown'
                )
            except:
                pass
        else:
            # Ban
            user.is_banned = True
            user.ban_until = datetime.now() + timedelta(minutes=minutes)
            db.update_user(user)
            
            # Ban IP nếu có
            if user.ip_address and user.ip_address.startswith('tg_'):
                with db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO banned_ips (ip_address, reason, banned_by)
                        VALUES (?, ?, ?)
                    ''', (user.ip_address, reason, user_id))
            
            bot.reply_to(
                message,
                f"🚫 **ĐÃ BAN USER**\n\n"
                f"👤 **User:** `{target_id}`\n"
                f"⏰ **Thời gian:** `{minutes}` phút\n"
                f"📝 **Lý do:** {reason}\n"
                f"📅 **Hết hạn:** {user.ban_until.strftime('%H:%M %d/%m/%Y')}",
                parse_mode='Markdown'
            )
            
            try:
                bot.send_message(
                    target_id,
                    f"🚫 **BẠN ĐÃ BỊ BAN**\n\n"
                    f"⏰ **Thời gian:** `{minutes}` phút\n"
                    f"📝 **Lý do:** {reason}\n"
                    f"📅 **Hết hạn:** {user.ban_until.strftime('%H:%M %d/%m/%Y')}",
                    parse_mode='Markdown'
                )
            except:
                pass
            
    except (ValueError, IndexError) as e:
        bot.reply_to(message, "❌ Format: `user_id minutes reason`\nVí dụ: `12345678 30 Spam`")

def process_check_ip(message):
    user_id = message.from_user.id
    
    if not db.is_admin(user_id):
        bot.reply_to(message, "⛔ Bạn không phải admin!")
        return
    
    query = message.text.strip()
    
    try:
        # Check by user_id
        if query.isdigit():
            user = db.get_user(int(query))
            if user and user.ip_address:
                ip = user.ip_address
            else:
                bot.reply_to(message, "❌ Không tìm thấy user hoặc IP!")
                return
        else:
            ip = query
        
        with db.get_connection() as conn:
            cursor = conn.cursor()
            
            # Check anti_buff
            cursor.execute('SELECT * FROM anti_buff WHERE ip_address = ?', (ip,))
            buff_data = cursor.fetchone()
            
            # Check banned_ips
            cursor.execute('SELECT * FROM banned_ips WHERE ip_address = ?', (ip,))
            banned_ip = cursor.fetchone()
            
            # Find users with this IP
            cursor.execute('SELECT user_id, first_name, username, is_banned FROM users WHERE ip_address = ?', (ip,))
            users = cursor.fetchall()
            
            # Find referrals from this IP
            cursor.execute('''
                SELECT r.*, u.first_name, u.username 
                FROM referrals r
                JOIN users u ON r.referred_id = u.user_id
                WHERE r.ip_address = ?
                ORDER BY r.created_at DESC
            ''', (ip,))
            referrals = cursor.fetchall()
        
        text = f"🔍 **KẾT QUẢ CHECK IP**\n\n"
        text += f"🌐 **IP:** `{ip}`\n\n"
        
        if banned_ip:
            text += f"🚫 **IP BỊ BAN!**\n"
            text += f"📝 Lý do: {banned_ip['reason']}\n"
            text += f"📅 Banned: {banned_ip['banned_at']}\n\n"
        
        if buff_data:
            text += f"📊 **ANTI-BUFF:**\n"
            text += f"• Ref count: {buff_data['referral_count']}\n"
            text += f"• Last ref: {buff_data['last_referral_time']}\n"
            text += f"• Suspicious: {buff_data['suspicious_activities']}\n"
            text += f"• Blocked: {'Có' if buff_data['is_blocked'] else 'Không'}\n\n"
        
        if users:
            text += f"👥 **USERS CÙNG IP:**\n"
            for u in users:
                status = "🟢" if not u['is_banned'] else "🔴"
                name = u['first_name'] or u['username'] or f"User {u['user_id']}"
                text += f"{status} `{u['user_id']}` - {name}\n"
            text += "\n"
        
        if referrals:
            text += f"📋 **REFERRALS TỪ IP NÀY:**\n"
            for r in referrals[:5]:
                name = r['first_name'] or r['username'] or f"User {r['referred_id']}"
                text += f"• {name} - {r['created_at']}\n"
            if len(referrals) > 5:
                text += f"  ... và {len(referrals) - 5} người khác\n"
        
        bot.reply_to(message, text, parse_mode='Markdown')
        
    except Exception as e:
        bot.reply_to(message, f"❌ Lỗi: {e}")

# ==================== COMMAND HANDLERS (ADMIN) ====================
@bot.message_handler(commands=['clearram'])
def cmd_clear_ram(message):
    user_id = message.from_user.id
    if not db.is_admin(user_id):
        bot.reply_to(message, "⛔ Bạn không phải admin!")
        return

    proc = psutil.Process(os.getpid())
    before = proc.memory_info().rss

    try:
        gc.collect()
    except Exception:
        pass

    trimmed = False
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6")
        if hasattr(libc, "malloc_trim"):
            libc.malloc_trim(0)
            trimmed = True
    except Exception:
        trimmed = False

    after = proc.memory_info().rss
    diff = before - after

    bot.reply_to(
        message,
        f"🧹 **CLEAR RAM**\n\n"
        f"📌 RSS trước: `{before/1024/1024:.2f} MB`\n"
        f"📌 RSS sau: `{after/1024/1024:.2f} MB`\n"
        f"📉 Giảm: `{diff/1024/1024:.2f} MB`\n"
        f"🧠 malloc_trim: `{trimmed}`",
        parse_mode='Markdown'
    )

@bot.message_handler(commands=['unpin', 'huytreo'])
def cmd_unpin(message):
    user_id = message.from_user.id
    if not db.is_admin(user_id):
        bot.reply_to(message, "⛔ Bạn không phải admin!")
        return

    try:
        parts = message.text.split(maxsplit=2)
        if len(parts) < 3:
            bot.reply_to(message, "❌ Format: /unpin user_id file_name")
            return
        target_id = int(parts[1])
        file_name = sanitize_filename(parts[2])

        # kiểm tra tồn tại record
        info = db.get_user_file(target_id, file_name)
        if not info:
            bot.reply_to(message, "❌ File không tồn tại trong DB!")
            return

        db.clear_file_pin(target_id, file_name)
        bot.reply_to(message, f"✅ Đã hủy treo `{file_name}` của user `{target_id}`", parse_mode='Markdown')
    except Exception as e:
        bot.reply_to(message, f"❌ Lỗi: {e}")

@bot.message_handler(commands=['addcoin', 'removecoin', 'setcoin'])
def cmd_manage_coins(message):
    user_id = message.from_user.id
    
    if not db.is_admin(user_id):
        bot.reply_to(message, "⛔ Bạn không phải admin!")
        return
    
    try:
        parts = message.text.split()
        if len(parts) != 3:
            bot.reply_to(message, "❌ Format: /addcoin user_id amount hoặc /removecoin user_id amount")
            return
        
        cmd = parts[0][1:]  # Bỏ dấu /
        target_id = int(parts[1])
        amount = int(parts[2])
        
        if amount <= 0:
            bot.reply_to(message, "❌ Số coin phải lớn hơn 0!")
            return
        
        target_user = db.get_user(target_id)
        if not target_user:
            bot.reply_to(message, "❌ User không tồn tại!")
            return
        
        old_balance = target_user.balance
        
        if cmd == 'addcoin':
            target_user.balance += amount
            target_user.total_earned += amount
            db.add_transaction(
                target_id,
                amount,
                'admin_add',
                f'Admin +{amount} coin',
                target_user.balance
            )
            action = "cộng"
            change = f"+{amount}"
        elif cmd == 'removecoin':
            if target_user.balance < amount:
                bot.reply_to(message, "❌ User không đủ coin!")
                return
            target_user.balance -= amount
            db.add_transaction(
                target_id,
                -amount,
                'admin_remove',
                f'Admin -{amount} coin',
                target_user.balance
            )
            action = "trừ"
            change = f"-{amount}"
        else:  # setcoin
            target_user.balance = amount
            target_user.total_earned += max(0, amount - old_balance)
            db.add_transaction(
                target_id,
                amount - old_balance,
                'admin_set',
                f'Admin set coin: {old_balance} → {amount}',
                target_user.balance
            )
            action = "set"
            change = f"{amount}"
        
        db.update_user(target_user)
        
        bot.reply_to(
            message,
            f"✅ **ĐÃ {action.upper()} COIN**\n\n"
            f"👤 **User:** `{target_id}`\n"
            f"💰 **Thay đổi:** `{change}` Coin\n"
            f"💎 **Số dư cũ:** `{format_number(old_balance)}`\n"
            f"💎 **Số dư mới:** `{format_number(target_user.balance)}`",
            parse_mode='Markdown'
        )
        
        try:
            bot.send_message(
                target_id,
                f"💰 **CẬP NHẬT SỐ DƯ**\n\n"
                f"📝 **Thay đổi:** `{change}` Coin\n"
                f"💎 **Số dư mới:** `{format_number(target_user.balance)}`",
                parse_mode='Markdown'
            )
        except:
            pass
            
    except ValueError:
        bot.reply_to(message, "❌ Vui lòng nhập số hợp lệ!")

@bot.message_handler(commands=['userinfo'])
def cmd_userinfo(message):
    user_id = message.from_user.id
    
    if not db.is_admin(user_id):
        bot.reply_to(message, "⛔ Bạn không phải admin!")
        return
    
    try:
        parts = message.text.split()
        target_id = int(parts[1]) if len(parts) > 1 else user_id
        
        target = db.get_user(target_id)
        if not target:
            bot.reply_to(message, "❌ User không tồn tại!")
            return
        
        stats = db.get_referral_stats(target_id)
        files = db.get_user_files(target_id)
        
        text = f"👤 **THÔNG TIN USER**\n\n"
        text += f"🆔 **ID:** `{target.user_id}`\n"
        text += f"📝 **Username:** @{target.username}\n" if target.username else ""
        text += f"👤 **Tên:** {target.first_name}\n"
        text += f"💰 **Số dư:** {format_number(target.balance)} Coin\n"
        text += f"📈 **Đã kiếm:** {format_number(target.total_earned)} Coin\n"
        text += f"👥 **Ref count:** {target.referral_count}\n"
        text += f"💎 **Hoa hồng ref:** {format_number(target.referral_earnings)} Coin\n"
        text += f"🔥 **Daily streak:** {target.daily_streak}\n"
        text += f"📅 **Ngày tham gia:** {target.created_at.strftime('%d/%m/%Y %H:%M') if target.created_at else 'N/A'}\n"
        text += f"⏰ **Hoạt động cuối:** {target.last_active.strftime('%d/%m/%Y %H:%M') if target.last_active else 'N/A'}\n"
        text += f"🌐 **IP:** `{target.ip_address}`\n"
        text += f"🚫 **Banned:** {'Có' if target.is_banned else 'Không'}\n"
        if target.is_banned and target.ban_until:
            text += f"⏳ **Hết hạn ban:** {target.ban_until.strftime('%d/%m/%Y %H:%M')}\n"
        text += f"⚠️ **Suspicious:** {'Có' if target.is_suspicious else 'Không'}\n"
        text += f"⚠️ **Cảnh cáo:** {target.warning_count}\n"
        text += f"📁 **Files:** {len(files)}\n\n"
        
        if files:
            text += f"📁 **DANH SÁCH FILES:**\n"
            for f in files:
                running = "🟢" if f['is_running'] else "🔴"
                text += f"{running} {f['file_name']} ({f['file_type']}) - {f['run_count']} lần chạy\n"
        
        bot.reply_to(message, text, parse_mode='Markdown')
        
    except (ValueError, IndexError):
        bot.reply_to(message, "❌ Format: /userinfo [user_id]")

# ==================== FILE HANDLER ====================
@bot.message_handler(content_types=['document'])
def handle_document(message):
    user_id = message.from_user.id
    
    # Kiểm tra ban
    banned, ban_msg = check_ban(user_id)
    if banned:
        bot.reply_to(message, ban_msg)
        return
    
    # Cập nhật user
    user = check_and_update_user(
        user_id,
        message.from_user.username or "",
        message.from_user.first_name or "",
        get_client_ip(message)
    )
    
    # Kiểm tra suspicious
    check_suspicious(user)

    # Anti-spam upload
    ok_up, up_msg = spam_protector.check(user_id, "upload", SPAM_FILE_UPLOAD_LIMIT, SPAM_FILE_UPLOAD_WINDOW)
    if not ok_up:
        bot.reply_to(message, up_msg)
        return
    
    # Kiểm tra giới hạn file
    file_limit = get_user_file_limit(user_id)
    current_files = get_user_file_count(user_id)
    
    if current_files >= file_limit:
        limit_str = str(file_limit) if file_limit != float('inf') else "∞"
        bot.reply_to(
            message,
            f"⚠️ **ĐẠT GIỚI HẠN FILE!**\n\n"
            f"Hiện tại: `{current_files}/{limit_str}`\n"
            f"Vui lòng xóa bớt file cũ.",
            parse_mode='Markdown'
        )
        return
    
    doc = message.document
    file_name = sanitize_filename(doc.file_name)
    
    if not file_name:
        bot.reply_to(message, "❌ File không có tên!")
        return
    
    # Kiểm tra định dạng
    file_ext = os.path.splitext(file_name)[1].lower()
    if file_ext not in ['.py', '.js', '.zip']:
        bot.reply_to(
            message,
            "❌ **ĐỊNH DẠNG KHÔNG HỖ TRỢ!**\n\n"
            "Chỉ chấp nhận: `.py`, `.js`, `.zip`",
            parse_mode='Markdown'
        )
        return
    
    # Kiểm tra kích thước
    if doc.file_size > 20 * 1024 * 1024:
        bot.reply_to(
            message,
            "❌ **FILE QUÁ LỚN!**\n\nGiới hạn: 20MB",
            parse_mode='Markdown'
        )
        return
    
    try:
        # Forward cho owner
        try:
            bot.forward_message(OWNER_ID, message.chat.id, message.message_id)
            bot.send_message(
                OWNER_ID,
                f"📤 **UPLOAD MỚI**\n\n"
                f"👤 **User:** `{user_id}`\n"
                f"📄 **File:** `{file_name}`\n"
                f"📦 **Size:** {doc.file_size / 1024:.1f} KB",
                parse_mode='Markdown'
            )
        except:
            pass
        
        # Download file
        msg = bot.reply_to(message, f"⏳ Đang tải `{file_name}`...")
        file_info = bot.get_file(doc.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        
        # Quét virus/botnet cơ bản (heuristic)
        if file_ext != '.zip':
            ok_scan, scan_msg = file_scanner.scan_bytes(file_name, downloaded_file)
            if not ok_scan:
                bot.edit_message_text(
                    f"❌ **BỊ CHẶN BỞI ANTI-VIRUS**\n\n{scan_msg}",
                    message.chat.id,
                    msg.message_id,
                    parse_mode='Markdown'
                )
                return

        bot.edit_message_text(
            f"✅ Đã tải xong! Đang xử lý...",
            message.chat.id,
            msg.message_id
        )
        
        user_folder = get_user_folder(user_id)
        
        # Xử lý file
        if file_ext == '.zip':
            handle_zip_file(downloaded_file, file_name, user_id, user_folder, message, msg, doc.file_size)
        else:
            # Lưu file
            file_path = os.path.join(user_folder, file_name)
            with open(file_path, 'wb') as f:
                f.write(downloaded_file)
            
            # Lưu vào database
            file_type = 'py' if file_ext == '.py' else 'js'
            db.add_user_file(user_id, file_name, file_type, doc.file_size)
            
            bot.edit_message_text(
                f"✅ **UPLOAD THÀNH CÔNG!**\n\n"
                f"📄 **File:** `{file_name}`\n"
                f"📦 **Size:** {doc.file_size / 1024:.1f} KB\n"
                f"📁 **Đã lưu vào thư mục của bạn.**",
                message.chat.id,
                msg.message_id,
                parse_mode='Markdown'
            )
            
            # Hỏi có chạy luôn không
            markup = types.InlineKeyboardMarkup()
            markup.row(
                types.InlineKeyboardButton("▶️ Chạy Ngay", callback_data=f"start_{user_id}_{file_name}"),
                types.InlineKeyboardButton("🔙 Quay Lại", callback_data="my_files")
            )
            
            bot.send_message(
                user_id,
                f"🚀 **BẠN MUỐN CHẠY SCRIPT NGAY?**",
                parse_mode='Markdown',
                reply_markup=markup
            )
            
    except Exception as e:
        logger.error(f"Lỗi xử lý file {file_name} từ user {user_id}: {e}", exc_info=True)
        bot.reply_to(message, f"❌ Lỗi xử lý file: {str(e)}")

def handle_zip_file(downloaded_file, file_name, user_id, user_folder, message, status_msg, file_size):
    temp_dir = None
    
    try:
        temp_dir = tempfile.mkdtemp(prefix=f"user_{user_id}_", dir=TEMP_DIR)
        zip_path = os.path.join(temp_dir, file_name)
        
        # Lưu file zip
        with open(zip_path, 'wb') as f:
            f.write(downloaded_file)
        
        # Quét virus/botnet & chống zip-bomb
        ok_zip, zip_msg = file_scanner.scan_zip_safely(zip_path)
        if not ok_zip:
            bot.edit_message_text(
                f"❌ **BỊ CHẶN BỞI ANTI-VIRUS**\n\n{zip_msg}",
                message.chat.id,
                status_msg.message_id,
                parse_mode='Markdown'
            )
            return
        
        # Giải nén với kiểm tra an toàn
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Kiểm tra đường dẫn nguy hiểm
            for member in zip_ref.infolist():
                member_path = os.path.abspath(os.path.join(temp_dir, member.filename))
                if not member_path.startswith(os.path.abspath(temp_dir)):
                    raise zipfile.BadZipFile(f"Phát hiện đường dẫn nguy hiểm: {member.filename}")
            
            zip_ref.extractall(temp_dir)
        
        # Tìm file chính
        extracted_files = os.listdir(temp_dir)
        py_files = [f for f in extracted_files if f.endswith('.py')]
        js_files = [f for f in extracted_files if f.endswith('.js')]
        
        # Xử lý requirements.txt
        if 'requirements.txt' in extracted_files:
            bot.edit_message_text(
                "📦 Đang cài đặt Python dependencies...",
                message.chat.id,
                status_msg.message_id
            )
            
            req_path = os.path.join(temp_dir, 'requirements.txt')
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'install', '--user', '-r', req_path],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                logger.warning(f"Lỗi cài đặt requirements: {result.stderr}")
        
        # Xử lý package.json
        if 'package.json' in extracted_files:
            bot.edit_message_text(
                "📦 Đang cài đặt Node.js dependencies...",
                message.chat.id,
                status_msg.message_id
            )
            
            result = subprocess.run(
                ['npm', 'install', '--no-fund', '--no-audit'],
                cwd=temp_dir,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                logger.warning(f"Lỗi cài đặt npm: {result.stderr}")
        
        # Xác định file chính
        main_script = None
        file_type = None
        
        # Ưu tiên các tên phổ biến
        preferred_py = ['main.py', 'bot.py', 'app.py', 'run.py', 'index.py']
        preferred_js = ['index.js', 'main.js', 'bot.js', 'app.js', 'server.js']
        
        for p in preferred_py:
            if p in py_files:
                main_script = p
                file_type = 'py'
                break
        
        if not main_script:
            for p in preferred_js:
                if p in js_files:
                    main_script = p
                    file_type = 'js'
                    break
        
        # Nếu không có tên ưu tiên, lấy file đầu tiên
        if not main_script and py_files:
            main_script = py_files[0]
            file_type = 'py'
        elif not main_script and js_files:
            main_script = js_files[0]
            file_type = 'js'
        
        if not main_script:
            bot.edit_message_text(
                "❌ **KHÔNG TÌM THẤY FILE SCRIPT!**\n\n"
                "Zip phải chứa file `.py` hoặc `.js`",
                message.chat.id,
                status_msg.message_id,
                parse_mode='Markdown'
            )
            return
        

        # Quét lại file script chính sau khi giải nén (heuristic)
        try:
            main_path = os.path.join(temp_dir, main_script)
            if os.path.exists(main_path):
                with open(main_path, 'rb') as fp:
                    main_data = fp.read(VIRUS_SCAN_MAX_BYTES)
                ok_main, msg_main = file_scanner.scan_bytes(main_script, main_data)
                if not ok_main:
                    bot.edit_message_text(
                        f"❌ **BỊ CHẶN BỞI ANTI-VIRUS**\n\n{msg_main}",
                        message.chat.id,
                        status_msg.message_id,
                        parse_mode='Markdown'
                    )
                    return
        except Exception:
            pass

        # Di chuyển files vào thư mục user
        moved_files = []
        for item in extracted_files:
            src = os.path.join(temp_dir, item)
            dst = os.path.join(user_folder, item)
            
            if os.path.isdir(dst):
                shutil.rmtree(dst)
            elif os.path.exists(dst):
                os.remove(dst)
            
            shutil.move(src, dst)
            moved_files.append(item)
        
        # Lưu vào database
        db.add_user_file(user_id, main_script, file_type, file_size)
        
        bot.edit_message_text(
            f"✅ **GIẢI NÉN THÀNH CÔNG!**\n\n"
            f"📄 **File chính:** `{main_script}`\n"
            f"📁 **Đã giải nén:** {len(moved_files)} files\n"
            f"📦 **Tổng dung lượng:** {file_size / 1024:.1f} KB",
            message.chat.id,
            status_msg.message_id,
            parse_mode='Markdown'
        )
        
        # Hỏi có chạy luôn không
        markup = types.InlineKeyboardMarkup()
        markup.row(
            types.InlineKeyboardButton("▶️ Chạy Ngay", callback_data=f"start_{user_id}_{main_script}"),
            types.InlineKeyboardButton("🔙 Quay Lại", callback_data="my_files")
        )
        
        bot.send_message(
            user_id,
            f"🚀 **BẠN MUỐN CHẠY SCRIPT NGAY?**",
            parse_mode='Markdown',
            reply_markup=markup
        )
        
    except zipfile.BadZipFile as e:
        bot.edit_message_text(
            f"❌ **FILE ZIP LỖI!**\n\n{str(e)}",
            message.chat.id,
            status_msg.message_id,
            parse_mode='Markdown'
        )
    except subprocess.TimeoutExpired:
        bot.edit_message_text(
            "❌ **QUÁ THỜI GIAN CÀI ĐẶT DEPENDENCIES!**",
            message.chat.id,
            status_msg.message_id,
            parse_mode='Markdown'
        )
    except Exception as e:
        logger.error(f"Lỗi xử lý zip cho user {user_id}: {e}", exc_info=True)
        bot.edit_message_text(
            f"❌ **LỖI XỬ LÝ ZIP!**\n\n{str(e)}",
            message.chat.id,
            status_msg.message_id,
            parse_mode='Markdown'
        )
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

# ==================== HEALTH CHECK SERVER ====================
# Nhiều nền tảng host (Render/Koyeb/Railway/...) chạy "TCP/HTTP health check" vào 1 cổng (thường là 8000).
# Bot Telegram chạy polling sẽ KHÔNG tự mở cổng => bị restart liên tục (log: TCP health check failed).
_HEALTH_SERVER = None

def start_health_server():
    """Mở 1 HTTP server siêu nhẹ để pass health check của host."""
    global _HEALTH_SERVER

    # Ưu tiên PORT của host, fallback 8000 (đúng với log bạn gửi)
    try:
        port = int(os.getenv("PORT", "8000"))
    except Exception:
        port = 8000

    host = "0.0.0.0"

    try:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    except Exception:
        # Fallback cho Python cũ
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from socketserver import ThreadingMixIn

        class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
            daemon_threads = True

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"OK")
            except Exception:
                pass

        def do_HEAD(self):
            try:
                self.send_response(200)
                self.end_headers()
            except Exception:
                pass

        def log_message(self, format, *args):
            # tắt log request để đỡ spam
            return

    try:
        _HEALTH_SERVER = ThreadingHTTPServer((host, port), Handler)
    except OSError as e:
        logger.warning(f"⚠️ Không thể mở health server tại {host}:{port}: {e}")
        _HEALTH_SERVER = None
        return None

    t = threading.Thread(target=_HEALTH_SERVER.serve_forever, daemon=True)
    t.start()
    logger.info(f"🌐 Health server listening on {host}:{port}")
    return _HEALTH_SERVER

def stop_health_server():
    global _HEALTH_SERVER
    if _HEALTH_SERVER:
        try:
            _HEALTH_SERVER.shutdown()
        except Exception:
            pass
        try:
            _HEALTH_SERVER.server_close()
        except Exception:
            pass
        _HEALTH_SERVER = None


# ==================== CLEANUP ====================
def cleanup():
    logger.info("🧹 Đang dọn dẹp...")

    # Tắt health server (nếu có)
    try:
        stop_health_server()
    except Exception:
        pass
    
    # Dừng tất cả scripts
    running = script_manager.get_all_running()
    for script in running:
        script_manager.stop_script(script['user_id'], script['file_name'])
        logger.info(f"Đã dừng script {script['file_name']} của user {script['user_id']}")
    
    # Xóa captcha cũ
    for filename in os.listdir(CAPTCHA_DIR):
        if filename.startswith('captcha_'):
            filepath = os.path.join(CAPTCHA_DIR, filename)
            try:
                if time.time() - os.path.getctime(filepath) > 3600:
                    os.remove(filepath)
            except:
                pass
    
    # Xóa temp files cũ
    for filename in os.listdir(TEMP_DIR):
        filepath = os.path.join(TEMP_DIR, filename)
        try:
            if time.time() - os.path.getctime(filepath) > 3600:
                if os.path.isfile(filepath):
                    os.remove(filepath)
                elif os.path.isdir(filepath):
                    shutil.rmtree(filepath, ignore_errors=True)
        except:
            pass
    
    logger.info(f"✅ Đã dọn dẹp {len(running)} scripts và files tạm")

# ==================== MAIN ====================
if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("🤖 MARCO BOT - PHIÊN BẢN NÂNG CẤP")
    logger.info("=" * 60)
    logger.info(f"👑 OWNER ID: {OWNER_ID}")
    logger.info(f"📁 BASE DIR: {BASE_DIR}")
    logger.info(f"💾 DATABASE: {DATABASE_PATH}")
    logger.info(f"📝 LOGS DIR: {LOGS_DIR}")
    logger.info(f"🧩 CAPTCHA DIR: {CAPTCHA_DIR}")
    logger.info(f"📦 TEMP DIR: {TEMP_DIR}")
    logger.info("=" * 60)
    
    # Đăng ký cleanup
    atexit.register(cleanup)
    
    # Xử lý signal
    def signal_handler(sig, frame):
        logger.info("🛑 Nhận tín hiệu dừng, đang tắt...")
        cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start health server để pass TCP/HTTP health check của host
# (Nếu host không cần, nó vẫn chạy nhẹ và không ảnh hưởng)
start_health_server()

# Chạy bot (auto-retry vô hạn + backoff) để hạn chế "crash"
retry_count = 0
backoff = 5  # seconds

while True:
    try:
        logger.info("🚀 Bắt đầu polling...")

        # Thử skip_pending nếu thư viện hỗ trợ (tránh xử lý backlog khi restart)
        try:
            bot.infinity_polling(timeout=60, long_polling_timeout=30, skip_pending=True)
        except TypeError:
            bot.infinity_polling(timeout=60, long_polling_timeout=30)

        # Nếu polling thoát ra (hiếm), reset backoff và chạy lại
        retry_count = 0
        backoff = 5
        time.sleep(1)

    except requests.exceptions.ReadTimeout:
        retry_count += 1
        logger.warning(f"⏰ Read timeout (lần {retry_count}), khởi động lại polling sau {backoff}s...")
        time.sleep(backoff)
        backoff = min(backoff * 2, 60)

    except requests.exceptions.ConnectionError as e:
        retry_count += 1
        logger.error(f"🔌 Lỗi kết nối (lần {retry_count}): {e}. Thử lại sau {backoff}s...")
        time.sleep(backoff)
        backoff = min(backoff * 2, 60)

    except Exception as e:
        retry_count += 1
        logger.critical(f"💥 Lỗi nghiêm trọng (lần {retry_count}): {e}", exc_info=True)
        time.sleep(backoff)
        backoff = min(backoff * 2, 60)
