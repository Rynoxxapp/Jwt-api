from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
import my_pb2
import output_pb2
import jwt
from datetime import datetime
import time
from collections import OrderedDict
import logging
import urllib.parse
from flask_caching import Cache
import random

app = Flask(__name__)

# Cache configuration
cache = Cache(config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 300})  # 5 minutes cache
cache.init_app(app)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# Retry configuration
MAX_RETRIES = 3
RETRY_DELAY = 2

def make_cache_key(path: str, args: dict):
    """Generate cache key from path and arguments"""
    safe_args = {k: v for k, v in args.items() if k != 'retry'}
    return f"{path}?{urllib.parse.urlencode(sorted(safe_args.items()))}"

def encrypt_message(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)


def generate_random_ip():
    while True:
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))

        first = int(ip.split(".")[0])

        # Reserved/private ranges avoid karein
        if (
            first == 10 or
            first == 127 or
            first >= 224 or
            ip.startswith("192.168.") or
            ip.startswith("169.254.") or
            ip.startswith("172.16.") or
            ip.startswith("172.17.") or
            ip.startswith("172.18.") or
            ip.startswith("172.19.") or
            ip.startswith("172.2") or   # 172.20-29
            ip.startswith("172.30.") or
            ip.startswith("172.31.")
        ):
            continue

        return ip
        
        
def get_token_with_retry(uid, password):
    """Get access token with retry mechanism"""
    oauth_url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }

    for attempt in range(MAX_RETRIES):
        try:
            logger.info(f"Attempt {attempt + 1} to get token for UID: {uid}")
            oauth_response = requests.post(oauth_url, data=payload, headers=headers, timeout=10)
            
            if oauth_response.status_code == 200:
                oauth_data = oauth_response.json()
                if 'access_token' in oauth_data and 'open_id' in oauth_data:
                    logger.info(f"Successfully got token for UID: {uid}")
                    return oauth_data
                else:
                    logger.warning(f"OAuth response missing required fields for UID: {uid}")
            else:
                logger.warning(f"OAuth API returned HTTP {oauth_response.status_code} for UID: {uid}")
                
        except requests.RequestException as e:
            logger.warning(f"Request exception on attempt {attempt + 1} for UID {uid}: {str(e)}")
        
        # Wait before retry (exponential backoff)
        if attempt < MAX_RETRIES - 1:
            wait_time = RETRY_DELAY * (2 ** attempt)  # Exponential backoff
            logger.info(f"Waiting {wait_time} seconds before retry...")
            time.sleep(wait_time)
    
    logger.error(f"All {MAX_RETRIES} attempts failed for UID: {uid}")
    return None

def major_login_with_retry(access_token, open_id):
    """Perform major login with retry mechanism for platform 4 only"""
    platform_type = 4  # Guest accounts use only platform 4

    for attempt in range(MAX_RETRIES):
        try:
            game_data = my_pb2.GameData()
            game_data.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            game_data.game_name = "free fire"
            game_data.game_version = 1
            game_data.version_code = "1.132.1"
            game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
            game_data.device_type = "Handheld"
            game_data.network_provider = "Verizon Wireless"
            game_data.connection_type = "WIFI"
            game_data.screen_width = 1280
            game_data.screen_height = 960
            game_data.dpi = "240"
            game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
            game_data.total_ram = 5951
            game_data.gpu_name = "Adreno (TM) 640"
            game_data.gpu_version = "OpenGL ES 3.0"
            game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
            game_data.ip_address = generate_random_ip()
            game_data.language = "en"
            game_data.open_id = open_id
            game_data.access_token = access_token
            game_data.platform_type = platform_type
            game_data.field_99 = str(platform_type)
            game_data.field_100 = str(platform_type)

            serialized_data = game_data.SerializeToString()
            encrypted_data = encrypt_message(serialized_data)
            hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

            url = "https://loginbp.ggpolarbear.com/MajorLogin"
            headers = {
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip",
                "Content-Type": "application/octet-stream",
                "Expect": "100-continue",
                "X-Unity-Version": "2018.4.11f1",
                "X-GA": "v1 1",
                "ReleaseVersion": "OB55"
            }
            edata = bytes.fromhex(hex_encrypted_data)

            logger.info(f"Attempt {attempt + 1} for platform {platform_type}")
            response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)

            if response.status_code == 200:
                data_dict = None
                try:
                    example_msg = output_pb2.Garena_420()
                    example_msg.ParseFromString(response.content)
                    data_dict = {field.name: getattr(example_msg, field.name)
                                 for field in example_msg.DESCRIPTOR.fields
                                 if field.name not in ["binary", "binary_data", "Garena420"]}
                except Exception:
                    try:
                        data_dict = response.json()
                    except ValueError:
                        continue

                if data_dict and "token" in data_dict:
                    token_value = data_dict["token"]
                    try:
                        decoded_token = jwt.decode(token_value, options={"verify_signature": False})
                        
                        # Extract required fields from decoded token
                        account_id = decoded_token.get("account_id") or decoded_token.get("sub") or ""
                        nickname = decoded_token.get("nickname") or decoded_token.get("name") or ""
                        region = decoded_token.get("lock_region") or decoded_token.get("region") or "US"
                        
                        # Format the exp date
                        exp_timestamp = decoded_token.get("exp")
                        if exp_timestamp:
                            exp_date = datetime.fromtimestamp(exp_timestamp).strftime("%Y-%m-%d %H:%M:%S")
                            decoded_token["exp_date"] = exp_date
                        
                        return {
                            "token": token_value,
                            "decoded_token": decoded_token,
                            "account_id": str(account_id),
                            "nickname": nickname,
                            "region": region
                        }
                    except Exception as e:
                        logger.warning(f"JWT decode failed: {str(e)}")
                        continue
                
            # If we reach here, this attempt failed
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
                
        except requests.RequestException as e:
            logger.warning(f"Request failed for platform {platform_type}, attempt {attempt + 1}: {str(e)}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
            continue

    return None

@app.route('/token', methods=['GET'])
def oauth_guest():
    uid = request.args.get('uid')
    password = request.args.get('password')
    
    if not uid or not password:
        return jsonify({"message": "Missing uid or password"}), 400

    # Check cache first (unless retry is forced)
    use_cache = not request.args.get('retry')
    cache_key = make_cache_key(request.path, request.args.to_dict(flat=True))
    
    if use_cache:
        cached = cache.get(cache_key)
        if cached:
            logger.info(f"Returning cached response for UID: {uid}")
            return jsonify(cached)

    # Get OAuth token with retry
    oauth_data = get_token_with_retry(uid, password)
    if not oauth_data:
        # New format error response
        error_response = {
            "uid": uid or "",
            "password": password or "",
            "status": "error",
            "access_token": "",
            "open_id": "",
            "jwt_token": "",
            "account_id": "",
            "nickname": "",
            "region": "",
            "platform": ""
        }
        return jsonify(error_response), 400

    access_token = oauth_data['access_token']
    open_id = oauth_data['open_id']

    # Perform major login with retry (only platform 4)
    login_result = major_login_with_retry(access_token, open_id)
    if not login_result:
        # New format error response
        error_response = {
            "uid": uid,
            "password": password,
            "status": "error",
            "access_token": access_token,
            "open_id": open_id,
            "jwt_token": "",
            "account_id": "",
            "nickname": "",
            "region": "",
            "platform": ""
        }
        return jsonify(error_response), 400

    # Build successful response with new format
    result = {
        "uid": uid,
        "password": password,
        "status": "success",
        "access_token": access_token,
        "open_id": open_id,
        "jwt_token": login_result["token"],
        "account_id": login_result.get("account_id", ""),
        "nickname": login_result.get("nickname", ""),
        "region": login_result.get("region", "US"),
        "platform": "4"  # Always 4 for guest accounts
    }

    # Cache the successful response
    if use_cache:
        cache.set(cache_key, result, timeout=300)  # 5 minutes cache
    
    return jsonify(result), 200

# Keep the old format endpoint for backward compatibility
@app.route('/token_old', methods=['GET'])
def oauth_guest_old():
    uid = request.args.get('uid')
    password = request.args.get('password')
    
    if not uid or not password:
        return jsonify({"message": "Missing uid or password"}), 400

    # Check cache first (unless retry is forced)
    use_cache = not request.args.get('retry')
    cache_key = make_cache_key('/token_old', request.args.to_dict(flat=True))
    
    if use_cache:
        cached = cache.get(cache_key)
        if cached:
            logger.info(f"Returning cached old format response for UID: {uid}")
            return jsonify(cached)

    # Get OAuth token with retry
    oauth_data = get_token_with_retry(uid, password)
    if not oauth_data:
        error_response = OrderedDict([
            ("status", "error"),
            ("token", ""),
            ("decoded_token", None),
            ("credits", {
                "developer": "t.me/danger_ff_like",
                "main_channel": "t.me/freefirelikesdanger"
            })
        ])
        return jsonify(error_response), 400

    access_token = oauth_data['access_token']
    open_id = oauth_data['open_id']

    # Perform major login with retry (only platform 4)
    login_result = major_login_with_retry(access_token, open_id)
    if not login_result:
        error_response = OrderedDict([
            ("status", "error"),
            ("token", ""),
            ("decoded_token", None),
            ("credits", {
                "developer": "t.me/danger_ff_like",
                "main_channel": "t.me/freefirelikesdanger"
            })
        ])
        return jsonify(error_response), 400

    # Build successful response with exact old format
    result = OrderedDict([
        ("status", "live"),
        ("token", login_result["token"]),
        ("decoded_token", login_result["decoded_token"]),
        ("credits", {
            "developer": "t.me/danger_ff_like", 
            "main_channel": "t.me/freefirelikesdanger"
        })
    ])

    # Cache the successful response
    if use_cache:
        cache.set(cache_key, result, timeout=300)  # 5 minutes cache
    
    return jsonify(result), 200

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"}), 200

@app.route('/clear-cache', methods=['POST'])
def clear_cache():
    cache.clear()
    return jsonify({"message": "Cache cleared successfully"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1080, debug=False)
