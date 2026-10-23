import streamlit as st
import websocket
import threading
import time
import ssl
import re
import requests
import binascii
import urllib3

# InsecureRequestWarning chupane ke liye
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# ⚙️ APNE 8 SERVERS KI DETAILS YAHAN DAALEIN
# ==========================================
SERVER_LIST = [
    {"name": "Server 1", "url": "https://online-kbwr.onrender.com"},
    {"name": "Server 2", "url": "https://online-b5sr.onrender.com"},
    {"name": "Server 3", "url": "https://online-28k9.onrender.com"},
    {"name": "Server 4", "url": "https://online-zdnx.onrender.com"},
    {"name": "Server 5", "url": "https://online-g9o8.onrender.com"},
    {"name": "Server 6", "url": "https://online-mg7e.onrender.com"},
    {"name": "Server 7", "url": "https://online-8eeq.onrender.com"},
    {"name": "Servar 8", "url": "https://online-6nz0.onrender.com"},
    {"name": "Servar 9", "url": "randar token"},
    {"name": "Smart Ai3", "url": "https://hackarai.onrender.com"},
    {"name": "experiment", "url": "randar uptome"}
]

MY_UID = "4470446192" 
MY_TOKEN = "t0V6HVBay785tnmu4YsXBUV44HHGfsMCcUOvXpEMNCI%2BIptVkbKT7uzM83t7qLcc%2CnNM9ovMxw68YH21lQ7LVtkxu6cUGrEDx27tSHEaGCoFrBjSVdnSJjVRZlWiIH3lZ1o36q%2BBFMoZ0p%2BmFOUvkkaaCPnU7KEdmids44lmyZI1l%2FRyFxr3FFbaa2U11PLRydQ%2BMjZ3FnqgjqaRtR7JauEsvvW5zlMgIE%2BynZl7RGP8EGpjta4Jk6TFPlqRQmG1sYqTm7%2B0lq7lTtVpEBr6o8SfQrRWuUFUjR9gov2oExuBPIacpp6jNg78wU%2FanRl3jZrtQe1ZKSeWf2sbZJMkwWR4Xg7kPp1UXettKknjUpgoL61sT%2Fy6HLpoUVOi8I0N7kMO4zabuYsh6DeLGNiQxqTN8Bmq%2BoVYrUssUXewyLTwv2FbStfm5wPVNdOiM9n0Hmgb0ScZIm6aRMSoCpGoEBV3z2e0lpM8CmmEWB%2FUJjeW%2Fg4Shw39D1IZluojCeblAezXnfhnR5dU4otB2Cq%2FO0%2BjAutZPLEgz4QiKvf8i9udpVsQmtnU9kz44N4Ix7XFF"
WS_URL = f"wss://i-875.olaparty.com/ikxd_cproxy?token={MY_UID}"

HEADERS = {
    "X-App-Name": "olaparty",
    "X-Auth-Token": MY_TOKEN, 
    "Origin": "https://i-875.olaparty.com",
    "User-Agent": "com.live.partytill/2952 (Linux; U; Android 15; en_IN)"
}

# ==========================================
# 🛠️ HELPER FUNCTIONS
# ==========================================
def string_to_hex(s):
    return binascii.hexlify(s.encode()).decode()

def uid_to_varint_hex(uid_str, target_length=6):
    try:
        number = int(uid_str)
        encoded_bytes = []
        while True:
            byte = number & 0x7F
            number >>= 7
            if number > 0:
                byte |= 0x80
                encoded_bytes.append(byte)
            else:
                encoded_bytes.append(byte)
                break
        while len(encoded_bytes) < target_length:
            last = encoded_bytes.pop()
            encoded_bytes.append(last | 0x80)
            encoded_bytes.append(0x00)
        return ' '.join([f'{b:02X}' for b in encoded_bytes])
    except: return None

def extract_uids_from_hex(raw_hex_packet):
    hex_list = raw_hex_packet.split()
    uids = []
    i = 0
    while i < len(hex_list):
        try:
            result = 0
            shift = 0
            consumed = 0
            for j in range(i, len(hex_list)):
                byte = int(hex_list[j], 16)
                result |= (byte & 0x7F) << shift
                consumed += 1
                if (byte & 0x80) == 0: break
                shift += 7
            val = result
            length = consumed
            val_str = str(val)
            if val_str.startswith('4') and 9 <= len(val_str) <= 11:
                if val_str not in uids: 
                    uids.append(val_str)
            i += length 
        except:
            i += 1
    return uids

def extract_cid_from_link(text):
    match = re.search(r'(https?://api\.olaparty\.com/d/[\w-]+)', text)
    if match: return match.group(1)
    match = re.search(r'(https?://[\w\.]+/d/[\w-]+)', text)
    if match: return match.group(1)
    match = re.search(r'(https?://[^\s]+)', text)
    if match: return match.group(1)
    return None

def resolve_link_to_cid(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True, verify=False)
        combined_text = response.url + " " + response.text
        cid_match = re.search(r'(C_\d+_V[12]_[A-Z]+_\d+_[A-Z]+|C_\d{10,})', combined_text, re.IGNORECASE)
        if cid_match: 
            return cid_match.group(1).upper()
        return None
    except Exception as e:
        return None

def get_search_packet(target_vid):
    base_hex = "0A 6D 50 00 18 00 62 1D 0A 06 58 2D 50 63 69 64 12 13 31 31 35 32 39 32 31 35 30 34 36 31 32 38 30 32 37 34 39 22 05 65 6E 5F 69 6E 3A 13 45 6C 61 73 74 69 63 2E 53 65 61 72 63 68 55 73 65 72 73 48 01 32 00 10 BE EF 9A 9A C2 33 0A 1A 6E 65 74 2E 69 68 61 67 6F 2E 62 61 73 65 2E 73 72 76 2E 65 6C 61 73 74 69 63 42 05 30 2E 30 2E 30 1A 16 12 0A 32 30 36 38 32 36 33 32 35 35 0A 08 18 0F 10 00 08 00 20 00 10 00"
    old_vid_hex = "32 30 36 38 32 36 33 32 35 35" 
    old_time_varint = "BE EF 9A 9A C2 33"
    
    new_vid_hex = string_to_hex(str(target_vid)).upper()
    new_vid_spaced = " ".join([new_vid_hex[i:i+2] for i in range(0, len(new_vid_hex), 2)])
    packet_hex = base_hex.replace(old_vid_hex, new_vid_spaced)
    
    new_time_str = str(int(time.time() * 1000))
    new_time_varint = uid_to_varint_hex(new_time_str, target_length=6)
    if new_time_varint:
        packet_hex = packet_hex.replace(old_time_varint, new_time_varint)
        
    return bytes.fromhex(packet_hex.replace(" ", ""))

def get_location_packet(target_uid):
    base_hex = "0A 4E 0A 19 6E 65 74 2E 69 68 61 67 6F 2E 63 68 61 6E 6E 65 6C 2E 73 72 76 2E 6D 67 72 10 C6 A7 A1 D5 C9 33 22 05 65 6E 5F 69 6E 3A 1A 43 68 61 6E 6E 65 6C 2E 47 65 74 43 75 72 72 65 6E 74 43 68 61 6E 6E 65 6C 73 42 05 30 2E 30 2E 30 48 01 1A 08 08 FA 9F D6 D3 10 10 01"
    old_time_varint = "C6 A7 A1 D5 C9 33"
    old_uid_varint = "FA 9F D6 D3 10"
    new_uid_varint = uid_to_varint_hex(target_uid, target_length=5)
    new_time_str = str(int(time.time() * 1000))
    new_time_varint = uid_to_varint_hex(new_time_str, target_length=6)
    if not new_uid_varint or not new_time_varint: return None
    packet_hex = base_hex.replace(old_uid_varint, new_uid_varint).replace(old_time_varint, new_time_varint)
    return bytes.fromhex(packet_hex.replace(" ", ""))

class RoomTracker:
    def __init__(self, target_input):
        self.target_input = target_input
        self.found_uid = None
        self.final_cid = None
        self.is_done = False
        
        if target_input.startswith("4") and len(target_input) >= 9:
            self.step = "LOCATION"
            self.found_uid = target_input
        else:
            self.step = "SEARCH"

    def start(self):
        def on_open(ws):
            def timeout():
                time.sleep(6)
                if not self.is_done:
                    self.is_done = True
                    ws.close()
            threading.Thread(target=timeout).start()

            if self.step == "LOCATION":
                loc_packet = get_location_packet(self.found_uid)
                if loc_packet: ws.send(loc_packet, opcode=websocket.ABNF.OPCODE_BINARY)
            else:
                ws.send(get_search_packet(self.target_input), opcode=websocket.ABNF.OPCODE_BINARY)

        def on_message(ws, message):
            if not isinstance(message, bytes): return
            hex_msg = message.hex(" ").upper()
            response_text = message.decode('utf-8', errors='ignore')
            
            if self.step == "SEARCH":
                found_uids = extract_uids_from_hex(hex_msg)
                found_uids += re.findall(r'(4\d{9})', response_text)
                
                for uid in found_uids:
                    if uid != MY_UID: 
                        self.found_uid = uid
                        break
                        
                if self.found_uid:
                    self.step = "LOCATION"
                    loc_packet = get_location_packet(self.found_uid)
                    if loc_packet:
                        time.sleep(0.5)
                        ws.send(loc_packet, opcode=websocket.ABNF.OPCODE_BINARY)
                return

            elif self.step == "LOCATION":
                cid_match = re.search(r'(C_\d+_V[12]_[A-Z]+_\d+_[A-Z]+|C_\d{10,})', response_text, re.IGNORECASE)
                if cid_match:
                    self.final_cid = cid_match.group(1).upper()
                    self.is_done = True
                    ws.close()
                elif "Channel.GetCurrentChannels" in response_text or "Channel.GetCurrentRoomInfo" in response_text:
                    self.is_done = True
                    ws.close()

        def on_error(ws, error):
            self.is_done = True

        def on_close(ws, c, m):
            self.is_done = True

        ws = websocket.WebSocketApp(WS_URL, header=HEADERS, on_open=on_open, on_message=on_message, on_error=on_error, on_close=on_close)
        ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
        
        while not self.is_done:
            time.sleep(0.5)
        return self.final_cid

def smart_resolve_input(input_str):
    cid_match = re.search(r'(C_\d+_V[12]_[A-Za-z0-9_]+)', input_str, re.IGNORECASE)
    if cid_match:
        return cid_match.group(1).upper()

    if "http" in input_str:
        link = extract_cid_from_link(input_str)
        if link:
            return resolve_link_to_cid(link)
            
    clean_str = input_str.strip()
    if clean_str.isdigit():
        tracker = RoomTracker(clean_str)
        return tracker.start()
        
    return None

# ==========================================
# 🌐 STREAMLIT UI DESIGN (RGB DISCO & BLACK BACKGROUND)
# ==========================================
st.set_page_config(page_title="LUCKY GODFATHER | RGB Command Center", page_icon="🎮", layout="wide")

st.markdown(
    """
    <style>
    /* Dark Background */
    .stApp { 
        background-color: #050505; 
        background-image: radial-gradient(circle, #0a0a0a 0%, #000000 90%); 
        color: #ffffff; 
        font-family: 'Courier New', Courier, monospace; 
    }
    
    /* 🌈 RGB KEYFRAME ANIMATION FOR TEXT (Red, Yellow, Green, Blue, Pink) */
    @keyframes discoText {
        0% { color: #ff0040; text-shadow: 0 0 10px #ff0040, 0 0 20px #ff0040; }
        20% { color: #ffff00; text-shadow: 0 0 10px #ffff00, 0 0 20px #ffff00; }
        40% { color: #00ff00; text-shadow: 0 0 10px #00ff00, 0 0 20px #00ff00; }
        60% { color: #0088ff; text-shadow: 0 0 10px #0088ff, 0 0 20px #0088ff; }
        80% { color: #ff00ff; text-shadow: 0 0 10px #ff00ff, 0 0 20px #ff00ff; }
        100% { color: #ff0040; text-shadow: 0 0 10px #ff0040, 0 0 20px #ff0040; }
    }
    .disco-lucky {
        animation: discoText 1.5s infinite linear;
        font-weight: 900;
        display: inline-block;
    }

    /* GENERAL TEXT STYLING */
    h1, h2, h3, h4 { 
        color: #ffffff !important; 
        font-family: 'Courier New', Courier, monospace; 
        position: relative;
        z-index: 10;
    }
    p { position: relative; z-index: 10; }
    
    /* RGB GAMING BORDER ANIMATION FOR INPUT BOXES AND BUTTONS */
    @keyframes rgbBorder {
        0% { border-color: #ff0040; box-shadow: 0 0 15px #ff0040; }
        20% { border-color: #ffff00; box-shadow: 0 0 15px #ffff00; }
        40% { border-color: #00ff00; box-shadow: 0 0 15px #00ff00; }
        60% { border-color: #0088ff; box-shadow: 0 0 15px #0088ff; }
        80% { border-color: #ff00ff; box-shadow: 0 0 15px #ff00ff; }
        100% { border-color: #ff0040; box-shadow: 0 0 15px #ff0040; }
    }

    /* INPUT BOX HACKER STYLE */
    .stTextInput input { 
        background-color: rgba(10, 10, 10, 0.9) !important; 
        color: #ffffff !important; 
        border-radius: 4px; 
        font-weight: bold; 
        border: 2px solid transparent !important;
        animation: rgbBorder 3s infinite linear;
        position: relative;
        z-index: 10;
    }
    .stTextInput input:focus {
        outline: none !important;
        background-color: #111111 !important;
    }
    
    /* BUTTON RGB GAMING STYLE */
    .stButton>button { 
        background-color: #111111 !important; 
        color: #ffffff !important; 
        border: 2px solid transparent !important; 
        border-radius: 8px; 
        width: 100%; 
        height: 42px; 
        font-weight: bold; 
        transition: 0.3s; 
        animation: rgbBorder 2s infinite linear;
        text-transform: uppercase;
        letter-spacing: 1px;
        position: relative;
        z-index: 10;
    }
    .stButton>button:hover { 
        background-color: rgba(255,255,255,0.1) !important; 
        transform: scale(1.05); 
    }
    
    /* Status Messages */
    .stAlert {
        background-color: rgba(10, 10, 10, 0.8) !important;
        border: 1px solid #ffffff !important;
        color: #ffffff !important;
        z-index: 10;
        position: relative;
    }
    
    /* HIDE STREAMLIT BRANDING */
    #MainMenu, footer, header {visibility: hidden;}
    </style>
    """,
    unsafe_allow_html=True
)

# HTML Title (Using the disco class for "LUCKY" and "Godfather")
st.markdown("<h1 style='text-align: center;'>☠️ <span class='disco-lucky'>𝐋𝐔𝐂𝐊𝐘</span> 🌎 <span class='disco-lucky'>𝙂𝙤𝙙𝙛𝙖𝙩𝙝𝙚𝙧</span> 🖥️</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; font-size: 1.5rem; font-weight: bold;'> <span class='disco-lucky'>𝐋𝐔𝐂𝐊𝐘</span> 🌎 BOSS</p><hr style='border:1px solid #333; position:relative; z-index:10;'>", unsafe_allow_html=True)

# 8 SERVERS LOOP CREATION
for i, server in enumerate(SERVER_LIST):
    col1, col2, col3 = st.columns([1, 4, 1])
    
    with col1:
        st.markdown(f"<h4 style='margin-top: 5px; color: #aaaaaa;'>{server['name']}</h4>", unsafe_allow_html=True)
    
    with col2:
        target_input = st.text_input("Target", key=f"input_{i}", label_visibility="collapsed", placeholder=f"Room Link / ID for {server['name']}...")
        
    with col3:
        if st.button("🚀 CLICK ✅", key=f"btn_{i}"):
            if not target_input:
                st.warning(f"⚠️ {server['name']} ke liye link daalo!")
            else:
                with st.spinner(f"⏳ {server['name']} - TRACING TARGET..."):
                    target_cid = smart_resolve_input(target_input)

                if target_cid:
                    try:
                        api_link = f"{server['url'].strip('/')}/change_room?cid={target_cid}"
                        res = requests.get(api_link, timeout=15, verify=False)
                        
                        if res.status_code == 200:
                            st.success(f"✅ {server['name']} SUCCESS: Bot gaya!")
                            st.balloons()
                        else:
                            st.error(f"❌ {server['name']} ERROR {res.status_code}")
                    except Exception as e:
                        st.error(f"❌ {server['name']} OFFLINE ya UNREACHABLE.")
                else:
                    st.error("❌ INVALID TARGET.")

st.markdown("<hr style='border:1px solid #333; position:relative; z-index:10;'><p style='text-align: center; color: #777777; font-weight: bold; position:relative; z-index:10;'>// DEVELOPED BY <span class='disco-lucky'>LUCKY</span> <span class='disco-lucky'>GODFATHER</span> //</p>", unsafe_allow_html=True)
