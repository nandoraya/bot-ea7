import meshtastic
import meshtastic.serial_interface
import meshtastic.tcp_interface
from pubsub import pub
import time
import requests
import threading
import sqlite3
import logging
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from collections import deque
import xml.etree.ElementTree as ET
import tarfile
import io
import os
import csv
import paho.mqtt.client as mqtt

# --- CARGA DE CONFIGURACIÓN DESDE .env (mismo dir que el script) ---
def _cargar_env(path):
    """Carga un .env tipo KEY=VALUE sin depender de dotenv. Devuelve set de claves."""
    claves = set()
    try:
        if not os.path.exists(path):
            return claves
        with open(path, "r") as f:
            for linea in f:
                linea = linea.strip()
                if not linea or linea.startswith("#") or "=" not in linea:
                    continue
                k, _, v = linea.partition("=")
                k = k.strip()
                v = v.strip()
                if k.startswith("export "):
                    k = k[len("export "):].strip()
                claves.add(k)
                if k not in os.environ:
                    os.environ[k] = v.strip('"').strip("'")
    except Exception as e:
        logging.error(f"Error cargando {path}: {e}")
    return claves

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_cargar_env(os.path.join(_SCRIPT_DIR, ".env"))

def _env(k, default=""):
    return os.environ.get(k, default)

# --- RUTA ABSOLUTA DB ---
import os
import csv
LOG_FILE = "/tmp/bot_debug.log"
def debug_log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(str(msg) + "\n")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "meshtastic_nodes.db")

# --- VARIABLE PARA UPTIME ---
BOT_START_TIME = time.time()
MQTT_CONNECTED = False

# --- ANTI-SPAM: LÍMITE DE MENSAJES POR RADIO ---
RADIO_RATE_MAX = 30
RADIO_RATE_WINDOW = 600
radio_msg_times = deque()
radio_rate_alerted = False
SENT_TERREMOTOS = set()
SENT_ALERTAS = set()

# --- TRACEROUTE (/trace, solo desde chat principal TG) ---
TRACE_TIMEOUT = 90
TRACE_HOP_LIMIT = 7
_trace_lock = threading.Lock()
_trace_pending = None

KEYCAPS_TRACE = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟"]

def capturar_traceroute(packet, interface):
    try:
        if 'decoded' not in packet or packet['decoded'].get('portnum') != 'TRACEROUTE_APP':
            return
        t = _trace_pending
        if t is None:
            return
        raw_from = packet.get('from')
        try:
            if isinstance(raw_from, str):
                limpio = raw_from.lstrip('!')
                num_from = int(limpio, 16) if not limpio.isdigit() else int(limpio)
            else:
                num_from = int(raw_from)
        except (TypeError, ValueError):
            return
        if t.get("num") != num_from:
            return
        rd = meshtastic.mesh_pb2.RouteDiscovery()
        rd.ParseFromString(packet['decoded']['payload'])

        def _nombre(num):
            if isinstance(num, str):
                if not num.startswith('!'):
                    return num
                lookup = num.lower()
                nid = num
            else:
                nid = "!{:08x}".format(num)
                lookup = nid
            info = interface.nodes.get(lookup) or {}
            return (info.get('user', {}).get('shortName') or nid)

        def _snr(lista, idx):
            try:
                v = lista[idx]
                return (v / 4.0) if v != -128 else None
            except IndexError:
                return None

        def _sem(db):
            if db is None: return "❓"
            if db >= 8: return "🟢"
            if db >= 4: return "🟡"
            if db >= 0: return "🟠"
            return "🔴"

        def _seccion(titulo, intermedios, fin, snrs):
            enlaces = [(hop, _snr(snrs, i)) for i, hop in enumerate(intermedios)]
            enlaces.append((fin, _snr(snrs, len(intermedios))))
            out = []
            if len(intermedios) == 0:
                out.append("{} · conexión directa".format(titulo))
            else:
                out.append("{} · {} saltos".format(titulo, len(enlaces)))
            validos = []
            for i, (tgt, db) in enumerate(enlaces):
                k = KEYCAPS_TRACE[i] if i < len(KEYCAPS_TRACE) else "{}.".format(i + 1)
                txt_db = "{:.1f} dB".format(db) if db is not None else "? dB"
                out.append("{} {} · {} {}".format(k, _nombre(tgt), _sem(db), txt_db))
                if db is not None:
                    validos.append(db)
            if validos:
                out.append("📶 Media: {:.1f} dB".format(sum(validos) / len(validos)))
            return out

        destino_nombre = _nombre(num_from)
        lineas = _seccion("🛣 IDA", list(rd.route), destino_nombre, list(rd.snr_towards))
        if len(rd.snr_back) == len(rd.route_back) + 1:
            lineas.append("")
            lineas += _seccion("🔙 VUELTA", list(rd.route_back), "BOT", list(rd.snr_back))
        t["lineas"] = lineas
        t["evento"].set()
    except Exception as e:
        logging.error(f"Error parseando traceroute: {e}", exc_info=True)

# Intentamos importar BeautifulSoup para el scraping de HamQTH
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

# --- CONFIGURACIÓN DE LOGS ---
logging.basicConfig(
    filename='bot_debug.log',
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# --- CONFIGURACIÓN ---
PUERTO_USB = "/dev/ttyUSB0"
MAX_CH_UTIL = 25.0
MARGEN_ONLINE = 24 * 3600 

MI_NODO_ID = _env("MI_NODO_ID", "!02eda160")

ROUTERS_VIGILADOS = {
    "!c9f19db9": "GR02",    
    "!7698895a": "AL01",
    "!8c75ca9f": "AL02",
    "!81fde5cc": "AL03",
    "!af429732": "MA03",
    "!da061b4e": "MA04",
    "!b62448bb": "SE01",
    "!f9b6f070": "JA01"
}

NODOS_INFO2 = {"!d9e01680": "NAN6 (C. Real)", "!fd91149c": "EA7 (Jarapa)", "!1adb57bc": "JES2 (S. Filabres)", "!fe1d3a9d": "AL08 (Fiñana)", "!b9551f82": "SRA2 (Sierra 2.0)", "!c5d10c03": "CAR^ (Carboneras)", "!415af331": "TRKG (Tranktastic)"}

TELEGRAM_TOKEN = _env("TELEGRAM_TOKEN")
MI_CHAT_ID = _env("MI_CHAT_ID", "-1004339561947")
CHATS_PERMITIDOS = [c.strip() for c in _env("CHATS_PERMITIDOS", "133068052,-1002968559479,1662256372,-5292771691,-3630484380,799660298,-1004339561947").split(",") if c.strip()]

# --- POTATO MESH API ---
POTATO_API_URL = _env("POTATO_API_URL", "http://192.168.1.100:41447")
POTATO_API_TOKEN = _env("POTATO_API_TOKEN")

# --- PUENTE A POTATO MESH ---
def post_mensaje_potato(texto, ch_idx, iface):
    try:
        msg_id = int(time.time() * 1000) % 100000000
        canal_nombre = CHANNEL_NAMES.get(ch_idx, "Primary") if CHANNEL_NAMES else "Primary"
        payload = {
            "id": msg_id, "text": texto, "channel": ch_idx,
            "from_id": MI_NODO_ID, "to_id": "^all",
            "rx_time": int(time.time()), "portnum": "TEXT_MESSAGE_APP",
            "channel_name": canal_nombre
        }
        headers = {"Authorization": "Bearer " + POTATO_API_TOKEN, "Content-Type": "application/json"}
        requests.post(POTATO_API_URL + "/api/messages", json=payload, headers=headers, timeout=3)
    except Exception as e:
        logging.error(f"Error Potato bridge: {e}")

# --- SOTA CONFIGURACIÓN ---
SOTA_USER = _env("SOTA_USER", "EA7LQK")
SOTA_PASS = _env("SOTA_PASS")
SOTA_TOKEN_URL = "https://sso.sota.org.uk/auth/realms/SOTA/protocol/openid-connect/token"
SOTA_API_URL = "https://api2.sota.org.uk/api/spots"
SOTA_CLIENT_ID = "sotawatch"

# --- AEMET CONFIGURACIÓN ---
AEMET_API_KEY = _env("AEMET_API_KEY")
FIRMS_MAP_KEY = _env("FIRMS_MAP_KEY")

# --- CALIMA CONFIGURACION ---
CALIMA_UMBRAL_PM10 = 50.0
CALIMA_PROVINCIAS = ["Almeria", "Granada", "Malaga", "Jaen", "Sevilla"]

# --- IA CONFIGURACION (GROQ) ---
IA_API_URL = "https://api.groq.com/openai/v1/chat/completions"
IA_API_KEY = _env("IA_API_KEY")
IA_MODEL = _env("IA_MODEL", "openai/gpt-oss-120b")
IA_TIMEOUT = 12
IA_COOLDOWN_GLOBAL = 30
IA_COOLDOWN_NODO = 60
IA_MAX_BYTES_RADIO = 220
_ia_lock = threading.Lock()
_ia_last_global = [0.0]
_ia_last_nodo = {}

# --- QRZ CONFIGURACIÓN ---
QRZ_USER = _env("QRZ_USER")
QRZ_PASS = _env("QRZ_PASS")
QRZ_CACHE = {}
QRZ_CACHE_TTL = 86400
MIN_MAGNITUD_TERREMOTO = 3.0
CANAL_ALERTAS_NOMBRE = "Almeria"  # backward compat, keep for non-province uses

# --- CONFIGURACIÓN MULTIPROVINCIA ---
PROVINCIAS = {
    "Almeria": {
        "zones": {"610401", "610402", "610403", "610404"},
        "channel_name": "Almeria",
        "bbox": {"min_lon": -3.0, "min_lat": 36.5, "max_lon": -1.5, "max_lat": 37.8},
        "quake_center": (36.83, -2.45),
        "quake_radius": 1.8,
    },
    "Granada": {
        "zones": {"611801", "611802", "611803", "611804"},
        "channel_name": "Granada",
        "bbox": {"min_lon": -4.2, "min_lat": 36.7, "max_lon": -2.5, "max_lat": 38.0},
        "quake_center": (37.2, -3.5),
        "quake_radius": 1.3,
    },
    "Malaga": {
        "zones": {"612901", "612902", "612903", "612904"},
        "channel_name": "Malaga",
        "bbox": {"min_lon": -5.1, "min_lat": 36.3, "max_lon": -3.5, "max_lat": 37.2},
        "quake_center": (36.8, -4.5),
        "quake_radius": 1.3,
    },
    "Jaen": {
        "zones": {"612301", "612302", "612303", "612304"},
        "channel_name": "Jaen",
        "bbox": {"min_lon": -4.4, "min_lat": 37.35, "max_lon": -2.4, "max_lat": 38.75},
        "quake_center": (37.98, -3.47),
        "quake_radius": 1.3,
    },
    "Sevilla": {
        "zones": {"414101", "414102", "414103", "414104", "414105", "414106"},
        "channel_name": "Sevilla",
        "bbox": {"min_lon": -6.5, "min_lat": 36.4, "max_lon": -4.5, "max_lat": 38.2},
        "quake_center": (37.38, -5.98),
        "quake_radius": 1.3,
    },
}

ZONE_TO_PROV = {}
for _prov, _cfg in PROVINCIAS.items():
    for _z in _cfg["zones"]:
        ZONE_TO_PROV[_z] = _prov

CANALES = {_p: _c["channel_name"] for _p, _c in PROVINCIAS.items()}
CHANNEL_TO_PROV = {}
CHANNEL_NAMES = {}

# --- MUNICIPIOS (con provincia) ---
TOWNS = [
    ("Almeria", 36.8381, -2.4597, "Almeria"),
    ("El Ejido", 36.7763, -2.8141, "Almeria"),
    ("Roquetas de Mar", 36.7642, -2.6147, "Almeria"),
    ("Nijar", 36.9667, -2.2000, "Almeria"),
    ("Adra", 36.7500, -3.0167, "Almeria"),
    ("Berja", 36.8458, -2.9486, "Almeria"),
    ("Huercal-Overa", 37.3900, -1.9500, "Almeria"),
    ("Cuevas del Almanzora", 37.2967, -1.8806, "Almeria"),
    ("Vera", 37.2500, -1.8667, "Almeria"),
    ("Garrucha", 37.1814, -1.8233, "Almeria"),
    ("Mojacar", 37.1397, -1.8517, "Almeria"),
    ("Carboneras", 37.0000, -1.8917, "Almeria"),
    ("Sorbas", 37.1000, -2.1167, "Almeria"),
    ("Tabernas", 37.0500, -2.3917, "Almeria"),
    ("Gergal", 37.1194, -2.5397, "Almeria"),
    ("Alhama de Almeria", 36.9578, -2.5700, "Almeria"),
    ("Finana", 37.1794, -2.8433, "Almeria"),
    ("Abla", 37.1417, -2.7833, "Almeria"),
    ("Laujar de Andarax", 36.9944, -2.8967, "Almeria"),
    ("Canjayar", 37.0100, -2.7400, "Almeria"),
    ("Dalias", 36.8333, -2.8667, "Almeria"),
    ("Vicar", 36.7833, -2.6500, "Almeria"),
    ("La Mojonera", 36.7525, -2.6836, "Almeria"),
    ("Pulpi", 37.4117, -1.7450, "Almeria"),
    ("Albox", 37.3889, -2.1472, "Almeria"),
    ("Olula del Rio", 37.3500, -2.3000, "Almeria"),
    ("Tijola", 37.3500, -2.4333, "Almeria"),
    ("Seron", 37.3500, -2.5167, "Almeria"),
    ("Purchena", 37.3500, -2.3667, "Almeria"),
    ("Macael", 37.3333, -2.3000, "Almeria"),
    ("Arboleas", 37.3500, -2.0833, "Almeria"),
    ("Zurgena", 37.3500, -2.0333, "Almeria"),
    ("Antas", 37.2500, -1.9167, "Almeria"),
    ("Lubrin", 37.2167, -2.0667, "Almeria"),
    ("Lucainena de las Torres", 37.0333, -2.2000, "Almeria"),
    ("Bayarcal", 37.0333, -2.9833, "Almeria"),
    ("Alcolea", 36.9833, -2.9667, "Almeria"),
    # Granada
    ("Granada capital", 37.1773, -3.5986, "Granada"),
    ("Motril", 36.7500, -3.5167, "Granada"),
    ("Almunecar", 36.7333, -3.6833, "Granada"),
    ("Salobrena", 36.7500, -3.5833, "Granada"),
    ("Guadix", 37.3000, -3.1333, "Granada"),
    ("Baza", 37.4833, -2.7667, "Granada"),
    ("Loja", 37.1667, -4.1500, "Granada"),
    ("Armilla", 37.1500, -3.6167, "Granada"),
    ("Maracena", 37.2000, -3.6333, "Granada"),
    ("Las Gabias", 37.1333, -3.6667, "Granada"),
    ("Santa Fe", 37.1833, -3.7167, "Granada"),
    ("Peligros", 37.2333, -3.6333, "Granada"),
    ("Atarfe", 37.2167, -3.6833, "Granada"),
    ("Albolote", 37.2333, -3.6500, "Granada"),
    ("Ogijares", 37.1333, -3.6000, "Granada"),
    ("Huetor Vega", 37.1500, -3.5667, "Granada"),
    ("Cullar Vega", 37.1500, -3.6667, "Granada"),
    ("Churriana de la Vega", 37.1500, -3.6333, "Granada"),
    ("Lanjarón", 36.9167, -3.4833, "Granada"),
    ("Orgiva", 36.9000, -3.4167, "Granada"),
    ("Alhama de Granada", 37.0167, -3.9833, "Granada"),
    ("Huéscar", 37.8000, -2.5333, "Granada"),
    ("Cullar", 37.5833, -2.5667, "Granada"),
    ("Montefrio", 37.3167, -3.6500, "Granada"),
    ("Illora", 37.2833, -3.8833, "Granada"),
    ("Moclin", 37.3333, -3.7833, "Granada"),
    # Malaga
    ("Malaga capital", 36.7213, -4.4214, "Malaga"),
    ("Marbella", 36.5167, -4.8833, "Malaga"),
    ("Fuengirola", 36.5333, -4.6167, "Malaga"),
    ("Benalmadena", 36.6000, -4.5167, "Malaga"),
    ("Torremolinos", 36.6167, -4.5000, "Malaga"),
    ("Mijas", 36.6000, -4.6333, "Malaga"),
    ("Estepona", 36.4333, -5.1500, "Malaga"),
    ("Velez-Malaga", 36.7833, -4.1000, "Malaga"),
    ("Torrox", 36.7500, -3.9500, "Malaga"),
    ("Nerja", 36.7500, -3.8667, "Malaga"),
    ("Rincon de la Victoria", 36.7167, -4.2833, "Malaga"),
    ("Alhaurin de la Torre", 36.6667, -4.5500, "Malaga"),
    ("Alhaurin el Grande", 36.6333, -4.6833, "Malaga"),
    ("Coin", 36.6667, -4.7500, "Malaga"),
    ("Antequera", 37.0167, -4.5500, "Malaga"),
    ("Ronda", 36.7333, -5.1667, "Malaga"),
    ("Campillos", 37.0500, -4.8333, "Malaga"),
    ("Archidona", 37.1000, -4.3833, "Malaga"),
    ("Alora", 36.8167, -4.7000, "Malaga"),
    ("Cártama", 36.7167, -4.6333, "Malaga"),
    ("Pizarra", 36.7667, -4.7000, "Malaga"),
    ("Almargen", 37.0167, -5.0167, "Malaga"),
    ("Teba", 36.9833, -4.9167, "Malaga"),
    ("Manilva", 36.3667, -5.2500, "Malaga"),
    ("Casares", 36.4333, -5.2667, "Malaga"),
    # Jaen
    ("Jaén capital", 37.7692, -3.7903, "Jaen"),
    ("Linares", 38.0952, -3.6365, "Jaen"),
    ("Úbeda", 38.0136, -3.3707, "Jaen"),
    ("Andújar", 38.0372, -4.0509, "Jaen"),
    ("Alcalá la Real", 37.4617, -3.9239, "Jaen"),
    ("Martos", 37.7211, -3.9689, "Jaen"),
    ("Bailén", 38.0988, -3.7789, "Jaen"),
    ("La Carolina", 38.2769, -3.6176, "Jaen"),
    ("Alcaudete", 37.5894, -4.0891, "Jaen"),
    ("Mancha Real", 37.7867, -3.6120, "Jaen"),
    ("Torreperogil", 38.0358, -3.2897, "Jaen"),
    ("Jódar", 37.8409, -3.3515, "Jaen"),
    ("Villanueva del Arzobispo", 38.1695, -3.0044, "Jaen"),
    ("Beas de Segura", 38.2521, -2.8959, "Jaen"),
    ("Segura de la Sierra", 38.2964, -2.6534, "Jaen"),
    ("Cazorla", 37.9102, -3.0045, "Jaen"),
    ("Quesada", 37.8458, -3.0670, "Jaen"),
    ("Villacarrillo", 38.1177, -3.0846, "Jaen"),
    ("Santisteban del Puerto", 38.2486, -3.2094, "Jaen"),
    ("Navas de San Juan", 38.1827, -3.3211, "Jaen"),
    ("Arquillos", 38.1825, -3.4234, "Jaen"),
    ("Lopera", 37.9450, -4.2144, "Jaen"),
    ("Porcuna", 37.8753, -4.1884, "Jaen"),
    ("Arjona", 37.9358, -4.0561, "Jaen"),
    ("Marmolejo", 38.0458, -4.1681, "Jaen"),
    ("Mengíbar", 37.9696, -3.8047, "Jaen"),
    ("Torredonjimeno", 37.7675, -3.9597, "Jaen"),
    ("Torredelcampo", 37.8647, -3.9042, "Jaen"),
    ("Huelma", 37.6477, -3.4597, "Jaen"),
    # Sevilla
    ("Sevilla capital", 37.3891, -5.9845, "Sevilla"),
    ("Dos Hermanas", 37.2829, -5.9209, "Sevilla"),
    ("Alcala de Guadaira", 37.3379, -5.8550, "Sevilla"),
    ("Utrera", 37.1846, -5.7812, "Sevilla"),
    ("Mairena del Aljarafe", 37.3424, -6.0672, "Sevilla"),
    ("Coria del Rio", 37.2861, -6.0527, "Sevilla"),
    ("Camas", 37.4011, -6.0323, "Sevilla"),
    ("San Juan de Aznalfarache", 37.3617, -6.0286, "Sevilla"),
    ("Tomares", 37.3741, -6.0480, "Sevilla"),
    ("Ecija", 37.5333, -5.0833, "Sevilla"),
    ("Carmona", 37.4710, -5.6410, "Sevilla"),
    ("Osuna", 37.2361, -5.1024, "Sevilla"),
    ("Marchena", 37.3300, -5.4167, "Sevilla"),
    ("Moron de la Frontera", 37.1211, -5.4511, "Sevilla"),
    ("Lebrija", 36.9191, -6.0786, "Sevilla"),
    ("Sanlucar la Mayor", 37.3833, -6.2000, "Sevilla"),
    ("Lora del Rio", 37.6600, -5.5200, "Sevilla"),
    ("Estepa", 37.2931, -4.8797, "Sevilla"),
    ("Cazalla de la Sierra", 37.9297, -5.7606, "Sevilla"),
    ("Constantina", 37.8717, -5.6183, "Sevilla"),
    ("Guillena", 37.5414, -6.0567, "Sevilla"),
    ("Alcala del Rio", 37.5169, -5.9786, "Sevilla"),
    ("Palomares del Rio", 37.3156, -6.0600, "Sevilla"),
    ("Gines", 37.3869, -6.0786, "Sevilla"),
    ("Castilleja de la Cuesta", 37.3861, -6.0522, "Sevilla"),
]
# --- CONTROL DE SPAM (limite global entre workers) ---
_last_send_time = 0
_lock_envio = threading.Lock()

# --- SOTA SPOT ---
def obtener_token_sota():
    try:
        r = requests.post(SOTA_TOKEN_URL, data={
            "client_id": SOTA_CLIENT_ID,
            "username": SOTA_USER,
            "password": SOTA_PASS,
            "grant_type": "password"
        }, timeout=15)
        if r.status_code == 200:
            return r.json().get("access_token")
    except:
        pass
    return None

def validar_cumbre_sota(assoc, summit):
    try:
        token = obtener_token_sota()
        if not token:
            return None, "Error auth SOTA"
        r = requests.get(f"https://api2.sota.org.uk/api/summits/{assoc}/{summit}", headers={
            "Authorization": f"Bearer {token}"
        }, timeout=15)
        if r.status_code == 200:
            return r.json(), None
        return None, f"Codigo de cumbre invalido ({assoc}/{summit})"
    except Exception as e:
        return None, f"Error validando cumbre: {e}"

def parsear_ref_sota(ref):
    if "/" in ref:
        partes = ref.split("/")
        if len(partes) == 2:
            return partes[0], partes[1]
    elif ref.count("-") >= 1:
        idx = ref.index("-")
        return ref[:idx], ref[idx+1:]
    return None, None

def obtener_spots_sota(limite=10):
    try:
        r = requests.get(f"https://api2.sota.org.uk/api/spots/{limite}/all", timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        debug_log(f"SOTA spots error: {e}")
    return None


def publicar_spot_sota(activator_callsign, summit_ref, frecuencia, modo, comentario=""):
    try:
        debug_log("SOTA: enter publicar_spot_sota")
        token = obtener_token_sota()
        if not token:
            debug_log("SOTA: no token")
            return "\u274c Error auth SOTA"
        assoc, summit = parsear_ref_sota(summit_ref)
        if not assoc or not summit:
            debug_log("SOTA: bad format")
            return "\u274c Formato: EA7/AL-001 o EA7-AL-001"
        cumbre, err = validar_cumbre_sota(assoc, summit)
        if err:
            debug_log(f"SOTA: val error: {err}")
            return f"\u274c {err}"
        payload = {
            "activatorCallsign": activator_callsign,
            "associationCode": assoc,
            "summitCode": summit,
            "frequency": frecuencia,
            "mode": modo.upper(),
            "comments": comentario or "",
            "posterCallsign": SOTA_USER,
        }
        debug_log(f"SOTA: payload: {payload}")
        debug_log("SOTA: calling POST")
        r = requests.post(SOTA_API_URL, json=payload, headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }, timeout=15)
        if r.status_code in (200, 201):
            debug_log("SOTA: success")
            return f"\u2705 Spot SOTA publicado: {activator_callsign} {summit_ref} {frecuencia}MHz {modo.upper()}"
        else:
            cuerpo = r.text[:200].replace("\n", " ")
            debug_log(f"SOTA: POST error {r.status_code}")
            debug_log(f"SOTA: body: {r.text[:500]}")
            return f"\u274c Error SOTA ({r.status_code}): {cuerpo}"
    except Exception as e:
        debug_log(f"SOTA: exception: {e}")
        return f"\u274c Error: {e}"



# --- MEDUSAS (MEDUSEO) ---
MEDUSEO_REGIONES = {
    "almeria": {"nombre": "Almer\u00eda", "slug": "costa-almeria-15", "filtrar": False},
    "granada": {"nombre": "Granada", "slug": "costa-del-sol-16", "filtrar": True},
    "malaga": {"nombre": "M\u00e1laga", "slug": "costa-del-sol-16", "filtrar": True},
}

CIUDADES_MEDUSAS = {
    "granada": ["motril", "almu\u00f1\u00e9car", "almunecar", "salobre\u00f1a", "salobrena",
                "torrenueva", "gualchos", "l\u00fajar", "lujar", "rubite", "polopos",
                "sorvil\u00e1n", "sorvilan", "albu\u00f1ol", "albunol", "castell de ferro",
                "calahonda", "la herradura", "cotobro", "velilla", "taramay",
                "carchuna", "caleta", "granada"],
    "malaga": ["m\u00e1laga", "malaga", "nerja", "torrox", "v\u00e9lez", "velez",
               "rincon", "rinc\u00f3n", "benalm\u00e1dena", "benalmadena", "fuengirola",
               "mijas", "marbella", "estepona", "torremolinos", "manilva", "casares",
               "benajarafe", "chingal", "maro", "frigiliana"],
}

DENSIDAD_MEDUSAS = {
    "none": {"emoji": "\u2705", "label": "Ninguna"},
    "very little": {"emoji": "\u26aa", "label": "Muy pocas"},
    "few": {"emoji": "\U0001f7e1", "label": "Algunas"},
    "a lot": {"emoji": "\U0001f534", "label": "Muchas"},
}

SPECIES_ABREV = {
    "Pelagia Noctiluca": "PN", "Aurelia Aurita": "AA",
    "Chrysaora hysoscella": "CH", "Rhizostoma pulmo": "RP",
    "Rhizostoma octopus": "RO", "Cotylorhiza tuberculata": "CT",
    "other": "?", "": "?"
}

def obtener_medusas(provincia="almeria"):
    provincia = provincia.lower()
    info = MEDUSEO_REGIONES.get(provincia)
    if not info:
        return None
    try:
        r = requests.get("https://meduseo.com/en/regions/" + info['slug'], timeout=10)
        if r.status_code != 200:
            debug_log("Medusas HTTP " + str(r.status_code))
            return None
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(r.text, "lxml")
        rows = soup.select("table tbody tr") or soup.select("table tr")
        avistamientos = []
        for row in rows:
            tds = row.find_all("td")
            if len(tds) >= 4:
                fecha_raw = tds[0].get_text(strip=True)
                loc_raw = tds[1].get_text(strip=True)
                dens_raw = tds[2].get_text(strip=True).lower()
                sp_raw = tds[3].get_text(strip=True)
                if not fecha_raw:
                    continue
                ciudad, playa = "", ""
                for sep in ["\U0001f3d7", "\U0001f3d6", "\U0001f3d4", "\u26f1", "\U0001f3d5"]:
                    if sep in loc_raw:
                        ciudad, _, playa = loc_raw.partition(sep)
                        ciudad = ciudad.strip()
                        playa = playa.strip()
                        break
                if not ciudad:
                    ciudad = loc_raw
                    playa = loc_raw
                if info["filtrar"]:
                    limite = CIUDADES_MEDUSAS.get(provincia, [])
                    if not any(c in ciudad.lower().replace("\u0301", "") for c in limite):
                        continue
                fecha = fecha_raw[:5] if "/" in fecha_raw and len(fecha_raw) >= 5 else fecha_raw
                sp_abrev = "?"
                for k, v in SPECIES_ABREV.items():
                    if k and k.lower() in sp_raw.lower():
                        sp_abrev = v
                        break
                dinfo = DENSIDAD_MEDUSAS.get(dens_raw, {"emoji": "\u2753", "label": dens_raw})
                avistamientos.append({
                    "fecha": fecha,
                    "playa": playa or ciudad,
                    "ciudad": ciudad,
                    "densidad": dens_raw,
                    "densidad_emoji": dinfo["emoji"],
                    "densidad_label": dinfo["label"],
                    "especie": sp_raw or "?",
                    "especie_abrev": sp_abrev,
                })
        return {"provincia": info["nombre"], "avistamientos": avistamientos}
    except Exception as e:
        debug_log("Medusas error: " + str(e))
        return None

def formatear_medusas_radio(data):
    if not data or not data.get("avistamientos"):
        return "\u274c No hay datos de medusas"
    from datetime import date
    hoy = date.today().strftime("%d/%m")
    avisos = [a for a in data["avistamientos"] if a["fecha"] == hoy]
    if not avisos:
        return "\u2705 No hay avisos activos hoy en " + data["provincia"]
    lines = ["\U0001fabc AVISOS MEDUSAS " + data["provincia"]]
    for a in avisos[:4]:
        lines.append(a["playa"] + " " + a["fecha"] + " " + a["densidad_emoji"] + " " + a["especie_abrev"])
    return "\n".join(lines)

def formatear_medusas_telegram(data):
    if not data or not data.get("avistamientos"):
        return "\u274c No hay datos de medusas"
    avs = data["avistamientos"][:8]
    lines = ["\U0001fabc *MEDUSAS " + data["provincia"] + "*"]
    for a in avs:
        if a["ciudad"] and a["ciudad"] != a["playa"]:
            loc = a["playa"] + " (" + a["ciudad"] + ")"
        else:
            loc = a["playa"]
        lines.append("")
        lines.append("\U0001f4cd " + loc)
        lines.append(a["densidad_emoji"] + " " + a["densidad_label"] + " \u00b7 " + a["especie"] + " \u00b7 " + a["fecha"])
    return "\n".join(lines)
CODIGOS_PROVINCIAS = {
    "alava": "01", "albacete": "02", "alicante": "03", "almeria": "04", "avila": "05",
    "badajoz": "06", "baleares": "07", "barcelona": "08", "burgos": "09", "caceres": "10",
    "cadiz": "11", "castellon": "12", "ciudad real": "13", "cordoba": "14", "coruña": "15",
    "cuenca": "16", "girona": "17", "granada": "18", "guadalajara": "19", "guipuzcoa": "20",
    "huelva": "21", "huesca": "22", "jaen": "23", "leon": "24", "lleida": "25", "rioja": "26",
    "lugo": "27", "madrid": "28", "malaga": "29", "murcia": "30", "navarra": "31",
    "ourense": "32", "asturias": "33", "palencia": "34", "las palmas": "35", "pontevedra": "36",
    "salamanca": "37", "tenerife": "38", "cantabria": "39", "segovia": "40", "sevilla": "41",
    "soria": "42", "tarragona": "43", "teruel": "44", "toledo": "45", "valencia": "46",
    "valladolid": "47", "vizcaya": "48", "zamora": "49", "zaragoza": "50", "ceuta": "51", "melilla": "52"
}

COORDENADAS_PROVINCIAS = {
    "almeria": (36.83, -2.45), "granada": (37.17, -3.60), "malaga": (36.72, -4.42),
    "cadiz": (36.52, -6.28), "huelva": (37.26, -6.94), "sevilla": (37.38, -5.98),
    "cordoba": (37.88, -4.77), "jaen": (37.76, -3.78), "madrid": (40.41, -3.70),
    "barcelona": (41.38, 2.17), "valencia": (39.46, -0.37), "murcia": (37.98, -1.13)
}

# --- BASE DE DATOS ---
def iniciar_db():
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS nodos 
                     (id TEXT PRIMARY KEY, nombre TEXT, hops INTEGER, fecha TEXT, rol TEXT, estado_hops_mal INTEGER DEFAULT 0)''')
        c.execute('''CREATE TABLE IF NOT EXISTS trafico 
                     (id TEXT PRIMARY KEY, mensajes INTEGER DEFAULT 0)''')
        c.execute('''CREATE TABLE IF NOT EXISTS registro_mensajes 
                     (id TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS posiciones 
                     (id TEXT, timestamp REAL, intervalo_seg INTEGER, ultimo_aviso REAL DEFAULT 0, estado_mal INTEGER DEFAULT 0)''')
        c.execute('''CREATE TABLE IF NOT EXISTS terremotos 
                     (id TEXT PRIMARY KEY, magnitud REAL, ubicacion TEXT, fecha TEXT, enviado INTEGER DEFAULT 1)''')
        c.execute('''CREATE TABLE IF NOT EXISTS alertas_enviadas 
                     (headline TEXT PRIMARY KEY, fecha TEXT)''')
        c.execute('CREATE TABLE IF NOT EXISTS incendios_alertas (fire_id TEXT PRIMARY KEY, fecha TEXT)')
        c.execute('''CREATE TABLE IF NOT EXISTS cache_qrz 
                     (callsign TEXT PRIMARY KEY, nombre TEXT, qth TEXT, pais TEXT, timestamp INTEGER)''')
        c.execute('''CREATE TABLE IF NOT EXISTS calima_alertas
                     (provincia TEXT PRIMARY KEY, valor REAL, fecha TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS metricas_hora
                     (ts INTEGER PRIMARY KEY, ocupacion REAL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS routers_snapshot
                     (ts INTEGER, alias TEXT, online INTEGER)''')
        c.execute("CREATE INDEX IF NOT EXISTS idx_registro_ts ON registro_mensajes(timestamp)")
        
        c.execute("PRAGMA table_info(nodos)")
        col_nodos = [col[1] for col in c.fetchall()]
        if 'estado_hops_mal' not in col_nodos:
            c.execute("ALTER TABLE nodos ADD COLUMN estado_hops_mal INTEGER DEFAULT 0")

        if 'short_name' not in col_nodos:
            c.execute("ALTER TABLE nodos ADD COLUMN short_name TEXT")

        if 'creado' not in col_nodos:
            c.execute("ALTER TABLE nodos ADD COLUMN creado TEXT")

        # Tabla de configuracion global (proteccion, etc.)
        c.execute('''CREATE TABLE IF NOT EXISTS config
                     (key TEXT PRIMARY KEY, value TEXT)''')
        c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('proteccion_activa', '1')")
        conn.commit()
    except Exception as e:
        logging.error(f"Error al iniciar DB: {e}")
    finally:
        if conn: conn.close()

def get_proteccion():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        c = conn.cursor()
        c.execute("SELECT value FROM config WHERE key = 'proteccion_activa'")
        row = c.fetchone()
        return int(row[0]) if row else 1
    except:
        return 1
    finally:
        if conn: conn.close()

def set_proteccion(val):
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('proteccion_activa', ?)", (str(val),))
        conn.commit()
    except:
        pass
    finally:
        if conn: conn.close()

def guardar_nodo_db(node_id, nombre, hops, rol=None, short_name=None):
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        c = conn.cursor()
        fecha_act = datetime.now().strftime("%d/%m %H:%M")
        nombre_str = str(nombre).strip()
        nombre_final = node_id if not nombre or nombre_str in ["None", "", node_id] else nombre_str
        rol_guardar = str(rol) if rol else "DESCONOCIDO"
        short_name_final = str(short_name).strip() if short_name else ""
        
        c.execute('''INSERT INTO nodos (id, nombre, hops, fecha, rol, short_name, creado) VALUES (?, ?, ?, ?, ?, ?, datetime('now','localtime'))
                     ON CONFLICT(id) DO UPDATE SET
                       hops=excluded.hops, fecha=excluded.fecha,
                       nombre=CASE WHEN excluded.nombre = excluded.id THEN nodos.nombre ELSE excluded.nombre END,
                       short_name=CASE WHEN excluded.short_name = '' OR excluded.short_name = excluded.id THEN nodos.short_name ELSE excluded.short_name END,
                       rol=CASE WHEN excluded.rol = 'DESCONOCIDO' THEN nodos.rol ELSE excluded.rol END''',
                  (node_id, nombre_final, hops, fecha_act, rol_guardar, short_name_final))
        conn.commit()
    except Exception as e:
        logging.error(f"Error al guardar nodo {node_id}: {e}")
    finally:
        if conn: conn.close()

def registrar_trafico(node_id):
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        c = conn.cursor()
        c.execute('''INSERT INTO trafico (id, mensajes) VALUES (?, 1)
                     ON CONFLICT(id) DO UPDATE SET mensajes = mensajes + 1''', (node_id,))
        c.execute("INSERT INTO registro_mensajes (id) VALUES (?)", (node_id,))
        conn.commit()
    except Exception as e:
        logging.error(f"Error al registrar trafico {node_id}: {e}")
    finally:
        if conn: conn.close()

# --- FUNCIONES DE APOYO ---
def enviar_telegram(mensaje, destino_id=MI_CHAT_ID, thread_id=None):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": destino_id, "text": mensaje, "parse_mode": "Markdown"}
    if thread_id:
        payload["message_thread_id"] = thread_id
    try: requests.post(url, json=payload, timeout=10)
    except: pass

def localidad_cercana(lat, lon):
    mejor_nombre = None
    mejor_prov = "Almeria"
    mejor_dist = 999.0
    for nombre, tlat, tlon, prov in TOWNS:
        dlat = lat - tlat
        dlon = lon - tlon
        dist = (dlat*dlat + dlon*dlon) ** 0.5
        if dist < mejor_dist:
            mejor_dist = dist
            mejor_nombre = nombre
            mejor_prov = prov
    if mejor_dist * 111 > 12:
        return None, None
    return mejor_nombre, mejor_prov


def obtener_channel(iface, provincia):
    nombre_canal = CANALES.get(provincia)
    if not nombre_canal:
        return 0
    try:
        if hasattr(iface.localNode, 'channels'):
            for ch in iface.localNode.channels:
                if ch.settings.name == nombre_canal:
                    return ch.index
    except Exception as e:
        logging.error(f"Error buscando canal {nombre_canal}: {e}")
    return 0
def enviar_con_limite(iface, msg_radio, ch_index, msg_telegram=None, chat_id=None):
    global _last_send_time
    with _lock_envio:
        ahora = time.time()
        if ahora - _last_send_time < 20:
            return False
        iface.sendText(msg_radio, destinationId=meshtastic.BROADCAST_ADDR, channelIndex=ch_index, wantAck=False)
        if msg_telegram and chat_id:
            enviar_telegram(msg_telegram, chat_id)
        _last_send_time = time.time()
        return True

def formatear_tiempo_corto(segundos):
    if segundos < 3600: return f"{int(segundos/60)}m"
    return f"{int(segundos/3600)}h{int((segundos%3600)/60)}m"

def grados_a_flecha(g):
    if g is None: return "➡️"
    if (g >= 337.5) or (g < 22.5): return "⬇️N"
    if (g >= 22.5) and (g < 67.5): return "↙️NE"
    if (g >= 67.5) and (g < 112.5): return "⬅️E"
    if (g >= 112.5) and (g < 157.5): return "↖️SE"
    if (g >= 157.5) and (g < 202.5): return "⬆️S"
    if (g >= 202.5) and (g < 247.5): return "↗️SW"
    if (g >= 247.5) and (g < 292.5): return "➡️W"
    if (g >= 292.5) and (g < 337.5): return "↘️NW"
    return "➡️"

def interpretar_wmo(c):
    mapeo = {0:"Despejado☀️", 1:"Despejado🌤️", 2:"Nublado⛅", 3:"Cubierto☁️", 45:"Niebla🌫️", 61:"Lluvia🌧️", 80:"Chubascos🌧️", 95:"Tormenta⛈️"}
    return mapeo.get(c, "Var.☁️")

def obtener_datos_clima(lat=36.83, lon=-2.45):
    try:
        url = f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&current=temperature_2m,relative_humidity_2m,weather_code,wind_speed_10m,wind_direction_10m&daily=weather_code,temperature_2m_max,temperature_2m_min,wind_gusts_10m_max,wind_direction_10m_dominant&timezone=auto"
        r = requests.get(url, timeout=10)
        return r.json()
    except: return None

def obtener_clima_espacial():
    try:
        url = "https://www.hamqsl.com/solarxml.php"
        headers = {'User-Agent': 'Mozilla/5.0'}
        r = requests.get(url, headers=headers, timeout=12)
        if r.status_code != 200: return "⚠️ Error: Servidor solar caído."
        
        root = ET.fromstring(r.content)
        sol = root.find('solardata')
        
        sfi = sol.findtext('solarflux', 'N/A')
        ssn = sol.findtext('sunspots', 'N/A')
        kp_raw = sol.findtext('kindex', '0').strip()
        
        kp_int = int(kp_raw) if kp_raw.isdigit() else 0
        geomag = sol.findtext('geomagfield', 'Desconocido').upper()
        
        geo_es = {"QUIET": "Tranquilo ✅", "UNSETTLED": "Inestable ⚠️", "STORM": "TORMENTA 🔴"}
        estado_final = geo_es.get(geomag, geomag)

        if kp_int <= 3: semaforo = "🟢 ÓPTIMO"
        elif kp_int == 4: semaforo = "🟡 RUIDO MODERADO"
        else: semaforo = "🔴 INTERFERENCIAS / MALO"

        res = (f"☀️ *ESTADO SOLAR PARA MESHTASTIC*\n\n"
               f"💠 *Índice Kp:* {kp_int} ({estado_final})\n"
               f"💠 *Actividad (SFI/SSN):* {sfi} / {ssn}\n\n"
               f"📡 *ESTADO BANDA 868MHz:*\n"
               f"【 {semaforo} 】")
        return res
    except:
        return "⚠️ Error al procesar datos solares."

def obtener_prevision_3_dias(lat=36.83, lon=-2.45):
    try:
        data = obtener_datos_clima(lat, lon)
        if not data: return "⚠️ Error clima."
        d = data['daily']
        txt = "🔮 *PREVISIÓN 3 DÍAS*\n"
        for i in range(1, 4):
            f_dia = datetime.strptime(d['time'][i], "%Y-%m-%d").strftime("%d/%m")
            txt += f"• {f_dia}: {interpretar_wmo(d['weather_code'][i])} {int(d['temperature_2m_max'][i])}° {grados_a_flecha(d['wind_direction_10m_dominant'][i])}\n"
        return txt.strip()
    except: return "⚠️ Error"

def obtener_calima(lat, lon):
    try:
        url = (f"https://air-quality-api.open-meteo.com/v1/air-quality"
               f"?latitude={lat}&longitude={lon}&current=pm10,dust&timezone=auto")
        r = requests.get(url, timeout=10)
        return r.json().get("current")
    except Exception:
        return None

def formatear_calima(prov, cur):
    pm10 = cur.get("pm10") if cur else None
    dust = cur.get("dust") if cur else None
    if pm10 is None and dust is None:
        return "⚠️ Error datos calidad del aire."
    activa = (pm10 or 0) >= CALIMA_UMBRAL_PM10
    lineas = [f"🌬️ *CALIMA ACTIVA* — *{prov.upper()}*" if activa else f"✅ *SIN CALIMA* — *{prov.upper()}*"]
    if pm10 is not None:
        lineas.append(f"• PM10: `{round(pm10)}` µg/m³ (umbral {int(CALIMA_UMBRAL_PM10)})")
    if dust is not None:
        lineas.append(f"• Polvo sahariano: `{round(dust)}` µg/m³")
    if not activa and pm10 is not None and pm10 >= CALIMA_UMBRAL_PM10 * 0.6:
        lineas.append("ℹ️ PM10 elevado, posible entrada de calima.")
    return "\n".join(lineas)

def _recortar_bytes(txt, max_bytes):
    while txt and len(txt.encode('utf-8')) > max_bytes:
        txt = txt[:-1]
    return txt.rstrip()

def consultar_ia(pregunta, nodo_id=None, modo_largo=False):
    ahora = time.time()
    with _ia_lock:
        restante_g = IA_COOLDOWN_GLOBAL - (ahora - _ia_last_global[0])
        if restante_g > 0:
            return "⏳ IA ocupada. Espera {}s.".format(int(restante_g) + 1)
        if nodo_id:
            restante_n = IA_COOLDOWN_NODO - (ahora - _ia_last_nodo.get(nodo_id, 0))
            if restante_n > 0:
                return "⏳ Espera {}s entre consultas.".format(int(restante_n) + 1)
        _ia_last_global[0] = ahora
        if nodo_id:
            _ia_last_nodo[nodo_id] = ahora
    try:
        limite = "700" if modo_largo else "180"
        system = ("Eres el asistente de una red comunitaria Meshtastic en Almería, España. "
                  "Responde SIEMPRE en español, de forma directa y útil. "
                  f"Usa como máximo {limite} caracteres de texto plano: sin markdown, sin asteriscos, sin emojis y sin listas.")
        r = requests.post(IA_API_URL,
                          headers={"Authorization": "Bearer " + IA_API_KEY},
                          json={"model": IA_MODEL,
                                "messages": [{"role": "system", "content": system},
                                             {"role": "user", "content": pregunta}],
                                "max_tokens": 900 if modo_largo else 400,
                                "temperature": 0.3,
                                "reasoning_effort": "low"},
                          timeout=IA_TIMEOUT)
        msg_ia = r.json()["choices"][0]["message"]
        txt = (msg_ia.get("content") or "").strip()
    except Exception as e:
        logging.warning(f"IA: {e}")
        return "⚠️ IA sin respuesta."
    txt = txt.replace("*", "").replace("`", "").strip()
    if modo_largo:
        return ("🤖 " + txt[:800]) if txt else "⚠️ IA sin respuesta."
    cuerpo = _recortar_bytes(txt, IA_MAX_BYTES_RADIO - len("🤖 ".encode("utf-8")))
    return ("🤖 " + cuerpo) if cuerpo else "⚠️ IA sin respuesta."

def ejecutar_trace(iface, destino_id):
    global _trace_pending
    destino_id = destino_id.strip()
    if not re.fullmatch(r"!?[0-9a-fA-F]{8}", destino_id):
        return "⚠️ Formato: `/trace !xxxxxxxx` (ID hexadecimal del nodo)."
    destino_id = "!" + destino_id.lstrip("!").lower()
    try:
        num_dest = int(destino_id[1:], 16)
    except ValueError:
        return "⚠️ ID no válido."
    conocido = iface.nodes.get(destino_id)
    with _trace_lock:
        if _trace_pending is not None:
            return "⏳ Ya hay un trace en curso. Espera a que termine."
        _trace_pending = {"dest": destino_id, "num": num_dest, "evento": threading.Event(), "lineas": []}
    try:
        rd = meshtastic.mesh_pb2.RouteDiscovery()
        iface.sendData(rd, destinationId=destino_id,
                       portNum=meshtastic.portnums_pb2.PortNum.TRACEROUTE_APP,
                       wantResponse=True, hopLimit=TRACE_HOP_LIMIT, channelIndex=0)
    except Exception as e:
        with _trace_lock:
            _trace_pending = None
        return f"❌ Error enviando traceroute: {e}"
    pend = _trace_pending
    ok = pend["evento"].wait(TRACE_TIMEOUT)
    with _trace_lock:
        lineas = list(pend.get("lineas") or [])
        _trace_pending = None
    nombre = ((conocido or {}).get('user', {}).get('shortName')
              or (conocido or {}).get('user', {}).get('longName') or destino_id)
    if not ok or not lineas:
        return (f"⏱ *Sin respuesta de {destino_id}* en {TRACE_TIMEOUT}s.\n"
                f"(Nodo apagado, dormido o fuera de alcance)")
    cabecera = f"🛰 *TRACEROUTE → {nombre}*"
    if nombre != destino_id:
        cabecera += f" `{destino_id}`"
    out = cabecera + "\n" + "\n".join(lineas)
    return out

def obtener_precios_gasolina(provincia_nombre="almeria", modo_radio=False):
    try:
        cod = CODIGOS_PROVINCIAS.get(provincia_nombre.lower())
        if not cod: return "⚠️ Provincia no reconocida."

        url = f"https://sedeaplicaciones.minetur.gob.es/ServiciosRESTCarburantes/PreciosCarburantes/EstacionesTerrestres/FiltroProvincia/{cod}"
        r = requests.get(url, timeout=15)
        datos = r.json()
        lista_estaciones = datos.get("ListaEESSPrecio", [])
        
        g95, diesel = [], []
        for e in lista_estaciones:
            p_g95 = e.get("Precio Gasolina 95 E5", "").replace(",", ".")
            p_die = e.get("Precio Gasoleo A", "").replace(",", ".")
            rot = e.get("Rótulo", "S/D")
            dir_e = e.get("Dirección", "S/D")
            
            if p_g95: g95.append({"rot": rot, "pre": float(p_g95), "dir": dir_e})
            if p_die: diesel.append({"rot": rot, "pre": float(p_die), "dir": dir_e})
            
        top_g = sorted(g95, key=lambda x: x['pre'])
        top_d = sorted(diesel, key=lambda x: x['pre'])

        if modo_radio:
            res = f"⛽ {provincia_nombre.upper()}\n"
            if top_g: res += f"G95: {top_g[0]['pre']} - {top_g[0]['rot'][:10]} ({top_g[0]['dir'][:15]})\n"
            if top_d: res += f"Die: {top_d[0]['pre']} - {top_d[0]['rot'][:10]} ({top_d[0]['dir'][:15]})"
            return res
        else:
            res = f"⛽ *{provincia_nombre.upper()}*\n"
            res += "*G95:*\n"
            medallas = ["🥇","🥈","🥉"]
            for i, x in enumerate(top_g[:3]): res += f"{medallas[i]} {x['pre']} - {x['rot']} ({x['dir']})\n"
            res += "*Diesel:*\n"
            for i, x in enumerate(top_d[:3]): res += f"{medallas[i]} {x['pre']} - {x['rot']} ({x['dir']})\n"
            return res
    except: return "⚠️ Error consulta gasolina."

def _qrz_ns(tag):
    return "{http://xmldata.qrz.com}" + tag

def obtener_sesion_qrz():
    try:
        url = "https://xmldata.qrz.com/xml/current/"
        params = f"username={QRZ_USER};password={QRZ_PASS};agent=BotAlmeria"
        r = requests.get(f"{url}?{params}", timeout=10)
        root = ET.fromstring(r.content)
        key_el = root.find(f".//{_qrz_ns('Key')}")
        if key_el is not None and key_el.text:
            return key_el.text.strip()
    except:
        return None

def consultar_qrz_api(indicativo):
    session_key = obtener_sesion_qrz()
    if not session_key:
        return None
    try:
        url = "https://xmldata.qrz.com/xml/current/"
        params = f"s={session_key};callsign={indicativo}"
        r = requests.get(f"{url}?{params}", timeout=10)
        root = ET.fromstring(r.content)
        error_el = root.find(f".//{_qrz_ns('Session')}/{_qrz_ns('Error')}")
        if error_el is not None:
            return None
        callsign = root.find(f".//{_qrz_ns('Callsign')}")
        if callsign is None:
            return None
        fname_el = callsign.find(_qrz_ns('fname'))
        name_el = callsign.find(_qrz_ns('name'))
        addr2_el = callsign.find(_qrz_ns('addr2'))
        country_el = callsign.find(_qrz_ns('country'))
        fname = fname_el.text.strip() if fname_el is not None and fname_el.text else ""
        name = name_el.text.strip() if name_el is not None and name_el.text else ""
        addr2 = addr2_el.text.strip() if addr2_el is not None and addr2_el.text else ""
        country = country_el.text.strip() if country_el is not None and country_el.text else ""
        nombre_completo = f"{fname} {name}".strip()
        if not nombre_completo:
            return None
        return {"nombre": nombre_completo, "qth": addr2, "pais": country}
    except:
        return None

def cache_qrz_get(indi):
    conn = sqlite3.connect(DB_PATH, timeout=5)
    try:
        c = conn.cursor()
        c.execute("SELECT nombre, qth, pais, timestamp FROM cache_qrz WHERE callsign = ?", (indi,))
        row = c.fetchone()
        if row and (time.time() - row[3]) < QRZ_CACHE_TTL:
            return {"nombre": row[0], "qth": row[1], "pais": row[2]}
    except:
        pass
    finally:
        conn.close()
    return None

def cache_qrz_set(indi, datos):
    conn = sqlite3.connect(DB_PATH, timeout=5)
    try:
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO cache_qrz (callsign, nombre, qth, pais, timestamp) VALUES (?, ?, ?, ?, ?)",
                  (indi, datos["nombre"], datos["qth"], datos["pais"], int(time.time())))
        conn.commit()
    except:
        pass
    finally:
        conn.close()

def formatear_qrz_radio(datos, indi):
    nombre = datos["nombre"][:20]
    qth = datos["qth"][:25] if datos["qth"] else datos["pais"][:15]
    return f"\U0001f194 {indi}\n\U0001f464 {nombre}\n\U0001f4cd {qth}"

def formatear_qrz_telegram(datos, indi):
    nombre = datos["nombre"]
    qth = datos["qth"] or "N/D"
    pais = datos["pais"] or "N/D"
    return f"\U0001f4e1 *QRZ: {indi}*\n\U0001f464 *Nombre:* {nombre}\n\U0001f4cd *QTH:* {qth}\n\U0001f30d *Pa\u00eds:* {pais}\n\U0001f517 [Perfil](https://www.qrz.com/db/{indi})"

def obtener_datos_hamqth(indicativo, modo_radio=False):
    indi = re.sub(r'[^a-zA-Z0-9]', '', indicativo).upper()
    if not indi:
        return "\u26a0\ufe0f Indicativo no v\u00e1lido."

    # 1. Check SQLite cache
    cache = cache_qrz_get(indi)
    if cache:
        if modo_radio: return formatear_qrz_radio(cache, indi)
        else: return formatear_qrz_telegram(cache, indi)

    # 2. Try QRZ API
    datos = consultar_qrz_api(indi)
    if datos:
        cache_qrz_set(indi, datos)
        if modo_radio: return formatear_qrz_radio(datos, indi)
        else: return formatear_qrz_telegram(datos, indi)

    # 3. Fallback: scraping HamQTH
    if not BS4_AVAILABLE:
        return "\u26a0\ufe0f Error: no disponible."
    try:
        url = f"https://www.hamqth.com/{indi}"
        headers = {'User-Agent': 'Mozilla/5.0'}
        r = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(r.content, 'html.parser')
        nombre, qth = "N/A", "N/A"
        label_nombre = soup.find(string=re.compile(r'Nombre:|Name:', re.I))
        if label_nombre: nombre = label_nombre.find_next().text.strip()
        label_qth = soup.find(string=re.compile(r'QTH:', re.I))
        if label_qth: qth = label_qth.find_next().text.strip()
        if nombre == "N/A" and qth == "N/A": return f"\u274c {indi} no encontrado."
        if modo_radio: return f"\U0001f194 {indi}\n\U0001f464 {nombre[:20]}\n\U0001f4cd {qth[:20]}"
        else: return f"\U0001f4e1 *HAMQTH: {indi}*\n\U0001f464 *Nombre:* {nombre}\n\U0001f4cd *QTH:* {qth}\n\U0001f517 [Perfil](https://www.hamqth.com/{indi})"
    except: return "\u26a0\ufe0f Error consulta."

# --- FUNCIÓN DE VERIFICACIÓN MQTT ---
MQTT_SERVER = _env("MQTT_SERVER", "mqtt.meshtastic.pt")
MQTT_PORT = int(_env("MQTT_PORT", "1883"))
MQTT_USER = _env("MQTT_USER", "EA7!")
MQTT_PASS = _env("MQTT_PASS")
MQTT_TOPIC = _env("MQTT_TOPIC", "msh/EA7")

def probar_mqtt():
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.username_pw_set(MQTT_USER, MQTT_PASS)
        client.connect(MQTT_SERVER, MQTT_PORT, 10)
        client.disconnect()
        return True
    except:
        return False

def mqtt_check_worker():
    global MQTT_CONNECTED
    while True:
        try:
            MQTT_CONNECTED = probar_mqtt()
        except:
            pass
        time.sleep(300)

# --- PROCESADOR RADIO ---
def _nombre_nodo(interface, node_id):
    """Resuelve el nombre corto de un nodo con lookup insensible a mayúsculas."""
    low = str(node_id).lower()
    n_info = interface.nodes.get(low) or {}
    if not n_info:
        for k, v in (interface.nodes or {}).items():
            if str(k).lower() == low:
                n_info = v
                break
    return n_info.get('user', {}).get('shortName') or node_id

def on_receive(packet, interface):
    try:
        raw_num_id = packet.get('from') 
        if not raw_num_id: return
        # Normalizar SIEMPRE a !xxxxxxxx en minúsculas (la lib 2.7.7 puede
        # traer 'from' como int o str, y en este caso el lookup coincide).
        if isinstance(raw_num_id, str):
            limpio = raw_num_id.lstrip('!')
            sender_id = "!{}".format(limpio.lower()) if limpio else raw_num_id.lower()
        else:
            sender_id = "!{:08x}".format(raw_num_id)
        if sender_id == MI_NODO_ID: return

        source_channel = packet.get('channel', 0)
        
        registrar_trafico(sender_id)

        # --- DETECCIÓN RF VS MQTT ---
        via_mqtt = packet.get('viaMqtt', False)
        transport = packet.get('transportMechanism')
        if via_mqtt or transport == meshtastic.mesh_pb2.MeshPacket.TRANSPORT_MQTT:
            via_emoji = "🌐"
        elif transport == meshtastic.mesh_pb2.MeshPacket.TRANSPORT_LORA or transport == meshtastic.mesh_pb2.MeshPacket.TRANSPORT_INTERNAL or transport is None:
            via_emoji = "📻"
        else:
            via_emoji = "📻"

        # --- DM NO_DEC ---
        if "decoded" not in packet and str(packet.get("toId", "")) == MI_NODO_ID:
            interface.sendText("DM cifrado. Usa canal Almeria para DM.", destinationId=raw_num_id, channelIndex=1, wantAck=True)
            return
        # --- LÓGICA DE CONTROL DE POSICIÓN ---
        if 'decoded' in packet and packet['decoded'].get('portnum') == 'POSITION_APP':
            ahora_pos = time.time()
            conn_pos = None
            try:
                conn_pos = sqlite3.connect(DB_PATH, timeout=10)
                cp = conn_pos.cursor()
                cp.execute("SELECT timestamp, ultimo_aviso, estado_mal FROM posiciones WHERE id = ? ORDER BY timestamp DESC LIMIT 1", (sender_id,))
                resultado = cp.fetchone()
                
                if resultado:
                    ultimo_ts, u_aviso, est_anterior = resultado
                    intervalo = int(ahora_pos - ultimo_ts)
                    if intervalo > 15:
                        s_name = _nombre_nodo(interface, sender_id)
                        if 15 < intervalo <= 1200:
                            proteccion = get_proteccion()
                            nuevo_aviso_ts = u_aviso
                            if proteccion and (ahora_pos - u_aviso) > 3600:
                                msg_cordial = f"{s_name}, posicion cada {int(intervalo/60)} min detectada. Por favor, ajusta a +20 min para no saturar. Para ayuda Telegram https://t.me/+8Zfyk53KL9tkMThk Gracias!"
                                interface.sendText(msg_cordial, destinationId=raw_num_id, wantAck=True)
                                nuevo_aviso_ts = ahora_pos
                                if est_anterior == 0:
                                    enviar_telegram(f"⚠️ *MALA TELEMETRÍA* {via_emoji}\nNodo: `{s_name}` (`{sender_id}`)\nIntervalo: `{int(intervalo/60)} min`.\nDM enviado por radio.", MI_CHAT_ID)
                            cp.execute("INSERT INTO posiciones (id, timestamp, intervalo_seg, ultimo_aviso, estado_mal) VALUES (?, ?, ?, ?, ?)", (sender_id, ahora_pos, intervalo, nuevo_aviso_ts, 1 if proteccion else 0))
                        else:
                            if est_anterior == 1:
                                enviar_telegram(f"✅ *NODO CORREGIDO*\nNodo: `{s_name}` (`{sender_id}`)\nIntervalo actual: `{int(intervalo/60)} min`.", MI_CHAT_ID)
                            cp.execute("INSERT INTO posiciones (id, timestamp, intervalo_seg, ultimo_aviso, estado_mal) VALUES (?, ?, ?, ?, 0)", (sender_id, ahora_pos, intervalo, u_aviso))
                    conn_pos.commit()
                else:
                    cp.execute("INSERT INTO posiciones (id, timestamp, intervalo_seg, ultimo_aviso, estado_mal) VALUES (?, ?, 0, 0, 0)", (sender_id, ahora_pos))
                    conn_pos.commit()
            except Exception as e: logging.error(f"Error logic posicion: {e}")
            finally:
                if conn_pos: conn_pos.close()
        
        # --- LÓGICA DE CONTROL DE SALTOS ---
        hops = packet.get('hopStart')
        if hops is not None:
            n_info = interface.nodes.get(sender_id, {})
            l_name = n_info.get('user', {}).get('longName')
            s_name = _nombre_nodo(interface, sender_id)
            n_role = n_info.get('user', {}).get('role')
            guardar_nodo_db(sender_id, l_name, hops, n_role, s_name)
            conn_h = None
            try:
                conn_h = sqlite3.connect(DB_PATH, timeout=10)
                ch = conn_h.cursor()
                ch.execute("SELECT estado_hops_mal FROM nodos WHERE id = ?", (sender_id,))
                res_h = ch.fetchone()
                est_hops_ant = res_h[0] if res_h else 0
                proteccion = get_proteccion()
                if hops >= 6:
                    ch.execute("UPDATE nodos SET estado_hops_mal = 1 WHERE id = ?", (sender_id,))
                elif hops <= 5:
                    ch.execute("UPDATE nodos SET estado_hops_mal = 0 WHERE id = ?", (sender_id,))
                conn_h.commit()
            except Exception as e: logging.error(f"Error logic saltos: {e}")
            finally:
                if conn_h: conn_h.close()

        # --- CAPTURA RESPUESTA TRACEROUTE (/trace) ---
        capturar_traceroute(packet, interface)

        # --- COMANDOS RADIO ---
        if 'decoded' in packet and packet['decoded'].get('portnum') == 'TEXT_MESSAGE_APP':
            msg_raw = packet['decoded']['payload'].decode('utf-8').strip()
            msg_lower = msg_raw.lower()
            msg_split = msg_lower.split(" ")
            msg_cmd = msg_split[0]
            msg_id_para_reply = packet.get('id')
            to_id_str = packet.get("toId", "")
            to_int = packet.get("to", 0xFFFFFFFF)
            es_dm = (to_id_str not in ("^all", "", None)) or (isinstance(to_int, int) and to_int != 0xFFFFFFFF and to_int != 0) 
            
            s_name = _nombre_nodo(interface, sender_id)

            ch_name = CHANNEL_NAMES.get(packet.get("channel", 0), "Ch{}".format(packet.get("channel", 0)))
            if not msg_cmd.startswith("/"):
                via_txt = "DM" if es_dm else "CANAL ({})".format(ch_name)
                enviar_telegram(f"💬 *MENSAJE {via_txt} DE {s_name}*\nTexto: `{msg_raw}`", MI_CHAT_ID)
            else:
                via_cmd = "DM" if es_dm else "CANAL ({})".format(ch_name)
                enviar_telegram(f"🤖 *COMANDO RADIO ({via_cmd})*\nNodo: `{s_name}`\nComando: `{msg_raw}`", MI_CHAT_ID)

                if source_channel == 0 and not es_dm:
                    return

                def responder(texto):
                    if es_dm:
                        interface.sendText(texto, destinationId=raw_num_id, channelIndex=source_channel, wantAck=True)
                    else:
                        interface.sendText(texto, destinationId=meshtastic.BROADCAST_ADDR, channelIndex=source_channel, wantAck=False, replyId=msg_id_para_reply)

                if msg_cmd == "/help":
                    responder("🤖 COMANDOS:\n/info, /tiempo, /viento, /prevision, /solar, /gasolina, /ra, /mqtt, /sota, /ping, /medusas, /calima, /ia, /status")
                elif msg_cmd == "/info":
                    ahora = time.time(); resp = "🏗️ ESTADO RED\n"
                    for nid, alias in ROUTERS_VIGILADOS.items():
                        n = interface.nodes.get(nid); ant = ahora-n['lastHeard'] if n and 'lastHeard' in n else None
                        if ant is not None: 
                            bat = n.get('deviceMetrics', {}).get('batteryLevel')
                            resp += f"{'🟢' if ant < MARGEN_ONLINE else '🔴'}{alias}:{formatear_tiempo_corto(ant)}{f'|B:{bat}%' if bat is not None else ''}\n"
                    responder(resp)
                elif msg_cmd == "/tiempo":
                    prov = msg_split[1] if len(msg_split) > 1 else CHANNEL_TO_PROV.get(source_channel, "Almeria").lower()
                    coords = COORDENADAS_PROVINCIAS.get(prov, (36.83, -2.45))
                    data = obtener_datos_clima(coords[0], coords[1])
                    if data:
                        c = data['current']; f = grados_a_flecha(c['wind_direction_10m'])
                        resp = f"🌤️ {prov.upper()}\n{interpretar_wmo(c['weather_code'])}\n🌡️ {c['temperature_2m']}°C | {f} {c['wind_speed_10m']}km/h"
                        responder(resp)
                elif msg_cmd == "/viento":
                    prov = msg_split[1] if len(msg_split) > 1 else CHANNEL_TO_PROV.get(source_channel, "Almeria").lower()
                    coords = COORDENADAS_PROVINCIAS.get(prov, (36.83, -2.45))
                    data = obtener_datos_clima(coords[0], coords[1])
                    if data:
                        d = data['daily']; f_h = grados_a_flecha(d['wind_direction_10m_dominant'][0]); f_m = grados_a_flecha(d['wind_direction_10m_dominant'][1])
                        resp = f"🚩 RACHAS {prov.upper()}\nHoy: {f_h} {d['wind_gusts_10m_max'][0]}km/h\nMañ: {f_m} {d['wind_gusts_10m_max'][1]}km/h"
                        responder(resp)
                elif msg_cmd == "/prevision":
                    prov = msg_split[1] if len(msg_split) > 1 else CHANNEL_TO_PROV.get(source_channel, "Almeria").lower()
                    coords = COORDENADAS_PROVINCIAS.get(prov, (36.83, -2.45))
                    responder(obtener_prevision_3_dias(coords[0], coords[1]).replace("*", ""))
                elif msg_cmd == "/solar":
                    responder(obtener_clima_espacial().replace("*", ""))
                elif msg_cmd == "/gasolina":
                    prov = msg_split[1] if len(msg_split) > 1 else "almeria"
                    responder(obtener_precios_gasolina(prov, modo_radio=True).replace("*", ""))
                elif msg_cmd == "/ra":
                    indi = msg_split[1] if len(msg_split) > 1 else ""
                    if indi: responder(obtener_datos_hamqth(indi, modo_radio=True))
                elif msg_cmd == "/mqtt":
                    resp = f"🌐 MQTT\nServidor: {MQTT_SERVER}\nUser: {MQTT_USER}\nPass: {MQTT_PASS}\nTopic: {MQTT_TOPIC} o msh"
                    responder(resp)
                elif msg_cmd == "/status":
                    ahora = time.time()
                    with open('/proc/uptime') as f: up_secs = int(float(f.read().split()[0]))
                    up_txt = f"{up_secs // 86400}d {(up_secs % 86400) // 3600}h {(up_secs % 3600) // 60}m"
                    conn = sqlite3.connect(DB_PATH)
                    cur = conn.cursor()
                    cur.execute("SELECT COUNT(*) FROM nodos"); nodos_tot = cur.fetchone()[0]
                    cur.execute("SELECT COUNT(*) FROM registro_mensajes WHERE timestamp > datetime('now', '-24 hours')"); msg_hoy = cur.fetchone()[0]
                    conn.close()
                    proteccion = get_proteccion()
                    prot_txt = "🟢 Activa" if proteccion else "🔴 Desactivada"
                    rt_on = sum(1 for rid in ROUTERS_VIGILADOS if interface.nodes.get(rid) and 'lastHeard' in interface.nodes.get(rid) and (ahora - interface.nodes.get(rid)['lastHeard'] < MARGEN_ONLINE))
                    util = interface.nodes.get(MI_NODO_ID, {}).get('deviceMetrics', {}).get('channelUtilization', 0)
                    mqtt_ok = "Conectado" if MQTT_CONNECTED else "Inactivo"
                    ocp_sema = "🟢" if util < 20 else "🟡" if util < 30 else "🔴"
                    mqtt_sema = "🟢" if mqtt_ok == "Conectado" else "🟡"
                    resp = (f"🛰️ STATUS\n\n⏱ Uptime: {up_txt}\n"
                    f"📡 Ocupación: {util:.1f}% {ocp_sema}\n"
                    f"🛡️ Proteccion: {prot_txt}\n"
                    f"👥 Nodos: {nodos_tot} detectados\n"
                    f"📊 Tráfico 24h: {msg_hoy} pkts\n\n"
                    f"📍 Routers: {rt_on}/{len(ROUTERS_VIGILADOS)} 🟢\n"
                    f"🌐 MQTT: {mqtt_ok} {mqtt_sema}")
                    responder(resp)
                elif msg_cmd == "/sota":
                    if len(msg_split) >= 2 and msg_split[1] == "spot":
                        modos_filtro = [m.upper() for m in msg_split[2:]]
                        spots = obtener_spots_sota(15)
                        if not spots:
                            responder("\u274c Error al obtener spots")
                        else:
                            if modos_filtro:
                                spots = [s for s in spots if s["mode"].upper() in modos_filtro]
                            if not spots:
                                txt = "/".join(modos_filtro) if modos_filtro else ""
                                responder(f"\u274c No hay spots{f' en {txt}' if txt else ''}")
                            else:
                                resp = "\U0001f4e1 SOTA"
                                if modos_filtro:
                                    resp += f" ({'/'.join(modos_filtro)})"
                                resp += "\n"
                                for s in spots[:4]:
                                    t = s["timeStamp"][11:16]
                                    resp += f"{t}z {s['activatorCallsign']} {s['summitCode']} {s['frequency']} {s['mode']}\n"
                                responder(resp.strip())
                    elif len(msg_split) < 4:
                        responder("\U0001f3d4 SOTA\nUso: /sota CALL SUMMIT FREQ MODE\nEj: EA7LQK/P EA7/MA-102 14.200 SSB\n\n/sota spot [MODO] para \u00faltimos spots")
                    else:
                        if not es_dm:
                            responder("\u26a0\ufe0f Publicar spot solo por DM")
                        else:
                            activator = msg_split[1].upper()
                            summit_ref = msg_split[2].upper()
                            freq = msg_split[3]
                            mode = msg_split[4].upper() if len(msg_split) > 4 else "SSB"
                            coment = " ".join(msg_split[5:]) if len(msg_split) > 5 else ""
                            debug_log("SOTA radio: calling publicar_spot_sota")
                            resp = publicar_spot_sota(activator, summit_ref, freq, mode, coment)
                            responder(resp)
                elif msg_cmd == "/medusas":
                    prov = msg_split[1].lower() if len(msg_split) >= 2 else "almeria"
                    data = obtener_medusas(prov)
                    if data is None:
                        responder("\u274c Error al obtener datos de medusas")
                    else:
                        responder(formatear_medusas_radio(data))
                elif msg_cmd == "/calima":
                    prov = msg_split[1] if len(msg_split) > 1 else CHANNEL_TO_PROV.get(source_channel, "Almeria").lower()
                    coords = COORDENADAS_PROVINCIAS.get(prov, (36.83, -2.45))
                    responder(formatear_calima(prov, obtener_calima(coords[0], coords[1])).replace("*", "").replace("`", ""))
                elif msg_cmd == "/ia":
                    pregunta = msg_raw.split(" ", 1)[1].strip() if " " in msg_raw else ""
                    if not pregunta:
                        responder("\U0001F916 Uso: /ia <consulta>")
                    elif len(pregunta) > 200:
                        responder("\U0001F916 Consulta demasiado larga (max 200 car).")
                    else:
                        debug_log(f"IA radio {sender_id}: {pregunta}")
                        responder(consultar_ia(pregunta, nodo_id=sender_id))
                elif msg_cmd == "/ping":
                    h_s = packet.get('hopStart')
                    h_l = packet.get('hopLimit')
                    if h_s is not None and h_l is not None and h_s > 0:
                        hops_p = h_s - h_l
                        bar = "".join("🟥" if i < hops_p else "🟩" for i in range(h_s))
                        txt_saltos = f"{bar} {hops_p}/{h_s}"
                    else:
                        txt_saltos = "🐰 ? saltos"
                    via_txt = "MQTT" if via_emoji == "🌐" else "RF"
                    snr = packet.get('rxSnr', 0.0)
                    rssi = packet.get('rxRssi', 0)
                    linea1 = f"📡 PING desde {s_name} {via_emoji}"
                    linea2 = f"🆔 {sender_id}"
                    linea3 = f"{txt_saltos} | 📶 SNR {snr} dB | 📡 RSSI {rssi} dBm"
                    responder(linea1 + chr(10) + linea2 + chr(10) + linea3)
    except Exception as e: logging.error(f"Error Radio: {e}")

# --- TRABAJADOR AEMET (ALERTAS PROACTIVAS) ---
def aemet_worker(iface):
    url_aemet = "https://opendata.aemet.es/opendata/api/avisos_cap/ultimoelaborado/area/esp"
    headers = {'api_key': AEMET_API_KEY}
    session = requests.Session()
    retry_wait = 1800

    while True:
        if AEMET_API_KEY == "TU_API_KEY_AQUI":
            time.sleep(3600)
            continue

        try:
            r = session.get(url_aemet, headers=headers, timeout=30)
            if r.status_code != 200:
                raise Exception(f"HTTP {r.status_code}")

            datos = r.json()
            if datos.get("estado") != 200 or "datos" not in datos:
                raise Exception(f"API denego: {datos.get('descripcion', '?')}")

            tar_url = datos["datos"]
            r_tar = session.get(tar_url, timeout=30)
            if len(r_tar.content) < 1024:
                raise Exception(f"TAR vacio ({len(r_tar.content)} bytes)")
            tar = tarfile.open(fileobj=io.BytesIO(r_tar.content))

            nuevos_avisos = []
            for miembro in tar.getmembers():
                if not miembro.isfile():
                    continue
                f_xml = tar.extractfile(miembro)
                if not f_xml:
                    continue
                xml_text = f_xml.read().decode('utf-8', errors='ignore')

                infos = re.findall(r'<info>(.*?)</info>', xml_text, re.DOTALL)
                for info_block in infos:
                    geocode_match = re.search(r'<geocode>.*?<value>(\d+)</value>.*?</geocode>', info_block, re.DOTALL)
                    if not geocode_match or geocode_match.group(1) not in ZONE_TO_PROV:
                        continue
                    if not re.search(r"<language>es-ES</language>", info_block):
                        continue

                    provincia = ZONE_TO_PROV[geocode_match.group(1)]

                    headline_match = re.search(r'<headline>(.*?)</headline>', info_block)
                    severity_match = re.search(r'<severity>(.*?)</severity>', info_block)

                    if headline_match and severity_match:
                        headline = headline_match.group(1).strip()
                        severity = severity_match.group(1).strip().upper()

                        conn_a = sqlite3.connect(DB_PATH, timeout=10)
                        ca = conn_a.cursor()
                        ca.execute("SELECT 1 FROM alertas_enviadas WHERE headline = ? AND date(fecha) = date('now')", (headline,))
                        if ca.fetchone():
                            conn_a.close()
                            continue
                        if headline in SENT_ALERTAS:
                            conn_a.close()
                            continue
                        ca.execute("INSERT OR REPLACE INTO alertas_enviadas (headline, fecha) VALUES (?, datetime('now'))", (headline,))
                        conn_a.commit()
                        conn_a.close()

                        if severity in ["SEVERE", "EXTREME"]:
                            color = "🟡" if severity == "MODERATE" else "🟠" if severity == "SEVERE" else "🔴"
                            msg_radio = "⚠️ AEMET {}:\n{} {}".format(provincia, color, headline)
                            nuevos_avisos.append((provincia, msg_radio, headline))

            tar.close()
            retry_wait = 1800

            if nuevos_avisos:
                enviados_prov = {}
                for provincia, aviso, headline in nuevos_avisos:
                    enviados_prov[provincia] = enviados_prov.get(provincia, 0) + 1
                    if enviados_prov[provincia] > 1 and time.time() - BOT_START_TIME < 3600:
                        continue
                    ch_index = obtener_channel(iface, provincia)
                    iface.sendText(aviso, destinationId=meshtastic.BROADCAST_ADDR, channelIndex=ch_index, wantAck=False)
                    enviar_telegram(f"📢 *ALERTA AEMET {provincia} ({CHANNEL_NAMES.get(ch_index, 'Ch'+str(ch_index))}):*\n`{aviso}`", MI_CHAT_ID)
                    SENT_ALERTAS.add(headline)
                    time.sleep(5)

        except Exception as e:
            logging.warning(f"AEMET: {e}")
            try:
                if r.status_code == 429:
                    time.sleep(70)
                else:
                    time.sleep(retry_wait)
                    retry_wait = min(retry_wait * 2, 1800)
            except (NameError, AttributeError):
                time.sleep(retry_wait)
                retry_wait = min(retry_wait * 2, 1800)
            continue

        time.sleep(1800)
# --- TRABAJADOR TERREMOTOS (EMSC) ---
def terremotos_worker(iface):
    url_emsc = "https://www.seismicportal.eu/fdsnws/event/1/query"
    
    while True:
        try:
            params = {"format": "json", "lat": 37.0, "lon": -3.8,
                      "maxradius": 3.2, "minmag": MIN_MAGNITUD_TERREMOTO, "limit": 20}
            r = requests.get(url_emsc, params=params, timeout=15)
            if r.status_code == 200:
                datos = r.json()
                for feature in datos.get("features", []):
                    props = feature.get("properties", {})
                    ev_id = feature.get("id")
                    if not ev_id:
                        continue
                    
                    conn = None
                    try:
                        conn = sqlite3.connect(DB_PATH, timeout=10)
                        c = conn.cursor()
                        c.execute("SELECT 1 FROM terremotos WHERE id = ?", (ev_id,))
                        if c.fetchone():
                            continue
                        if ev_id in SENT_TERREMOTOS:
                            continue
                        
                        mag = props.get("mag", "N/A")
                        region = props.get("flynn_region", "Desconocida")
                        time_raw = props.get("time", "")
                        
                        try:
                            utc_dt = datetime.strptime(time_raw[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                            local_dt = utc_dt.astimezone(ZoneInfo("Europe/Madrid"))
                            time_fmt = local_dt.strftime("%d/%m %H:%M")
                        except:
                            time_fmt = time_raw[:16]
                        
                        c.execute("INSERT INTO terremotos (id, magnitud, ubicacion, fecha) VALUES (?, ?, ?, ?)",
                                  (ev_id, mag, region, time_raw))
                        conn.commit()
                        
                        SENT_TERREMOTOS.add(ev_id)
                        
                        if time.time() - BOT_START_TIME < 1800:
                            continue
                        
                        coords = feature.get("geometry", {}).get("coordinates", [])
                        if len(coords) >= 2:
                            eq_lon, eq_lat = coords[0], coords[1]
                        else:
                            eq_lat, eq_lon = 36.83, -2.45
                        
                        localidad, provincia = localidad_cercana(eq_lat, eq_lon)
                        if not provincia:
                            provincia = "Almeria"
                        
                        if localidad and region.upper() == "SPAIN":
                            ubicacion_txt = "{} ({})".format(localidad, provincia)
                        else:
                            ubicacion_txt = region
                        
                        msg_radio = "\U0001f3da TERREMOTO M{}\n\U0001f4cd {}\n\U0001f550 {}".format(mag, ubicacion_txt, time_fmt)

                        ch_index = obtener_channel(iface, provincia)

                        iface.sendText(msg_radio, destinationId=meshtastic.BROADCAST_ADDR, channelIndex=ch_index, wantAck=False)
                        enviar_telegram("\U0001f4e2 *TERREMOTO {} ({}):*\n`{}`".format(provincia, CHANNEL_NAMES.get(ch_index, "Ch{}".format(ch_index)), msg_radio), MI_CHAT_ID)

                        try:
                            nombre_wp = "M{} {}".format(mag, ubicacion_txt[:20])
                            iface.sendWaypoint(
                                name=nombre_wp,
                                description="{}".format(time_fmt),
                                icon=0x1F3DA,
                                expire=int(time.time()) + 172800,
                                latitude=eq_lat,
                                longitude=eq_lon,
                                channelIndex=ch_index,
                                wantAck=False,
                            )
                        except Exception as e:
                            logging.warning("Error enviando waypoint terremoto: {}".format(e))
                        time.sleep(5)
                        
                    except Exception as e:
                        logging.error("Error procesando terremoto {}: {}".format(ev_id, e))
                    finally:
                        if conn: conn.close()
                        
        except Exception as e:
            logging.error("Error en terremotos_worker: {}".format(e))
        
        time.sleep(300) # Chequear cada 5 minutos

# --- TRABAJADOR INCENDIOS FORESTALES (FIRMS/NASA) ---
def incendios_worker(iface):
    MAP_KEY = FIRMS_MAP_KEY
    url = f"https://firms.modaps.eosdis.nasa.gov/api/area/csv/{MAP_KEY}/VIIRS_SNPP_NRT/world/1"
    # FIRMS ya no cubre ninguna provincia del bot: las andaluzas (incl. Jaén) las alerta INFOCA.
    FIRE_BBOXES = {}
    RADIO_AGRUPACION = 0.05
    while True:
        try:
            r = requests.get(url, timeout=30)
            if r.status_code != 200:
                logging.warning(f"INCENDIOS: HTTP {r.status_code}")
                time.sleep(1800)
                continue

            all_fires = []
            reader = csv.DictReader(io.StringIO(r.text))
            for row in reader:
                lat = float(row['latitude'])
                lon = float(row['longitude'])
                conf = row['confidence']
                for prov, bbox in FIRE_BBOXES.items():
                    if (bbox['min_lat'] <= lat <= bbox['max_lat'] and
                        bbox['min_lon'] <= lon <= bbox['max_lon'] and
                        conf == 'h'):
                        row['provincia'] = prov
                        all_fires.append(row)
                        break

            if not all_fires:
                time.sleep(1800)
                continue

            if time.time() - BOT_START_TIME < 3600:
                logging.info("INCENDIOS: saltando primer ciclo (grace period 1h)")
                time.sleep(1800)
                continue

            clusters = []
            used = [False] * len(all_fires)
            for i, f in enumerate(all_fires):
                if used[i]: continue
                cluster = [f]
                used[i] = True
                for j, g in enumerate(all_fires):
                    if used[j]: continue
                    fl = float(f['latitude'])
                    gl = float(g['latitude'])
                    fn = float(f['longitude'])
                    gn = float(g['longitude'])
                    if abs(fl - gl) < RADIO_AGRUPACION and abs(fn - gn) < RADIO_AGRUPACION:
                        cluster.append(g)
                        used[j] = True
                clusters.append(cluster)

            clusters.sort(key=lambda c: max(float(p['frp']) for p in c), reverse=True)

            enviados = 0
            for cluster in clusters:
                if enviados >= 1:
                    break

                lat_avg = sum(float(p['latitude']) for p in cluster) / len(cluster)
                lon_avg = sum(float(p['longitude']) for p in cluster) / len(cluster)
                date = cluster[0]['acq_date']
                max_frp = max(float(p['frp']) for p in cluster)
                has_high = any(p['confidence'] == 'h' for p in cluster)

                localidad, provincia = localidad_cercana(lat_avg, lon_avg)
                if not provincia:
                    provincia = "Jaen"

                fire_id = f"{lat_avg:.2f}_{lon_avg:.2f}_{date}"

                conn = sqlite3.connect(DB_PATH, timeout=10)
                c = conn.cursor()
                c.execute("SELECT 1 FROM incendios_alertas WHERE fire_id = ? AND date(fecha) = date('now')", (fire_id,))
                if c.fetchone():
                    conn.close()
                    continue

                c.execute("INSERT OR REPLACE INTO incendios_alertas (fire_id, fecha) VALUES (?, datetime('now'))", (fire_id,))
                conn.commit()
                conn.close()

                conf_txt = "ALTA" if has_high else "MEDIA"
                zona = localidad if localidad else f"{provincia} provincia"
                emoji = "🔥"
                msg = f"{emoji} INCENDIO {zona}\n⚡ {max_frp:.0f}MW ({conf_txt})\n📍 {lat_avg:.3f},{lon_avg:.3f}\n🌐 https://firms.modaps.eosdis.nasa.gov/map/#d:24hrs;@{lon_avg:.3f},{lat_avg:.3f},10z"

                ch_index = obtener_channel(iface, provincia)

                if enviar_con_limite(iface, msg, ch_index,
                    f"{emoji} *INCENDIO {zona}*\n⚡ {max_frp:.0f}MW · Confianza {conf_txt}\n`📍 {lat_avg:.3f},{lon_avg:.3f}`\n[Ver en NASA FIRMS](https://firms.modaps.eosdis.nasa.gov/map/#d:24hrs;@{lon_avg:.3f},{lat_avg:.3f},10z)", MI_CHAT_ID):
                    enviados += 1
                    try:
                        iface.sendWaypoint(
                            name="INCENDIO {}".format(zona[:20]),
                            description="{:.0f}MW · {}".format(max_frp, conf_txt),
                            icon=0x1F525,
                            expire=int(time.time()) + 43200,
                            latitude=lat_avg,
                            longitude=lon_avg,
                            channelIndex=ch_index,
                            wantAck=False,
                        )
                    except Exception as e:
                        logging.warning("Error enviando waypoint incendio: {}".format(e))
                    time.sleep(3)

        except Exception as e:
            logging.warning(f"INCENDIOS: {e}")

        time.sleep(10800)

# --- TRABAJADOR INCENDIOS INFOCA (ANDALUCÍA, FUENTE OFICIAL) ---
INFOCA_FS_URL = "https://utility.arcgis.com/usrsvcs/servers/d6d1c0079ddd4c7f8876d58e13fcf1ac/rest/services/INFOCA/AN_INCIDENTES_PRO/FeatureServer/2"
INFOCA_VISOR_URL = "https://www.juntadeandalucia.es/organismos/ema/areas/incendios-forestales/situacion/incendios-activos.html"
INFOCA_PROV_MAP = {
    "ALMERÍA": "Almeria", "ALMERIA": "Almeria",
    "GRANADA": "Granada",
    "JAÉN": "Jaen", "JAEN": "Jaen",
    "MÁLAGA": "Malaga", "MALAGA": "Malaga",
    "SEVILLA": "Sevilla",
}
INFOCA_EMOJI = {"ACTIVO": "🔥", "CONTROLADO": "⛑️", "MOVILIZADO": "🚨", "EN EXTINCION": "🚨"}

def infoca_worker(iface):
    while True:
        try:
            params = {
                "where": "ESTADO NOT IN ('EXTINGUIDO')",
                "outFields": "OID_ENTERO,TERMINO_MUNICIPAL,PROVINCIA,TIPO_INCIDENTE,ESTADO,FECHA,HORA,MEDIOS_AEREOS,BRICAS,VEHICULOS,TECNICOS",
                "outSR": "4326",
                "resultRecordCount": "100",
                "f": "json",
            }
            r = requests.get(INFOCA_FS_URL + "/query", params=params, timeout=30)
            if r.status_code != 200:
                logging.warning(f"INFOCA: HTTP {r.status_code}")
                time.sleep(1800)
                continue
            data = r.json()
            if "error" in data:
                logging.warning(f"INFOCA: error API {data['error']}")
                time.sleep(1800)
                continue

            if os.environ.get("FORCE_INFOCA") != "1" and time.time() - BOT_START_TIME < 3600:
                logging.info("INFOCA: saltando primer ciclo (grace period 1h)")
                time.sleep(1800)
                continue

            feats = sorted(data.get("features") or [], key=lambda f: (f.get("attributes") or {}).get("FECHA") or 0, reverse=True)
            enviados = 0
            for feat in feats:
                if enviados >= 3:
                    break
                a = feat.get("attributes") or {}
                prov_infoca = str(a.get("PROVINCIA") or "").upper()
                prov_bot = INFOCA_PROV_MAP.get(prov_infoca)
                if not prov_bot:
                    continue
                tipo = str(a.get("TIPO_INCIDENTE") or "")
                if "INCENDIO" not in tipo.upper():
                    continue
                oid = a.get("OID_ENTERO")
                if oid is None:
                    continue
                geo = feat.get("geometry") or {}
                lon, lat = geo.get("x"), geo.get("y")
                if lon is None or lat is None:
                    continue

                estado = str(a.get("ESTADO") or "?").strip()
                municipio = str(a.get("TERMINO_MUNICIPAL") or "").strip()
                fecha_txt = "?"
                if a.get("FECHA"):
                    fecha_txt = datetime.fromtimestamp(a["FECHA"] / 1000, timezone.utc).strftime("%Y-%m-%d")
                    hora_txt = str(a.get("HORA") or "").strip()
                    if hora_txt:
                        fecha_txt += " " + hora_txt
                medios = []
                for campo, singular, plural in (("MEDIOS_AEREOS", "aéreo", "aéreos"), ("BRICAS", "brica", "bricas"), ("VEHICULOS", "vehículo", "vehículos"), ("TECNICOS", "técnico", "técnicos")):
                    try:
                        v = int(a.get(campo) or 0)
                    except (TypeError, ValueError):
                        v = 0
                    if v > 0:
                        medios.append(f"{v} {singular if v == 1 else plural}")
                medios_txt = " · ".join(medios) if medios else "sin medios desplegados"

                fire_id = f"INFOCA-{oid}"

                conn = sqlite3.connect(DB_PATH, timeout=10)
                c = conn.cursor()
                c.execute("SELECT 1 FROM incendios_alertas WHERE fire_id = ? AND date(fecha) = date('now')", (fire_id,))
                if c.fetchone():
                    conn.close()
                    continue
                c.execute("INSERT OR REPLACE INTO incendios_alertas (fire_id, fecha) VALUES (?, datetime('now'))", (fire_id,))
                conn.commit()
                conn.close()

                emoji = INFOCA_EMOJI.get(estado.upper(), "🔥")
                zona = municipio if municipio else prov_bot
                msg = f"{emoji} {estado}: INCENDIO {zona} (INFOCA)\n🛠 {medios_txt}\n🗓 {fecha_txt}\n📍 {lat:.4f},{lon:.4f}"

                ch_index = obtener_channel(iface, prov_bot)

                if enviar_con_limite(iface, msg, ch_index,
                    f"{emoji} *{estado}: INCENDIO {zona} ({prov_bot})* — INFOCA\n🛠 {medios_txt}\n🗓 {fecha_txt}\n`📍 {lat:.4f},{lon:.4f}`\n[Visor INFOCA]({INFOCA_VISOR_URL})", MI_CHAT_ID):
                    enviados += 1
                    try:
                        iface.sendWaypoint(
                            name="INCENDIO {}".format(zona[:20]),
                            description="{} · {}".format(estado, medios_txt),
                            icon=0x1F525,
                            expire=int(time.time()) + 43200,
                            latitude=lat,
                            longitude=lon,
                            channelIndex=ch_index,
                            wantAck=False,
                        )
                    except Exception as e:
                        logging.warning("Error enviando waypoint infoca: {}".format(e))
                    time.sleep(3)

        except Exception as e:
            logging.warning(f"INFOCA: {e}")

        time.sleep(1800)

# --- TRABAJADOR CALIMA (OPEN-METEO AIR QUALITY, ALERTA PROACTIVA) ---
def calima_alertado_hoy(prov):
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        c = conn.cursor()
        c.execute("SELECT 1 FROM calima_alertas WHERE provincia = ? AND date(fecha) = date('now')", (prov,))
        return bool(c.fetchone())
    except Exception as e:
        logging.error(f"CALIMA dedup: {e}")
        return False
    finally:
        if conn: conn.close()

def marcar_calima(prov, val):
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO calima_alertas (provincia, valor, fecha) VALUES (?, ?, datetime('now'))", (prov, val))
        conn.commit()
    except Exception as e:
        logging.error(f"CALIMA marcar: {e}")
    finally:
        if conn: conn.close()

def calima_worker(iface):
    while True:
        try:
            for prov in CALIMA_PROVINCIAS:
                coords = COORDENADAS_PROVINCIAS.get(prov.lower())
                if not coords:
                    continue
                cur = obtener_calima(coords[0], coords[1])
                pm10 = cur.get("pm10") if cur else None
                if pm10 is None or pm10 < CALIMA_UMBRAL_PM10:
                    continue
                if calima_alertado_hoy(prov):
                    continue
                dust = cur.get("dust")
                msg_radio = "🌬️ CALIMA {}\nPM10: {} µg/m³ (≥{})".format(prov.upper(), round(pm10), int(CALIMA_UMBRAL_PM10))
                if dust is not None:
                    msg_radio += "\nPolvo sahariano: {} µg/m³".format(round(dust))
                ch_index = obtener_channel(iface, prov)
                try:
                    iface.sendText(msg_radio, destinationId=meshtastic.BROADCAST_ADDR, channelIndex=ch_index, wantAck=False)
                except Exception as e:
                    logging.warning("CALIMA error radio {}: {}".format(prov, e))
                tg = f"🌬️ *CALIMA EN {prov.upper()}*\n• PM10: `{round(pm10)}` µg/m³ (umbral {int(CALIMA_UMBRAL_PM10)})"
                if dust is not None:
                    tg += f"\n• Polvo sahariano: `{round(dust)}` µg/m³"
                enviar_telegram(tg, MI_CHAT_ID)
                marcar_calima(prov, pm10)
                time.sleep(20)
        except Exception as e:
            logging.warning(f"CALIMA: {e}")
        time.sleep(3600)

# --- RESUMEN SEMANAL (DOMINGO 21:00, PANEL OPCION A) ---
def _tomar_snapshot_metricas(iface):
    try:
        ahora = int(time.time())
        util = iface.nodes.get(MI_NODO_ID, {}).get('deviceMetrics', {}).get('channelUtilization')
        conn = sqlite3.connect(DB_PATH, timeout=10)
        c = conn.cursor()
        if util is not None:
            c.execute("INSERT OR REPLACE INTO metricas_hora (ts, ocupacion) VALUES (?, ?)", (ahora, float(util)))
        for nid, alias in ROUTERS_VIGILADOS.items():
            n = iface.nodes.get(nid)
            online = 1 if (n and 'lastHeard' in n and (ahora - n['lastHeard']) < MARGEN_ONLINE) else 0
            c.execute("INSERT INTO routers_snapshot (ts, alias, online) VALUES (?, ?, ?)", (ahora, alias, online))
        limite = ahora - 30 * 86400
        c.execute("DELETE FROM routers_snapshot WHERE ts < ?", (limite,))
        c.execute("DELETE FROM metricas_hora WHERE ts < ?", (limite,))
        conn.commit()
        conn.close()
    except Exception as e:
        logging.warning(f"SNAPSHOT: {e}")

def _proximo_domingo_21():
    tz = ZoneInfo("Europe/Madrid")
    ahora = datetime.now(tz)
    candidata = ahora.replace(hour=21, minute=0, second=0, microsecond=0) + timedelta(days=(6 - ahora.weekday()) % 7)
    if candidata <= ahora:
        candidata += timedelta(days=7)
    return candidata

def construir_resumen_semanal(iface):
    tz = ZoneInfo("Europe/Madrid")
    hoy = datetime.now(tz)
    rango = "{}–{}".format((hoy - timedelta(days=6)).strftime("%d/%m"), hoy.strftime("%d/%m"))
    semana_ts = int(time.time()) - 7 * 86400
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    def q(sql, args=()):
        c.execute(sql, args)
        return c.fetchone()[0]
    trafico = q("SELECT COUNT(*) FROM registro_mensajes WHERE timestamp > datetime('now','-7 days')")
    previo = q("SELECT COUNT(*) FROM registro_mensajes WHERE timestamp > datetime('now','-14 days') AND timestamp <= datetime('now','-7 days')")
    delta = ""
    if previo:
        pct = int(round((trafico - previo) * 100.0 / previo))
        delta = " ({}{}% vs sem. ant.)".format("+" if pct >= 0 else "", pct)
    activos = q("SELECT COUNT(DISTINCT id) FROM registro_mensajes WHERE timestamp > datetime('now','-7 days')")
    nuevos = q("SELECT COUNT(*) FROM nodos WHERE creado IS NOT NULL AND date(creado) >= date('now','-6 days')")
    aemet_n = q("SELECT COUNT(*) FROM alertas_enviadas WHERE date(fecha) >= date('now','-6 days')")
    inc_infoca = q("SELECT COUNT(*) FROM incendios_alertas WHERE fire_id LIKE 'INFOCA%' AND date(fecha) >= date('now','-6 days')")
    inc_firms = q("SELECT COUNT(*) FROM incendios_alertas WHERE fire_id NOT LIKE 'INFOCA%' AND date(fecha) >= date('now','-6 days')")
    sismos = q("SELECT COUNT(*) FROM terremotos WHERE date(fecha) >= date('now','-6 days')")
    calimas = q("SELECT COUNT(*) FROM calima_alertas WHERE date(fecha) >= date('now','-6 days')")
    hops_mal = q("SELECT COUNT(*) FROM nodos WHERE estado_hops_mal = 1")
    pos_mal = q("SELECT COUNT(*) FROM posiciones WHERE rowid IN (SELECT MAX(rowid) FROM posiciones GROUP BY id) AND estado_mal = 1")
    util_media = q("SELECT AVG(ocupacion) FROM metricas_hora WHERE ts > ?", (semana_ts,))
    top_rows = c.execute("SELECT id, COUNT(*) AS ct FROM registro_mensajes WHERE timestamp > datetime('now','-7 days') GROUP BY id ORDER BY ct DESC LIMIT 3").fetchall()
    caidos_rows = c.execute("SELECT alias, COUNT(*) FROM routers_snapshot WHERE online = 0 AND ts > ? GROUP BY alias ORDER BY 2 DESC", (semana_ts,)).fetchall()
    conn.close()

    lineas = ["📊 *RESUMEN SEMANAL {}*".format(rango), "", "🌐 *Red*"]
    lineas.append("• Tráfico: {} pkts{}".format(trafico, delta))
    lineas.append("• Nodos activos: {} | Nuevos: {}".format(activos, nuevos))
    if util_media is not None:
        lineas.append("• Ocupación media: {:.1f}%".format(util_media))
    lineas.append("")
    lineas.append("🚨 *Alertas de la semana*")
    total_inc = inc_infoca + inc_firms
    lineas.append("• AEMET: {} | Incendios: {} | Sismos: {} | Calima: {}".format(aemet_n, total_inc, sismos, calimas))
    if caidos_rows:
        det = ", ".join("{} (~{}h)".format(alias, n) for alias, n in caidos_rows)
        lineas.append("• Routers offline: {}".format(det))
    lineas.append("")
    lineas.append("🏆 *Top actividad*")
    if top_rows:
        medallas = ["🥇", "🥈", "🥉"]
        for i, (idn, ct) in enumerate(top_rows[:3]):
            ln = iface.nodes.get(idn, {}).get('user', {}).get('longName') or idn
            lineas.append("{} {}: {} pqts".format(medallas[i], ln, ct))
    else:
        lineas.append("• Sin tráfico registrado")
    lineas.append("")
    lineas.append("⚠️ *Pendientes*")
    pend = []
    if hops_mal: pend.append("Saltos altos: {}".format(hops_mal))
    if pos_mal: pend.append("Telemetría mala: {}".format(pos_mal))
    lineas.append("• " + (" | ".join(pend) if pend else "✅ Ninguno"))
    return "\n".join(lineas)

def resumen_semanal_worker(iface):
    ultima_snap = 0
    while True:
        try:
            ahora = time.time()
            if ahora - ultima_snap >= 3600:
                _tomar_snapshot_metricas(iface)
                ultima_snap = ahora
            espera = (_proximo_domingo_21() - datetime.now(ZoneInfo("Europe/Madrid"))).total_seconds()
            if espera <= 60:
                panel = construir_resumen_semanal(iface)
                enviar_telegram(panel, MI_CHAT_ID)
                time.sleep(3600)
            else:
                time.sleep(min(espera - 30, 600))
        except Exception as e:
            logging.warning(f"RESUMEN: {e}")
            time.sleep(600)

# --- RECONCILIACION DE NOMBRES DE NODOS DESDE POTATO MESH ---
POTATO_NODES_URL = POTATO_API_URL + "/api/nodes?limit=1000"

def reconciliar_nombres_worker(iface):
    ultimo_purga_dia = None
    while True:
        try:
            r = requests.get(POTATO_NODES_URL, headers={"Authorization": "Bearer " + POTATO_API_TOKEN}, timeout=20)
            if r.status_code == 200:
                nodos_potato = r.json()
                ahora_epoch = int(time.time())
                conn = sqlite3.connect(DB_PATH, timeout=10)
                c = conn.cursor()
                actuales = {fila[0]: fila[1] for fila in c.execute("SELECT id, nombre FROM nodos")}
                placeholders = 0
                actualizados = 0
                for n in nodos_potato:
                    nid = n.get("node_id")
                    ln = str(n.get("long_name") or "").strip()
                    sn = str(n.get("short_name") or "").strip()
                    rl = str(n.get("role") or "").strip() or None
                    lh = n.get("last_heard") or 0
                    if not nid or not ln or ln.startswith("!"):
                        continue
                    previo = actuales.get(nid)
                    if previo is None or previo.startswith("!"):
                        c.execute("UPDATE nodos SET nombre=?, short_name=?, rol=? WHERE id=?", (ln, sn, rl or 'DESCONOCIDO', nid))
                        placeholders += 1
                    elif ln != previo and (ahora_epoch - lh) < 7 * 86400:
                        c.execute("UPDATE nodos SET nombre=?, short_name=? WHERE id=?", (ln, sn, nid))
                        actualizados += 1
                borrados = 0
                hoy = time.strftime("%Y-%m-%d")
                if hoy != ultimo_purga_dia:
                    activos = {fila[0] for fila in c.execute("SELECT DISTINCT id FROM registro_mensajes WHERE timestamp > datetime('now','-60 days')")}
                    fantasmas = [fila[0] for fila in c.execute("SELECT id FROM nodos WHERE nombre LIKE '!%'") if fila[0] not in activos]
                    if fantasmas:
                        c.executemany("DELETE FROM nodos WHERE id=?", [(f,) for f in fantasmas])
                        borrados = len(fantasmas)
                    ultimo_purga_dia = hoy
                conn.commit()
                conn.close()
                if placeholders + actualizados + borrados > 0:
                    enviar_telegram(f"🔄 *Nombres de nodos reconciliados*\n• Placeholders reparados: {placeholders}\n• Nombres actualizados: {actualizados}" + (f"\n• Fantasmas purgados: {borrados}" if borrados else ""), MI_CHAT_ID)
            else:
                logging.warning(f"RECONCILIA: HTTP {r.status_code}")
        except Exception as e:
            logging.warning(f"RECONCILIA: {e}")
        time.sleep(21600)

ROLES_MESH = {0:"CLIENT", 1:"CLIENT_MUTE", 2:"ROUTER", 3:"ROUTER_CLIENT", 4:"REPEATER", 5:"TRACKER", 6:"SENSOR", 7:"TAK", 8:"CLIENT_HIDDEN", 9:"LOST_AND_FOUND", 10:"TAK_TRACKER", 11:"ROUTER_LATE", 12:"CLIENT_BASE"}

def _nombre_hw(num):
    if num is None: return "?"
    try:
        return meshtastic.mesh_pb2.HardwareModel.Name(num)
    except Exception:
        comunes = {9:"RAK4631", 39:"NRF52840_PCA10059", 63:"NRF52 PROMICRO DIY", 117:"RAK3401", 122:"TBEAM_1_WATT"}
        return comunes.get(num, str(num))

def formatear_uptime(seg):
    seg = int(seg or 0)
    d, r = divmod(seg, 86400); h, r = divmod(r, 3600); m = r // 60
    if d: return f"{d}d {h}h"
    if h: return f"{h}h {m}m"
    return f"{m}m"

def resolver_nodo(iface, arg):
    """Resuelve alias/nombre/ID hacia node_id."""
    a = str(arg).strip().lower()
    if not a: return None
    for d in (ROUTERS_VIGILADOS, NODOS_INFO2):
        for nid, alias in d.items():
            alias_base = alias.split(" (")[0].strip().lower()
            if a == alias.strip().lower() or a == alias_base or a == nid.lower() or a == nid.lstrip("!"):
                return nid
    a_id = a if a.startswith("!") else "!" + a
    for nid, n in (iface.nodes or {}).items():
        if str(nid).lower() == a_id.lower(): return nid
        if isinstance(n, dict):
            user = n.get("user") or {}
            sn = (user.get("shortName") or "").strip().lower()
            ln = (user.get("longName") or "").strip().lower()
            if a == sn or (len(a) >= 3 and a in ln) or str(nid).lower().endswith(a):
                return nid
    return None

def formatear_detalle_nodo(iface, nid, ahora):
    n = (iface.nodes or {}).get(nid) or {}
    if not isinstance(n, dict): n = {}
    user = n.get("user") or {}
    short = user.get("shortName") or ""
    long = user.get("longName") or ""
    alias_oficial = None
    for d in (ROUTERS_VIGILADOS, NODOS_INFO2):
        if nid in d: alias_oficial = d[nid]
    titulo = (alias_oficial.split(" (")[0] if alias_oficial else None) or short or nid
    if long and long.lower() not in (titulo.lower(), short.lower()):
        titulo = f"{titulo} — {long}"
    lh = n.get("lastHeard")
    if lh:
        ant = ahora - lh
        estado = "🟢" if ant < MARGEN_ONLINE else "🔴"
        try: hora = datetime.fromtimestamp(lh, ZoneInfo("Europe/Madrid")).strftime("%H:%M %d/%m")
        except: hora = ""
        res = f"📡 *{titulo}*\n🆔 `{nid}` | {estado} visto hace {formatear_tiempo_corto(ant)} ({hora})\n"
    else:
        res = f"📡 *{titulo}*\n🆔 `{nid}` | ⚪ sin datos en esta sesión\n"
    link = "🌐 MQTT" if n.get("viaMqtt") else "📻 LoRa"
    extra = []
    if n.get("snr") is not None: extra.append(f"SNR {n['snr']:.1f} dB")
    if n.get("hopsAway") is not None: extra.append(f"{n['hopsAway']} saltos")
    if n.get("channel") is not None: extra.append(f"canal {n['channel']}")
    if extra: res += f"{link} | " + " · ".join(extra) + "\n"
    dm = n.get("deviceMetrics") or {}
    bat = dm.get("batteryLevel"); volt = dm.get("voltage")
    up = dm.get("uptimeSeconds"); cu = dm.get("channelUtilization")
    if bat is not None or volt is not None or cu is not None:
        linea = "⚡ "
        if bat is not None:
            linea += f"🔋 {bat}%"
            if volt is not None: linea += f" ({volt:.2f}V)"
        elif volt is not None: linea += f"{volt:.2f}V"
        if cu is not None: linea += f" | 📊 chUtil {cu:.1f}%"
        if up: linea += f" | up {formatear_uptime(up)}"
        res += linea + "\n"
    pos = n.get("position") or {}
    lat = pos.get("latitude"); lon = pos.get("longitude")
    if lat and lon and (abs(lat) + abs(lon)) > 0:
        acc = pos.get("gpsAccuracy"); alt = pos.get("altitude")
        res += f"📍 {lat:.4f}, {lon:.4f}"
        if alt: res += f" | {alt} m"
        if acc: res += f" (≒{acc} m)"
        res += "\n"
        extra_p = []
        if pos.get("satsInView"): extra_p.append(f"🛰️ {pos['satsInView']} sat")
        ft = pos.get("fixType")
        fixmap = {0:"no fix", 2:"fix 2D", 3:"fix 3D"}
        if ft is not None: extra_p.append(fixmap.get(ft, f"fix {ft}"))
        if pos.get("PDOP") is not None: extra_p.append(f"PDOP {pos['PDOP']}")
        if pos.get("groundSpeed") is not None:
            extra_p.append(f"vel {pos['groundSpeed']}km/h {grados_a_flecha(pos.get('groundTrack'))}")
        if extra_p: res += "  " + " · ".join(extra_p) + "\n"
        res += f"🔗 https://www.google.com/maps?q={lat:.5f},{lon:.5f}\n"
    ident = []
    if user.get("role") is not None: ident.append(f"rol {ROLES_MESH.get(user['role'], str(user['role']))}")
    if user.get("hwModel") is not None: ident.append(f"HW {_nombre_hw(user['hwModel'])}")
    if ident: res += "📊 " + " · ".join(ident) + "\n"
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        c = conn.cursor()
        c.execute("SELECT mensajes FROM trafico WHERE id=?", (nid,))
        r = c.fetchone()
        msgs = r[0] if r else 0
        c.execute("SELECT fecha, hops, rol FROM nodos WHERE id=?", (nid,))
        r2 = c.fetchone()
        conn.close()
        hist = []
        if lh:
            if r2 and r2[0]: hist.append(f"1ª vez: {r2[0]}")
        else:
            if r2 and r2[0]: hist.append(f"📅 Último visto: {r2[0]}")
        if r2 and r2[1] is not None: hist.append(f"{r2[1]} saltos")
        if msgs: hist.append(f"{msgs} msgs")
        if hist: res += "📜 " + " · ".join(hist) + "\n"
    except Exception as e:
        logging.error(f"Detalle nodo BD {nid}: {e}")
    return res

# --- TRABAJADOR TELEGRAM ---
def telegram_worker(iface):
    last_id = 0
    while True:
        try:
            r = requests.get(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getUpdates", params={"offset": last_id + 1}, timeout=10).json()
            for u in r.get("result", []):
                last_id = u["update_id"]
                msg = u.get("message", {})
                cid = str(msg.get("chat", {}).get("id", ""))
                tid = msg.get("message_thread_id")
                if cid in CHATS_PERMITIDOS:
                    text = msg.get("text", "").lower()
                    partes = text.split(" ")
                    cmd = partes[0]
                    
                    if cmd == "/help":
                        ayuda = ("🤖 *BOT EA7 - COMANDOS*\n\n📡 *RED MESHTASTIC*\n/info → Estado de ROUTERS\n/info2 → Estado de nodos importantes\n/posicion → Nodos con telemetría mala\n/trafico → Ranking histórico de tráfico\n/top → Top 3 actividad últimas 6h\n/bd → Nodos con exceso de saltos\n/trace !id → Traceroute RF (solo admin)\n/status → Salud general del bot\n\n🌤️ *CLIMA Y VIENTO*\n/tiempo [prov] → Temperatura y cielo\n/viento [prov] → Rachas hoy y mañana\n/prevision [prov] → Pronóstico 3 días\n/calima [prov] → Polvo sahariano (PM10)\n/solar → Clima espacial (Kp, SFI)\n\n⛽ *OTROS*\n/gasolina [prov] → Precios carburantes\n/ra [indicativo] → Datos HamQTH\n/ia [consulta] → Pregunta a la IA\n/mqtt → Configuración MQTT\n/sota → Publicar spot SOTA\n/medusas → Datos de medusas\n/ping → Latencia y SNR\n/delete → Resetear BD\n\n🛡️ *PROTECCIÓN*\n/protect on|off → Activar/desactivar protección de nodos")
                        enviar_telegram(ayuda, cid, thread_id=tid)
                    elif cmd == "/info":
                        if len(partes) > 1:
                            nid = resolver_nodo(iface, partes[1])
                            if nid:
                                enviar_telegram(formatear_detalle_nodo(iface, nid, time.time()), cid, thread_id=tid)
                            else:
                                enviar_telegram(f"No encontré el nodo *{partes[1]}* en la red. Usa un alias (AL02), nombre o parte del ID.", cid, thread_id=tid)
                        else:
                            ahora = time.time(); res = "🏗️ *ESTADO RED*\n\n"
                            for nid, alias in ROUTERS_VIGILADOS.items():
                                n = iface.nodes.get(nid)
                                if n and 'lastHeard' in n:
                                    ant = ahora - n['lastHeard']
                                    metrics = n.get('deviceMetrics', {})
                                    res += f"{'🟢' if ant < MARGEN_ONLINE else '🔴'} *{alias}*\n└─ Visto: {formatear_tiempo_corto(ant)} | 🔋 {metrics.get('batteryLevel')}% | 📊 {metrics.get('channelUtilization', 0):.1f}%\n"
                            enviar_telegram(res, cid, thread_id=tid)
                    elif cmd == "/info2":
                        ahora = time.time(); res = "🏗️ *ESTADO RED (INFO 2)*\n\n"
                        for nid, alias in NODOS_INFO2.items():
                            n = iface.nodes.get(nid)
                            if n and 'lastHeard' in n:
                                ant = ahora - n['lastHeard']
                                metrics = n.get('deviceMetrics', {})
                                res += f"{'🟢' if ant < MARGEN_ONLINE else '🔴'} *{alias}*\n└─ Visto: {formatear_tiempo_corto(ant)} | 🔋 {metrics.get('batteryLevel')}% | 📊 {metrics.get('channelUtilization', 0):.1f}%\n"
                            else: res += f"⚪ *{alias}*\n└─ Sin datos (Fuera de alcance)\n"
                        enviar_telegram(res, cid, thread_id=tid)
                    elif cmd == "/tiempo":
                        prov = partes[1] if len(partes) > 1 else "almeria"
                        coords = COORDENADAS_PROVINCIAS.get(prov, (36.83, -2.45))
                        data = obtener_datos_clima(coords[0], coords[1])
                        if data:
                            c = data['current']; f = grados_a_flecha(c['wind_direction_10m'])
                            enviar_telegram(f"🌤️ *{prov.upper()}*\n{interpretar_wmo(c['weather_code'])}\n🌡️ {c['temperature_2m']}°C | {f} {c['wind_speed_10m']}km/h", cid, thread_id=tid)
                    elif cmd == "/viento":
                        prov = partes[1] if len(partes) > 1 else "almeria"
                        coords = COORDENADAS_PROVINCIAS.get(prov, (36.83, -2.45))
                        data = obtener_datos_clima(coords[0], coords[1])
                        if data:
                            d = data['daily']; f_h = grados_a_flecha(d['wind_direction_10m_dominant'][0]); f_m = grados_a_flecha(d['wind_direction_10m_dominant'][1])
                            enviar_telegram(f"🚩 *RACHAS {prov.upper()}*\nHoy: {f_h} {d['wind_gusts_10m_max'][0]}km/h\nMañ: {f_m} {d['wind_gusts_10m_max'][1]}km/h", cid, thread_id=tid)
                    elif cmd == "/prevision":
                        prov = partes[1] if len(partes) > 1 else "almeria"
                        coords = COORDENADAS_PROVINCIAS.get(prov, (36.83, -2.45))
                        enviar_telegram(obtener_prevision_3_dias(coords[0], coords[1]), cid, thread_id=tid)
                    elif cmd == "/solar": enviar_telegram(obtener_clima_espacial(), cid, thread_id=tid)
                    elif cmd == "/gasolina":
                        prov = partes[1] if len(partes) > 1 else "almeria"
                        enviar_telegram(obtener_precios_gasolina(prov, modo_radio=False), cid, thread_id=tid)
                    elif cmd == "/ra":
                        indi = partes[1] if len(partes) > 1 else ""; 
                        if indi: enviar_telegram(obtener_datos_hamqth(indi, modo_radio=False), cid, thread_id=tid)
                    elif cmd == "/mqtt":
                        mqtt_txt = (f"🌐 *MQTT CONFIGURACIÓN*\n\n• *Dirección:* `{MQTT_SERVER}`\n• *Username:* `{MQTT_USER}`\n• *Password:* `{MQTT_PASS}`\n• *Topic solo Andalucía:* `{MQTT_TOPIC}`\n• *Topic Andalucía y Portugal:* `msh`")
                        enviar_telegram(mqtt_txt, cid, thread_id=tid)
                    elif cmd == "/posicion":
                        conn = None
                        try:
                            conn = sqlite3.connect(DB_PATH, timeout=10); c = conn.cursor()
                            c.execute('''SELECT id, intervalo_seg FROM posiciones WHERE rowid IN (SELECT MAX(rowid) FROM posiciones WHERE intervalo_seg > 0 GROUP BY id) AND intervalo_seg <= 1200 ORDER BY intervalo_seg ASC''')
                            rows = c.fetchall()
                            if not rows: enviar_telegram("✅ Telemetría OK.", cid, thread_id=tid)
                            else:
                                resp = "⚠️ *NODOS MAL CONFIGURADOS*\n\n"
                                for nid, seg in rows:
                                    s_name = iface.nodes.get(nid, {}).get('user', {}).get('shortName', 'N/A')
                                    resp += f"❌ *{s_name}* (`{nid}`): `{seg // 60} min`\n"
                                enviar_telegram(resp, cid, thread_id=tid)
                        except: pass
                        finally:
                            if conn: conn.close()
                    elif cmd == "/trafico":
                        conn = None
                        try:
                            conn = sqlite3.connect(DB_PATH, timeout=10); c = conn.cursor()
                            c.execute("SELECT SUM(mensajes) FROM trafico"); total_red = c.fetchone()[0] or 0
                            c.execute('''SELECT t.id, t.mensajes, n.nombre FROM trafico t LEFT JOIN nodos n ON t.id = n.id ORDER BY t.mensajes DESC LIMIT 5''')
                            rows = c.fetchall()
                            if rows:
                                resp = "📊 *HISTÓRICO*\n\n"
                                for id_nodo, total, n_db in rows:
                                    l_name = iface.nodes.get(id_nodo, {}).get('user', {}).get('longName') or n_db or id_nodo
                                    resp += f"🟢 *{l_name}*: **{total} pqts** ({int((total/total_red)*100)}%)\n"
                                enviar_telegram(resp, cid, thread_id=tid)
                        except: pass
                        finally:
                            if conn: conn.close()
                    elif cmd == "/top":
                        conn = None
                        try:
                            conn = sqlite3.connect(DB_PATH, timeout=10); c = conn.cursor()
                            c.execute('''SELECT r.id, COUNT(r.id) as cuenta, n.nombre FROM registro_mensajes r LEFT JOIN nodos n ON r.id = n.id WHERE r.timestamp > datetime('now', '-6 hours') GROUP BY r.id ORDER BY cuenta DESC LIMIT 3''')
                            rows = c.fetchall()
                            if rows:
                                resp = "🔥 *TOP 3 ACTIVIDAD (6H)*\n\n"
                                medallas = ["🥇", "🥈", "🥉"]
                                for i, (idn, tot, ndb) in enumerate(rows):
                                    ln = iface.nodes.get(idn, {}).get('user', {}).get('longName') or ndb or idn
                                    resp += f"{medallas[i]} *{ln}*: `{tot}` pqts\n"
                                enviar_telegram(resp, cid, thread_id=tid)
                        except: pass
                        finally:
                            if conn: conn.close()
                    elif cmd == "/bd":
                        conn = None
                        try:
                            conn = sqlite3.connect(DB_PATH, timeout=10); c = conn.cursor()
                            c.execute("SELECT id, nombre, hops, fecha FROM nodos WHERE hops >= 6 ORDER BY fecha DESC LIMIT 15")
                            rows = c.fetchall()
                            if rows:
                                resp = "🗄️ *REGISTRO DE SALTOS (6-7)*\n\n"
                                for idn, ndb, hp, fch in rows:
                                    ln = iface.nodes.get(idn, {}).get('user', {}).get('longName') or ndb or idn
                                    resp += f"• *{ln}* (`{idn}`)\n└ {'🐰' if hp >= 6 else '✅'} `{hp}` | {fch}\n"
                                enviar_telegram(resp, cid, thread_id=tid)
                        except: pass
                        finally:
                            if conn: conn.close()
                    elif cmd == "/protect" and cid == MI_CHAT_ID:
                        accion = partes[1] if len(partes) > 1 else ""
                        if accion == "on":
                            set_proteccion(1)
                            enviar_telegram("🛡️ Protección activada.", cid, thread_id=tid)
                        elif accion == "off":
                            set_proteccion(0)
                            enviar_telegram("🛡️ Protección desactivada. Los nodos no recibirán avisos ni se marcarán como mal configurados.", cid, thread_id=tid)
                        else:
                            estado = "🟢 ACTIVA" if get_proteccion() else "🔴 DESACTIVADA"
                            enviar_telegram(f"🛡️ *PROTECCIÓN*\n\nEstado: {estado}\n\nUsa:\n`/protect on` → Activar\n`/protect off` → Desactivar", cid, thread_id=tid)
                    elif cmd == "/status":
                        ahora = time.time()
                        with open('/proc/uptime') as f: up_secs = int(float(f.read().split()[0]))
                        up_txt = f"{up_secs // 86400}d {(up_secs % 86400) // 3600}h {(up_secs % 3600) // 60}m"
                        mi_nodo = iface.nodes.get(MI_NODO_ID, {}); util = mi_nodo.get('deviceMetrics', {}).get('channelUtilization', 0)
                        conn = sqlite3.connect(DB_PATH); cur = conn.cursor()
                        cur.execute("SELECT COUNT(*) FROM nodos"); nodos_tot = cur.fetchone()[0]
                        cur.execute("SELECT COUNT(*) FROM registro_mensajes WHERE timestamp > datetime('now', '-24 hours')"); msg_hoy = cur.fetchone()[0]
                        cur.execute("SELECT COUNT(*) FROM nodos WHERE estado_hops_mal = 1"); hops_mal = cur.fetchone()[0]
                        cur.execute("SELECT COUNT(*) FROM posiciones WHERE rowid IN (SELECT MAX(rowid) FROM posiciones GROUP BY id) AND estado_mal = 1"); pos_mal = cur.fetchone()[0]
                        conn.close()
                        proteccion = get_proteccion()
                        prot_txt = "🟢 Activa" if proteccion else "🔴 Desactivada"
                        rt_on = sum(1 for rid in ROUTERS_VIGILADOS if iface.nodes.get(rid) and 'lastHeard' in iface.nodes.get(rid) and (ahora - iface.nodes.get(rid)['lastHeard'] < MARGEN_ONLINE))
                        mqtt_ok = "Conectado" if MQTT_CONNECTED else "Inactivo"
                        alertas = []
                        if hops_mal > 0: alertas.append(f"{hops_mal} salto")
                        if pos_mal > 0: alertas.append(f"{pos_mal} posición")
                        txt_alertas = f"{sum([hops_mal, pos_mal])} activa" + ("s" if sum([hops_mal, pos_mal]) != 1 else "")
                        alertas_detalle = " | ".join(alertas) if alertas else ""
                        alertas_linea = f"\n└ {alertas_detalle}" if alertas_detalle else ""
                        ocp_sema = "🟢" if util < 20 else "🟡" if util < 30 else "🔴"
                        mqtt_sema = "🟢" if mqtt_ok == "Conectado" else "🟡"
                        enviar_telegram(
                            f"🛰️ *STATUS*\n\n"
                            f"⏱ *Uptime:* `{up_txt}`\n"
                            f"📡 *Ocupación:* `{util:.1f}%` {ocp_sema}\n"
                            f"🛡️ *Protección:* `{prot_txt}`\n"
                            f"👥 *Nodos:* `{nodos_tot}` detectados\n"
                            f"📊 *Tráfico 24h:* `{msg_hoy}` pkts\n\n"
                            f"📍 *Routers:* `{rt_on}/{len(ROUTERS_VIGILADOS)}` 🟢\n"
                            f"🌐 *MQTT:* `{mqtt_ok}` {mqtt_sema}\n\n"
                            f"⚠️ *Alertas:* `{txt_alertas}`{alertas_linea}",
                            cid, thread_id=tid
                        )
                    elif cmd == "/delete" and cid == MI_CHAT_ID:
                        conn = sqlite3.connect(DB_PATH); c = conn.cursor()
                        c.execute("DELETE FROM nodos"); c.execute("DELETE FROM trafico"); c.execute("DELETE FROM registro_mensajes"); c.execute("DELETE FROM posiciones")
                        conn.commit(); conn.close(); enviar_telegram("🗑️ DB reseteada.", cid, thread_id=tid)
                    elif cmd == "/sota":
                        if len(partes) >= 2 and partes[1] == "spot":
                            modos_filtro = [m.upper() for m in partes[2:]]
                            spots = obtener_spots_sota(25)
                            if not spots:
                                enviar_telegram("\u274c Error al obtener spots", cid, thread_id=tid)
                            else:
                                if modos_filtro:
                                    spots = [s for s in spots if s["mode"].upper() in modos_filtro]
                                if not spots:
                                    txt = "/".join(modos_filtro) if modos_filtro else ""
                                    enviar_telegram(f"\u274c No hay spots{f' en {txt}' if txt else ''}", cid, thread_id=tid)
                                else:
                                    resp = "\U0001f4e1 *\u00daLTIMOS SPOTS SOTA*"
                                    if modos_filtro:
                                        resp += f" ({'/'.join(modos_filtro)})"
                                    resp += "\n\n"
                                    for s in spots[:8]:
                                        t = s["timeStamp"][11:16]
                                        resp += f"{t}z `{s['activatorCallsign']}` {s['summitCode']} {s['frequency']} {s['mode']}\n"
                                    enviar_telegram(resp, cid, thread_id=tid)
                        elif len(partes) < 4:
                            enviar_telegram("\U0001f3d4 *SOTA SPOT*\n\nDesde aqu\u00ed puedes publicar un spot en SOTAwatch a trav\u00e9s del bot.\n\n*Uso:*\n`/sota EA7LQK/P EA7-MA-102 14.200 SSB Activando`\n\n*Par\u00e1metros:*\n\u2022 `CALL` \u2014 Indicativo del activador (ej: EA7LQK/P)\n\u2022 `SUMMIT` \u2014 Ref. SOTA (EA7-MA-102 o EA7/MA-102)\n\u2022 `FREQ` \u2014 Frecuencia en MHz\n\u2022 `MODE` \u2014 Modo (SSB, CW, FM)\n\u2022 `comentario` \u2014 Opcional\n\n*Por radio (DM):* Env\u00eda `/sota EA7LQK/P EA7-MA-102 14.200 SSB` en privado al bot", cid, thread_id=tid)
                        else:
                            activator = partes[1].upper()
                            summit_ref = partes[2].upper()
                            freq = partes[3]
                            mode = partes[4].upper() if len(partes) > 4 else "SSB"
                            coment = " ".join(partes[5:]) if len(partes) > 5 else ""
                            debug_log("SOTA tg: calling")
                            resp = publicar_spot_sota(activator, summit_ref, freq, mode, coment)
                            debug_log("SOTA tg: done")
                            enviar_telegram(resp, cid, thread_id=tid)

                    elif cmd == "/medusas":
                        prov = partes[1].lower() if len(partes) >= 2 else "almeria"
                        data = obtener_medusas(prov)
                        if data is None:
                            enviar_telegram("❌ Error al obtener datos de medusas", cid, thread_id=tid)
                        else:
                            enviar_telegram(formatear_medusas_telegram(data), cid, thread_id=tid)
                    elif cmd == "/calima":
                        prov = partes[1].lower() if len(partes) >= 2 else "almeria"
                        coords = COORDENADAS_PROVINCIAS.get(prov, (36.83, -2.45))
                        enviar_telegram(formatear_calima(prov, obtener_calima(coords[0], coords[1])), cid, thread_id=tid)
                    elif cmd == "/ia":
                        texto_tg = msg.get("text", "")
                        pregunta = texto_tg.split(" ", 1)[1].strip() if " " in texto_tg.strip() else ""
                        if not pregunta:
                            enviar_telegram("🤖 *IA*\nUso: `/ia <consulta>`\nEj: `/ia ¿qué es el SFNarrow en meshtastic?`", cid, thread_id=tid)
                        else:
                            enviar_telegram(f"🤖 Consultando IA: _{pregunta[:100]}_", cid, thread_id=tid)
                            resp_ia = consultar_ia(pregunta, nodo_id="TG:" + cid, modo_largo=True)
                            enviar_telegram(resp_ia, cid, thread_id=tid)
                    elif cmd == "/trace":
                        if cid != MI_CHAT_ID:
                            continue
                        if len(partes) < 2:
                            enviar_telegram("🛰️ *TRACEROUTE*\nUso: `/trace !xxxxxxxx` (ID del nodo)\nEj: `/trace !c9f19db9`", cid, thread_id=tid)
                        else:
                            enviar_telegram(f"🔍 Trazando ruta hacia `{partes[1]}`...", cid, thread_id=tid)
                            resp_trace = ejecutar_trace(iface, partes[1])
                            enviar_telegram(resp_trace, cid, thread_id=tid)
                    elif cmd == "/ping": enviar_telegram("🤖 PONG!", cid, thread_id=tid)
            time.sleep(3)
        except: time.sleep(5)

def iniciar():
    global MQTT_CONNECTED
    print(f"🚀 BOT ALMERÍA v11.4 - CALIMA + TRACE + RESUMEN SEMANAL")
    iniciar_db()
    try:
        _nodo_host = _env("MESHTASTIC_HOST", "192.168.1.116")
        _nodo_port = int(_env("MESHTASTIC_PORT", "4403"))
        iface = meshtastic.tcp_interface.TCPInterface(hostname=_nodo_host, portNumber=_nodo_port)
        # --- MAPA CANAL -> PROVINCIA ---
        global CHANNEL_TO_PROV, CHANNEL_NAMES
        try:
            for ch in iface.localNode.channels:
                CHANNEL_NAMES[ch.index] = ch.settings.name or f"Ch{ch.index}"
                for prov, nombre in CANALES.items():
                    if ch.settings.name == nombre:
                        CHANNEL_TO_PROV[ch.index] = prov
                        break
        except:
            CHANNEL_TO_PROV = {0: "Almeria", 2: "Granada", 3: "Malaga", 4: "Jaen", 5: "Sevilla"}
            CHANNEL_NAMES = {0: "Primary", 2: "Granada", 3: "Malaga", 4: "Jaen", 5: "Sevilla"}
        # --- ANTI-SPAM: envoltura con rate limiter ---
        original_send = iface.sendText
        def rate_limited_send(text, **kw):
            global radio_rate_alerted
            now = time.time()
            while radio_msg_times and radio_msg_times[0] < now - RADIO_RATE_WINDOW:
                radio_msg_times.popleft()
            if len(radio_msg_times) >= RADIO_RATE_MAX:
                if not radio_rate_alerted:
                    try:
                        enviar_telegram(f"⚠️ Límite de {RADIO_RATE_MAX} msgs en {RADIO_RATE_WINDOW//60} min alcanzado", MI_CHAT_ID)
                    except:
                        pass
                    radio_rate_alerted = True
                return
            radio_msg_times.append(now)
            radio_rate_alerted = False
            original_send(text, **kw)
        iface.sendText = rate_limited_send
        try:
            import potato_fusion
            potato_fusion.iniciar(iface)
            print("🥔 INGESTA POTATO FUSIONADA")
        except Exception as e:
            print(f"⚠️ Ingesta potato NO fusionada: {e}")
        threading.Thread(target=telegram_worker, args=(iface,), daemon=True).start()
        
        # --- TRABAJADOR AEMET ---
        threading.Thread(target=aemet_worker, args=(iface,), daemon=True).start()
        threading.Thread(target=terremotos_worker, args=(iface,), daemon=True).start()
        threading.Thread(target=incendios_worker, args=(iface,), daemon=True).start()
        threading.Thread(target=infoca_worker, args=(iface,), daemon=True).start()
        threading.Thread(target=calima_worker, args=(iface,), daemon=True).start()
        threading.Thread(target=resumen_semanal_worker, args=(iface,), daemon=True).start()
        threading.Thread(target=reconciliar_nombres_worker, args=(iface,), daemon=True).start()
        MQTT_CONNECTED = probar_mqtt()
        threading.Thread(target=mqtt_check_worker, daemon=True).start()
        
        pub.subscribe(on_receive, "meshtastic.receive")
        while True:
            try:
                if not iface.isConnected.is_set():
                    print("⚠️ CONEXIÓN PERDIDA — saliendo para reinicio automático")
                    os._exit(1)
                rx = getattr(iface, "_rxThread", None)
                if rx is not None and not rx.is_alive():
                    print("LECTOR RADIO MUERTO, reiniciando")
                    os._exit(1)
            except Exception:
                pass
            time.sleep(5)
    except Exception as e: print(f"Error conexión: {e}")

if __name__ == "__main__":
    iniciar()
