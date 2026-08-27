# Bot Meshtastic Meteo Andalucía

Bot para red **Meshtastic** (banda 868 MHz) que se conecta a un nodo por TCP y ofrece
servicios meteorológicos, alertas y utilidades tanto por radio (comandos en canales)
como por **Telegram**.

## Funcionalidades

- **Clima / viento / previsión / calima** por provincia (`/tiempo`, `/viento`, `/prevision`, `/calima`)
  con datos de Open-Meteo y calima (polvo sahariano) con alerta proactiva.
- **Alertas AEMET** (avisos meteorológicos) activas por provincia.
- **Terremotos** (EMSC), con waypoint automático en el mapa.
- **Incendios** (NASA FIRMS + INFOCA Andalucía), con waypoint y aviso.
- **Resumen semanal** por Telegram (domingo 21:00).
- **Traceroute RF** (`/trace !id`) por DM de Telegram.
- **Reconciliación de nombres de nodos** con la API de Potato Mesh.
- **IA** (`/ia <consulta>`) con Groq, tanto por radio como por Telegram.
- **SOTA, Gasolina, QRZ/HamQTH, Medusas, MQTT, /ping, /status** y más.

## Arquitectura

```
Nodo Meshtastic (TCP:4403)
   │  (firmware acepta 1 cliente TCP)
   ├── bot_meshtastic.py   ← bot principal
   └── potato_fusion.py    ← ingesta Potato Mesh compartiendo la misma conexión TCP
```

`potato_fusion` integra la ingesta de [potato-mesh](https://github.com/meshtastic/potato-mesh)
sobre la misma interfaz que abre el bot, de modo que un único proceso y una única conexión
TCP sirven a ambos.

## Instalación

Requisitos: Python 3.10+ y el repositorio de `potato-mesh` clonado (necesario para la ingesta).

```bash
# Entorno virtual
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configuración (rellena con tus valores reales)
cp .env.example .env
nano .env
```

## Configuración

Todos los parámetros (secretos, IPs, tokens) se cargan desde `.env` (o variables de entorno).
Consulta `.env.example` para la lista completa. La ruta del `.env` es el mismo directorio del script.

Principales variables:

| Variable | Descripción |
|---|---|
| `MESHTASTIC_HOST` / `MESHTASTIC_PORT` | Nodo Meshtastic TCP (default `192.168.1.116:4403`) |
| `TELEGRAM_TOKEN` / `MI_CHAT_ID` | Bot de Telegram y chat principal |
| `CHATS_PERMITIDOS` | Chats con acceso, separados por coma |
| `POTATO_API_URL` / `POTATO_API_TOKEN` | API de Potato Mesh |
| `AEMET_API_KEY` | Clave de opendata.aemet.es |
| `FIRMS_MAP_KEY` | Clave de FIRMS (NASA) |
| `IA_API_KEY` / `IA_MODEL` | Clave y modelo de Groq |
| `QRZ_USER` / `QRZ_PASS` | Credenciales HamQTH |
| `SOTA_USER` / `SOTA_PASS` | Credenciales SOTA |
| `MGTT_*` | Servidor MQTT Meshtastic |

## Ejecución como servicio (systemd)

```ini
[Unit]
Description=Bot Meshtastic Meteo Almería
After=network.target

[Service]
WorkingDirectory=/ruta/al/bot
ExecStart=/ruta/al/venv/bin/python3 /ruta/al/bot/bot_meshtastic.py
Restart=always
RestartSec=10
User=tu_usuario

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp bot_meshtastic.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bot_meshtastic
```

## Seguridad

- **Los secretos NO van en el código**: se leen de `.env` (ignorado por git).
- Nunca subas tu `.env` ni filtres tus tokens en issues/PRs.
- Si expones un token o clave, revócalo y genera otro.

## Notas

- Los canales desde los que se aceptan comandos se detectan dinámicamente en el arranque
  leyendo la configuración de canales del nodo (`iniciar()`).
- El canal primario (índice 0) ignora comandos por diseño; los comandos funcionan en
  canales provinciales y por DM.
