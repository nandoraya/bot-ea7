"""Fusion del ingestor potato-mesh dentro del bot.

Conecta la ingesta potato (handlers, cola y heartbeat) a la interfaz
meshtastic que ya abre el bot, de modo que un unico proceso y una unica
conexion TCP sirven a ambos (el firmware solo acepta 1 cliente TCP).

Uso:
    import potato_fusion
    potato_fusion.iniciar(iface)
"""

import os
import sys
import threading

import time

POTATO_ROOT = os.environ.get("POTATO_ROOT", "/home/nando/potato-mesh")
if POTATO_ROOT not in sys.path:
    sys.path.insert(0, POTATO_ROOT)

INSTANCE_DOMAIN = os.environ.get("POTATO_API_URL", "http://192.168.1.100:41447")
API_TOKEN = os.environ.get("POTATO_API_TOKEN", "")

os.environ.setdefault("INSTANCE_DOMAIN", INSTANCE_DOMAIN)
os.environ.setdefault("API_TOKEN", API_TOKEN)
os.environ.setdefault("CONNECTION", os.environ.get("MESHTASTIC_TCP", "tcp://192.168.1.116:4403"))
os.environ["MODEM_PRESET"] = os.environ.get("MODEM_PRESET", "SFNarrow")

from data.mesh_ingestor import config
from data.mesh_ingestor import daemon
from data.mesh_ingestor import handlers
from data.mesh_ingestor import ingestors
from data.mesh_ingestor import interfaces

SNAPSHOT_SECS = getattr(config, "SNAPSHOT_SECS", 60)


def iniciar(iface):
    """Integra la ingesta potato sobre la interfaz ya abierta."""

    config.INSTANCE = INSTANCE_DOMAIN
    config.API_TOKEN = API_TOKEN

    subscribed = daemon._subscribe_receive_topics()
    if subscribed:
        config._debug_log(
            "Bot fusion: topics ingesta suscritos",
            context="potato_fusion",
            severity="info",
            topics=subscribed,
        )

    interfaces._ensure_radio_metadata(iface)
    interfaces._ensure_channel_metadata(iface)
    handlers.register_host_node_id(interfaces._extract_host_node_id(iface))
    ingestors.set_ingestor_node_id(handlers.host_node_id())

    threading.Thread(target=_snapshot_inicial, args=(iface,), daemon=True).start()
    threading.Thread(
        target=_heartbeat_loop, args=(iface,), daemon=True
    ).start()
    return True


def _snapshot_inicial(iface):
    try:
        nodes = getattr(iface, "nodes", {}) or {}
        items = daemon._node_items_snapshot(nodes)
        if items is None:
            return
        for node_id, node in items:
            try:
                handlers.upsert_node(node_id, node)
            except Exception as exc:
                if config.DEBUG:
                    config._debug_log(
                        "Fusion: fallo en snapshot",
                        context="potato_fusion.snapshot",
                        severity="warn",
                        node_id=node_id,
                        error_class=exc.__class__.__name__,
                        error_message=str(exc),
                    )
    except Exception:
        pass


def _heartbeat_loop(iface):
    announcement_sent = False
    while True:
        try:
            announcement_sent = daemon._process_ingestor_heartbeat(
                iface, ingestor_announcement_sent=announcement_sent
            )
        except Exception:
            pass
        time.sleep(SNAPSHOT_SECS)


__all__ = ["iniciar"]
