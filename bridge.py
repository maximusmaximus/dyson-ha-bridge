"""
Dyson Desk Lamp BLE to Home Assistant Bridge Daemon
Runs natively on Windows 11 host (MCMINI) using bleak and WinRT Bluetooth.
Controls Dyson Lightcycle Morph via local BLE GATT characteristics with LTK authentication.
Exposes REST control endpoint and pushes live state to Home Assistant.
"""

import asyncio
import datetime
import hashlib
import hmac
import json
import logging
import math
import os
import signal
import sys
import time
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Optional
from uuid import UUID

import aiohttp
from aiohttp import web
from bleak import BleakClient, BleakScanner
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import yaml

# ── Logging Setup ─────────────────────────────────────────────────────────────

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bridge.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=2, encoding="utf-8"),
    ],
)
logger = logging.getLogger("dyson-bridge")

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")

# ── Dyson BLE Constants ───────────────────────────────────────────────────────

BLE_SERVICE_UUID = "2dd10010-1c37-452d-8979-d1b4a787d0a4"
BLE_AUTH_CHAR_UUID = "2dd10011-1c37-452d-8979-d1b4a787d0a4"
BLE_RSSI_CHAR_UUID = "2dd10013-1c37-452d-8979-d1b4a787d0a4"
BLE_WRITE_ATTR_CHAR_UUID = "2dd10021-1c37-452d-8979-d1b4a787d0a4"

BLE_POWER_UUID = "2dd11005-1c37-452d-8979-d1b4a787d0a4"
BLE_BRIGHTNESS_LUMENS_UUID = "2dd11009-1c37-452d-8979-d1b4a787d0a4"
BLE_COLOR_TEMP_UUID = "2dd11001-1c37-452d-8979-d1b4a787d0a4"
BLE_MOTION_UUID = "2dd11008-1c37-452d-8979-d1b4a787d0a4"

BLE_DAYLIGHT_MODE_DISABLE_PAYLOAD = bytes([0x13, 0x20, 0x01, 0x00, 0x00])

BLE_MSG_TYPE_REAUTH_PAYLOAD_A = 0x06
BLE_MSG_TYPE_REAUTH_PAYLOAD_B = 0x07
BLE_MSG_TYPE_REAUTH_PAYLOAD_C = 0x08
BLE_MSG_TYPE_REQUEST_PRODUCT_INFO = 0x0A
BLE_MSG_TYPE_PRODUCT_INFO = 0x0B
BLE_MSG_TYPE_CONNECTION_ESTABLISHED = 0x26

BLE_HKDF_INFO = b"USER_AUTH_AES\x00\x00\x00"
BLE_MIN_KELVIN = 1800
BLE_MAX_KELVIN = 6500
BLE_MIN_LUMENS = 100
BLE_MAX_LUMENS = 1000

# ── Dyson Framing & Crypto ────────────────────────────────────────────────────

def hkdf_derive_aes_key(ltk: bytes) -> bytes:
    prk = hmac.new(b"", ltk, hashlib.sha256).digest()
    block1 = hmac.new(prk, BLE_HKDF_INFO + b"\x01", hashlib.sha256).digest()
    return block1[:16]

def _aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def g20c_encrypt(enc_key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    ct = _aes_cbc_encrypt(enc_key, iv, plaintext)
    mac = hmac.new(enc_key, ct, hashlib.sha256).digest()
    return iv + ct + mac

def g20c_decrypt(enc_key: bytes, envelope: bytes) -> Optional[bytes]:
    if len(envelope) != 64:
        return None
    iv = envelope[:16]
    ct = envelope[16:32]
    mac = envelope[32:64]
    expected_mac = hmac.new(enc_key, ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        return None
    return _aes_cbc_decrypt(enc_key, iv, ct)

def fragment_dyson_message(type_id: int, payload: bytes, capacity: int = 20) -> list[bytes]:
    logical = bytes([type_id]) + payload
    data_per_fragment = capacity - 1
    total_fragments = max(1, math.ceil(len(logical) / data_per_fragment))
    fragments: list[bytes] = []
    for index in range(total_fragments):
        start = index * data_per_fragment
        chunk = logical[start : start + data_per_fragment]
        header = (0x80 | (total_fragments - 1)) if index == 0 else (index & 0x7F)
        fragments.append(bytes([header]) + chunk)
    return fragments

class DysonFragmentAssembler:
    def __init__(self):
        self._buffer = bytearray()
        self._expected_fragments = 0
        self._received_fragments = 0
        self._type_id = 0

    def reset(self):
        self._buffer.clear()
        self._expected_fragments = 0
        self._received_fragments = 0
        self._type_id = 0

    def feed(self, fragment: bytes) -> Optional[tuple[int, bytes]]:
        if not fragment:
            return None
        header = fragment[0]
        is_first = bool(header & 0x80)
        if is_first:
            if len(fragment) < 2:
                return None
            self._buffer.clear()
            self._expected_fragments = (header & 0x7F) + 1
            self._received_fragments = 1
            self._type_id = fragment[1]
            self._buffer.extend(fragment[2:])
        else:
            if self._expected_fragments == 0:
                return None
            self._received_fragments = (header & 0x7F) + 1
            self._buffer.extend(fragment[1:])

        if self._expected_fragments and self._received_fragments == self._expected_fragments:
            res = (self._type_id, bytes(self._buffer))
            self.reset()
            return res
        return None

# ── Dyson Bridge Engine ───────────────────────────────────────────────────────

class DysonBridge:
    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        self.config_path = config_path
        self.config = self._load_config(config_path)

        dev = self.config.get("device", {})
        self.mac = dev.get("mac", "").upper()
        self.serial = dev.get("serial", "")
        self.ltk_hex = dev.get("ltk", "").lower()
        self.account_uuid = dev.get("account_uuid", "00000000-0000-0000-0000-000000000000")

        ha = self.config.get("home_assistant", {})
        self.ha_url = ha.get("url", "http://192.168.50.106:8123").rstrip("/")
        self.ha_token = ha.get("token", "")

        br = self.config.get("bridge", {})
        self.listen_port = int(br.get("http_port", 8089))
        self.entity_id = br.get("entity_id", "light.dyson_desk_lamp")
        self.motion_entity_id = br.get("motion_entity_id", "binary_sensor.dyson_desk_lamp_motion")

        self.client: Optional[BleakClient] = None
        self.assembler = DysonFragmentAssembler()
        self.message_queue: asyncio.Queue[tuple[int, bytes]] = asyncio.Queue()

        # Lamp Live State
        self.power = False
        self.brightness = 255  # 1..255
        self.brightness_lumens = 1000  # 100..1000
        self.color_temp_kelvin = 4000  # 2700..6500
        self.motion = False
        self.connected = False
        self.authenticated = False
        self.last_seen = 0.0

        # Synced HA state tracking for echo prevention
        self._ha_power: Optional[bool] = None
        self._ha_brightness: Optional[int] = None
        self._ha_mireds: Optional[int] = None
        self._ha_motion: Optional[bool] = None
        self._suppress_ble_notifications_until = 0.0

        self._running = True
        self._lock = asyncio.Lock()

    def _load_config(self, path: str) -> dict:
        if not os.path.exists(path):
            logger.warning(f"Config file not found at {path}, using defaults")
            return {}
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    async def _send_dyson_message(self, type_id: int, payload: bytes = b"", inter_delay: float = 0.03):
        if not self.client or not self.client.is_connected:
            raise RuntimeError("BLE client not connected")
        fragments = fragment_dyson_message(type_id, payload)
        for i, frag in enumerate(fragments):
            await self.client.write_gatt_char(BLE_AUTH_CHAR_UUID, frag, response=False)
            if inter_delay > 0 and i < len(fragments) - 1:
                await asyncio.sleep(inter_delay)

    async def _wait_for_message(self, expected_type: int, timeout: float = 10.0) -> bytes:
        end = time.time() + timeout
        while time.time() < end:
            try:
                rem = max(0.1, end - time.time())
                t_id, payload = await asyncio.wait_for(self.message_queue.get(), timeout=rem)
                if t_id == expected_type:
                    return payload
                logger.debug(f"Discarding unsolicited message 0x{t_id:02X} while waiting for 0x{expected_type:02X}")
            except (asyncio.TimeoutError, TimeoutError):
                break
        raise TimeoutError(f"Timed out waiting for Dyson message 0x{expected_type:02X}")

    def _on_auth_notification(self, sender: Any, data: bytearray):
        msg = self.assembler.feed(bytes(data))
        if msg:
            type_id, payload = msg
            logger.debug(f"Reassembled Dyson message 0x{type_id:02X} ({len(payload)} bytes)")
            self.message_queue.put_nowait((type_id, payload))

    def _on_motion_notification(self, sender: Any, data: bytearray):
        raw = bytes(data)
        has_motion = any(b != 0 for b in raw)
        logger.info(f"Dyson Motion event: {'DETECTED' if has_motion else 'CLEAR'} (raw={raw.hex()})")
        self.motion = has_motion
        if self._ha_motion != has_motion:
            self._ha_motion = has_motion
            asyncio.create_task(self.push_entity_to_ha(self.motion_entity_id, {
                "state": "on" if self.motion else "off",
                "attributes": {
                    "friendly_name": "Dyson Desk Lamp Motion",
                    "device_class": "motion",
                },
            }))

    def _on_power_notification(self, sender: Any, data: bytearray):
        raw = bytes(data)
        new_power = bool(raw and raw[0] != 0)
        logger.info(f"Dyson Power notification: {'ON' if new_power else 'OFF'}")
        is_physical_activation = (new_power and not self.power and not self._ha_power)
        self.power = new_power
        if is_physical_activation:
            logger.info("Physical activation detected on Dyson lamp! Triggering circadian color temp...")
            asyncio.create_task(self._handle_physical_activation())
        else:
            if self._ha_power != new_power:
                self._ha_power = new_power
                asyncio.create_task(self.push_entity_to_ha(
                    "input_boolean.dyson_desk_lamp_state",
                    {"state": "on" if new_power else "off"}
                ))

    def _on_brightness_notification(self, sender: Any, data: bytearray):
        if time.time() < self._suppress_ble_notifications_until:
            return
        raw = bytes(data)
        if len(raw) >= 2:
            lumens = int.from_bytes(raw[:2], byteorder="little")
            self.brightness_lumens = lumens
            ha_b = max(1, min(255, round((lumens - BLE_MIN_LUMENS) * 255 / (BLE_MAX_LUMENS - BLE_MIN_LUMENS))))
            self.brightness = ha_b
            logger.info(f"Dyson Brightness notification: {lumens} lm (HA: {self.brightness})")
            if self._ha_brightness is None or abs(self._ha_brightness - ha_b) > 2:
                self._ha_brightness = ha_b
                asyncio.create_task(self.push_entity_to_ha(
                    "input_number.dyson_desk_lamp_brightness",
                    {"state": str(ha_b)}
                ))

    def _on_color_temp_notification(self, sender: Any, data: bytearray):
        if time.time() < self._suppress_ble_notifications_until:
            return
        raw = bytes(data)
        if len(raw) >= 2:
            kelvin = int.from_bytes(raw[:2], byteorder="little")
            self.color_temp_kelvin = max(BLE_MIN_KELVIN, min(BLE_MAX_KELVIN, kelvin))
            mireds = round(1_000_000 / self.color_temp_kelvin)
            logger.info(f"Dyson Color Temp notification: {kelvin} K ({mireds} mireds)")
            if self._ha_mireds is None or abs(self._ha_mireds - mireds) > 2:
                self._ha_mireds = mireds
                asyncio.create_task(self.push_entity_to_ha(
                    "input_number.dyson_desk_lamp_mireds",
                    {"state": str(mireds)}
                ))

    async def _authenticate(self, enc_key: bytes) -> bool:
        logger.info(f"Initiating LTK Re-auth with Dyson lamp ({self.serial})...")
        await self._send_dyson_message(BLE_MSG_TYPE_REQUEST_PRODUCT_INFO)
        try:
            prod_info = await self._wait_for_message(BLE_MSG_TYPE_PRODUCT_INFO, timeout=5.0)
            logger.info(f"Received Product Info ({len(prod_info)} bytes): {prod_info.hex()}")
        except TimeoutError:
            logger.warning("Product info timeout, continuing with auth...")

        # Step 1: Send PayloadA (0x06)
        nonce = os.urandom(16)
        uuid_bytes = UUID(self.account_uuid).bytes
        encrypted_nonce = g20c_encrypt(enc_key, nonce)
        payload_a = uuid_bytes + b"\x00\x00" + encrypted_nonce
        logger.info(f"Sending PayloadA (0x06) to {self.serial}...")
        await self._send_dyson_message(BLE_MSG_TYPE_REAUTH_PAYLOAD_A, payload_a)

        # Step 2: Wait for PayloadB (0x07)
        logger.info("Waiting for PayloadB (0x07)...")
        payload_b = await self._wait_for_message(BLE_MSG_TYPE_REAUTH_PAYLOAD_B, timeout=15.0)
        logger.info(f"PayloadB received ({len(payload_b)} bytes)")
        if len(payload_b) < 50:
            raise ValueError(f"PayloadB too short: {len(payload_b)} bytes")

        iv = payload_b[2:18]
        ct = payload_b[18:50]
        mac = payload_b[50:82]
        if len(mac) == 32:
            expected_mac = hmac.new(enc_key, ct, hashlib.sha256).digest()
            if not hmac.compare_digest(mac, expected_mac):
                raise ValueError("PayloadB HMAC validation failed — invalid LTK!")

        dec = _aes_cbc_decrypt(enc_key, iv, ct)
        device_nonce = dec[16:32]
        logger.info(f"Decoded device challenge: {device_nonce.hex()[:8]}...")

        # Step 3: Send PayloadC (0x08)
        payload_c = b"\x00\x00" + g20c_encrypt(enc_key, device_nonce)
        logger.info("Sending PayloadC (0x08)...")
        await self._send_dyson_message(BLE_MSG_TYPE_REAUTH_PAYLOAD_C, payload_c)

        # Step 4: Wait for Connection Established (0x26)
        logger.info("Waiting for Connection Established (0x26)...")
        await self._wait_for_message(BLE_MSG_TYPE_CONNECTION_ESTABLISHED, timeout=15.0)
        logger.info("Dyson BLE Connection Established & Authenticated!")
        return True

    async def connect_and_init(self):
        if not self.mac or not self.ltk_hex:
            logger.error("Missing MAC address or LTK in configuration!")
            return False

        ltk_bytes = bytes.fromhex(self.ltk_hex)
        enc_key = hkdf_derive_aes_key(ltk_bytes)

        try:
            logger.info(f"Connecting to Dyson lamp at {self.mac}...")
            self.client = BleakClient(self.mac, timeout=12.0)
            await self.client.connect()
            self.connected = self.client.is_connected
            logger.info(f"GATT Connected: {self.connected}")

            # Subscribe to Auth notifications
            await self.client.start_notify(BLE_AUTH_CHAR_UUID, self._on_auth_notification)

            # Authenticate
            await self._authenticate(enc_key)
            self.authenticated = True

            # Subscribe to controls & sensors
            try:
                await self.client.start_notify(BLE_POWER_UUID, self._on_power_notification)
                await self.client.start_notify(BLE_BRIGHTNESS_LUMENS_UUID, self._on_brightness_notification)
                await self.client.start_notify(BLE_COLOR_TEMP_UUID, self._on_color_temp_notification)
                await self.client.start_notify(BLE_MOTION_UUID, self._on_motion_notification)
            except Exception as e:
                logger.warning(f"Error subscribing to one or more characteristics: {e}")

            # Read initial states
            try:
                p_val = await self.client.read_gatt_char(BLE_POWER_UUID)
                self.power = bool(p_val and p_val[0] != 0)
                b_val = await self.client.read_gatt_char(BLE_BRIGHTNESS_LUMENS_UUID)
                if len(b_val) >= 2:
                    self.brightness_lumens = int.from_bytes(b_val[:2], byteorder="little")
                    self.brightness = max(1, min(255, round((self.brightness_lumens - BLE_MIN_LUMENS) * 255 / (BLE_MAX_LUMENS - BLE_MIN_LUMENS))))
                c_val = await self.client.read_gatt_char(BLE_COLOR_TEMP_UUID)
                if len(c_val) >= 2:
                    self.color_temp_kelvin = int.from_bytes(c_val[:2], byteorder="little")
                logger.info(f"Initial State: Power={'ON' if self.power else 'OFF'}, Lumens={self.brightness_lumens} lm, Kelvin={self.color_temp_kelvin} K")
            except Exception as e:
                logger.warning(f"Could not read full initial state: {e}")

            await self.push_state_to_ha()
            return True
        except Exception as e:
            logger.warning(f"Connection or authentication attempt failed: {e}")
            if self.client:
                try:
                    await self.client.disconnect()
                except Exception:
                    pass
                self.client = None
            self.connected = False
            self.authenticated = False
            return False

    # ── Control Operations ────────────────────────────────────────────────────

    async def set_power(self, on: bool, push_ha: bool = True):
        async with self._lock:
            if not self.client or not self.client.is_connected:
                raise RuntimeError("Lamp not connected")
            val = b"\x01" if on else b"\x00"
            await self.client.write_gatt_char(BLE_POWER_UUID, val, response=False)
            self.power = on
            logger.info(f"Set power: {'ON' if on else 'OFF'}")
            if push_ha:
                self._ha_power = on
                await self.push_entity_to_ha(
                    "input_boolean.dyson_desk_lamp_state",
                    {"state": "on" if on else "off"}
                )

    async def set_brightness(self, ha_brightness: int, push_ha: bool = True):
        async with self._lock:
            if not self.client or not self.client.is_connected:
                raise RuntimeError("Lamp not connected")
            # Map 1..255 to 100..1000 lm
            ha_brightness = max(1, min(255, ha_brightness))
            lumens = round(BLE_MIN_LUMENS + (ha_brightness / 255.0) * (BLE_MAX_LUMENS - BLE_MIN_LUMENS))
            # Assert manual mode
            await self.client.write_gatt_char(BLE_WRITE_ATTR_CHAR_UUID, BLE_DAYLIGHT_MODE_DISABLE_PAYLOAD, response=True)
            await asyncio.sleep(0.05)
            # Write lumens uint16 LE
            await self.client.write_gatt_char(BLE_BRIGHTNESS_LUMENS_UUID, lumens.to_bytes(2, byteorder="little"), response=True)
            self.brightness = ha_brightness
            self.brightness_lumens = lumens
            logger.info(f"Set brightness: {ha_brightness}/255 ({lumens} lm)")
            if push_ha:
                self._ha_brightness = ha_brightness
                await self.push_entity_to_ha(
                    "input_number.dyson_desk_lamp_brightness",
                    {"state": str(ha_brightness)}
                )

    async def set_color_temp_kelvin(self, kelvin: int, push_ha: bool = True):
        async with self._lock:
            if not self.client or not self.client.is_connected:
                raise RuntimeError("Lamp not connected")
            kelvin = max(BLE_MIN_KELVIN, min(BLE_MAX_KELVIN, kelvin))
            # Assert manual mode
            await self.client.write_gatt_char(BLE_WRITE_ATTR_CHAR_UUID, BLE_DAYLIGHT_MODE_DISABLE_PAYLOAD, response=True)
            await asyncio.sleep(0.05)
            # Write kelvin uint16 LE
            await self.client.write_gatt_char(BLE_COLOR_TEMP_UUID, kelvin.to_bytes(2, byteorder="little"), response=True)
            self.color_temp_kelvin = kelvin
            logger.info(f"Set color temp: {kelvin} K")
            if push_ha:
                mireds = round(1_000_000 / kelvin)
                self._ha_mireds = mireds
                await self.push_entity_to_ha(
                    "input_number.dyson_desk_lamp_mireds",
                    {"state": str(mireds)}
                )

    # ── Circadian Color Temp Calculation & Physical Activation ────────────────

    async def get_circadian_kelvin(self) -> int:
        tmpl = (
            "{% if is_state('sun.sun', 'below_horizon') and (now().hour >= 17 or now().hour < 6) %}"
            "{{ states('input_number.circadian_temp_night') | default(states('input_number.dyson_desk_lamp_temp_night'), true) | int(2700) }}"
            "{% elif now().hour < 12 %}"
            "{{ states('input_number.circadian_temp_morning') | default(states('input_number.dyson_desk_lamp_temp_morning'), true) | int(6500) }}"
            "{% else %}"
            "{{ states('input_number.circadian_temp_midday') | default(states('input_number.dyson_desk_lamp_temp_midday'), true) | int(4000) }}"
            "{% endif %}"
        )
        if self.ha_token:
            try:
                headers = {"Authorization": f"Bearer {self.ha_token}", "Content-Type": "application/json"}
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{self.ha_url}/api/template",
                        json={"template": tmpl},
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=3.0)
                    ) as resp:
                        if resp.status == 200:
                            text = (await resp.text()).strip()
                            k = int(text)
                            logger.info(f"HA circadian template returned: {k} K")
                            return max(BLE_MIN_KELVIN, min(BLE_MAX_KELVIN, k))
            except Exception as e:
                logger.warning(f"Failed to fetch circadian template from HA: {e}")

        # Local time fallback
        h = datetime.datetime.now().hour
        if h >= 17 or h < 6:
            return 2700
        elif h < 12:
            return 6500
        else:
            return 4000

    async def _handle_physical_activation(self):
        try:
            circadian_k = await self.get_circadian_kelvin()
            logger.info(f"Applying circadian temperature for physical activation: {circadian_k} K")
            await self.set_color_temp_kelvin(circadian_k, push_ha=False)
            circadian_mireds = round(1_000_000 / circadian_k)
            self._ha_power = True
            self._ha_mireds = circadian_mireds
            # Sync HA helpers
            await self.push_entity_to_ha("input_boolean.dyson_desk_lamp_state", {"state": "on"})
            await self.push_entity_to_ha("input_number.dyson_desk_lamp_mireds", {"state": str(circadian_mireds)})
        except Exception as e:
            logger.error(f"Error handling physical activation: {e}")

    # ── Home Assistant REST API Push ──────────────────────────────────────────

    async def push_entity_to_ha(self, entity_id: str, payload: dict):
        if not self.ha_token:
            return
        headers = {
            "Authorization": f"Bearer {self.ha_token}",
            "Content-Type": "application/json",
        }
        url = f"{self.ha_url}/api/states/{entity_id}"
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(url, json=payload, headers=headers)
        except Exception as e:
            logger.debug(f"Could not push {entity_id} to HA: {e}")

    async def push_all_to_ha(self):
        mireds = round(1_000_000 / self.color_temp_kelvin) if self.color_temp_kelvin > 0 else 370
        self._ha_power = self.power
        self._ha_brightness = self.brightness
        self._ha_mireds = mireds
        self._ha_motion = self.motion
        await self.push_entity_to_ha("input_boolean.dyson_desk_lamp_state", {"state": "on" if self.power else "off"})
        await self.push_entity_to_ha("input_number.dyson_desk_lamp_brightness", {"state": str(self.brightness)})
        await self.push_entity_to_ha("input_number.dyson_desk_lamp_mireds", {"state": str(mireds)})
        await self.push_entity_to_ha(self.motion_entity_id, {
            "state": "on" if self.motion else "off",
            "attributes": {
                "friendly_name": "Dyson Desk Lamp Motion",
                "device_class": "motion",
            },
        })

    async def push_state_to_ha(self):
        await self.push_all_to_ha()

    # ── Home Assistant WebSocket Listener (Zero-Firewall Push) ───────────────

    async def run_ha_ws_listener(self):
        ws_url = self.ha_url.replace("http://", "ws://").replace("https://", "wss://") + "/api/websocket"
        while self._running:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(ws_url) as ws:
                        logger.info(f"Connected to Home Assistant WebSocket at {ws_url}")
                        auth_msg = await ws.receive_json()
                        if auth_msg.get("type") == "auth_required":
                            await ws.send_json({"type": "auth", "access_token": self.ha_token})
                            auth_ok = await ws.receive_json()
                            if auth_ok.get("type") != "auth_ok":
                                logger.error(f"HA WebSocket auth failed: {auth_ok}")
                                await asyncio.sleep(10)
                                continue

                        # Subscribe to state_changed events
                        await ws.send_json({"id": 1, "type": "subscribe_events", "event_type": "state_changed"})
                        sub_res = await ws.receive_json()
                        logger.info(f"Subscribed to HA state_changed events (Success: {sub_res.get('success')})")

                        async for msg in ws:
                            if msg.type == aiohttp.WSMsgType.TEXT:
                                data = json.loads(msg.data)
                                if data.get("type") == "event":
                                    event = data.get("event", {})
                                    if event.get("event_type") == "state_changed":
                                        d = event.get("data", {})
                                        entity_id = d.get("entity_id")
                                        new_state = d.get("new_state", {})
                                        old_state = d.get("old_state", {})
                                        if not new_state:
                                            continue
                                        new_val = new_state.get("state")
                                        old_val = old_state.get("state") if old_state else None
                                        if new_val == old_val:
                                            continue

                                        # State Helper
                                        if entity_id == "input_boolean.dyson_desk_lamp_state":
                                            target_power = (new_val == "on")
                                            self._ha_power = target_power
                                            if target_power != self.power:
                                                logger.info(f"HA requested Power {'ON' if target_power else 'OFF'}")
                                                self._suppress_ble_notifications_until = time.time() + 1.5
                                                await self.set_power(target_power, push_ha=False)

                                        # Brightness Helper
                                        elif entity_id == "input_number.dyson_desk_lamp_brightness":
                                            try:
                                                ha_b = int(float(new_val))
                                                self._ha_brightness = ha_b
                                                if abs(ha_b - self.brightness) > 2:
                                                    logger.info(f"HA requested Brightness change: {ha_b}")
                                                    self._suppress_ble_notifications_until = time.time() + 1.5
                                                    await self.set_brightness(ha_b, push_ha=False)
                                            except Exception as ex:
                                                logger.warning(f"Error parsing brightness from HA: {ex}")

                                        # Mireds Helper
                                        elif entity_id == "input_number.dyson_desk_lamp_mireds":
                                            try:
                                                mireds = int(float(new_val))
                                                self._ha_mireds = mireds
                                                k = round(1_000_000 / max(1, mireds))
                                                if abs(k - self.color_temp_kelvin) > 50:
                                                    logger.info(f"HA requested Color Temp change: {k}K ({mireds} mireds)")
                                                    self._suppress_ble_notifications_until = time.time() + 1.5
                                                    await self.set_color_temp_kelvin(k, push_ha=False)
                                            except Exception as ex:
                                                logger.warning(f"Error parsing color temp from HA: {ex}")
                            elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                                break
            except Exception as e:
                logger.warning(f"HA WebSocket connection error: {e}. Reconnecting in 5s...")
                await asyncio.sleep(5)

    # ── Background Watchdog Loop ──────────────────────────────────────────────

    async def run_loop(self):
        retry_delay = 5
        while self._running:
            try:
                if not self.client or not self.client.is_connected or not self.authenticated:
                    logger.info("Attempting connection to Dyson lamp...")
                    ok = await self.connect_and_init()
                    if ok:
                        retry_delay = 5
                    else:
                        await asyncio.sleep(retry_delay)
                        retry_delay = min(15, retry_delay + 3)
                        continue

                # Keepalive read
                await asyncio.sleep(25.0)
                if self.client and self.client.is_connected:
                    try:
                        p = await self.client.read_gatt_char(BLE_POWER_UUID)
                        self.power = bool(p and p[0] != 0)
                        self.last_seen = time.time()
                    except Exception as e:
                        logger.warning(f"Keepalive ping failed: {e}")
                        self.connected = False
                        self.authenticated = False
            except Exception as e:
                logger.error(f"Error in Dyson bridge loop: {e}")
                self.connected = False
                self.authenticated = False
                await asyncio.sleep(retry_delay)
                retry_delay = min(15, retry_delay + 3)

# ── HTTP Server for Home Assistant Integration ────────────────────────────────

async def create_http_server(bridge: DysonBridge) -> web.AppRunner:
    app = web.Application()

    async def handle_status(request: web.Request) -> web.Response:
        data = {
            "connected": bridge.connected,
            "authenticated": bridge.authenticated,
            "power": bridge.power,
            "brightness": bridge.brightness,
            "lumens": bridge.brightness_lumens,
            "color_temp_kelvin": bridge.color_temp_kelvin,
            "motion": bridge.motion,
            "mac": bridge.mac,
            "serial": bridge.serial,
        }
        return web.json_response(data)

    async def handle_set(request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        logger.info(f"Received HTTP set request: {body}")
        try:
            # Handle power
            if "state" in body:
                st = str(body["state"]).lower()
                if st in ("on", "true", "1"):
                    await bridge.set_power(True)
                elif st in ("off", "false", "0"):
                    await bridge.set_power(False)

            # Handle brightness
            if "brightness" in body:
                b = int(body["brightness"])
                await bridge.set_brightness(b)

            # Handle color temp
            if "color_temp_kelvin" in body:
                k = int(body["color_temp_kelvin"])
                await bridge.set_color_temp_kelvin(k)
            elif "color_temp" in body:
                mireds = int(body["color_temp"])
                k = round(1_000_000 / max(1, mireds))
                await bridge.set_color_temp_kelvin(k)

            return web.json_response({"status": "ok", "power": bridge.power, "brightness": bridge.brightness, "color_temp_kelvin": bridge.color_temp_kelvin})
        except Exception as e:
            logger.error(f"Error handling set request: {e}")
            return web.json_response({"error": str(e)}, status=500)

    app.router.add_get("/api/light/status", handle_status)
    app.router.add_post("/api/light/set", handle_set)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", bridge.listen_port)
    await site.start()
    logger.info(f"HTTP Control Server listening on http://0.0.0.0:{bridge.listen_port}")
    return runner

# ── Main Entrypoint ───────────────────────────────────────────────────────────

async def main():
    bridge = DysonBridge()
    http_runner = await create_http_server(bridge)
    try:
        await asyncio.gather(
            bridge.run_loop(),
            bridge.run_ha_ws_listener(),
        )
    finally:
        await http_runner.cleanup()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Bridge daemon stopped by user")
