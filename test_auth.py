import asyncio
import hashlib
import hmac
import os
import sys
import time
from uuid import UUID
from bleak import BleakClient, BleakScanner
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import yaml

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

dev = config["device"]
MAC = dev["mac"]
SERIAL = dev["serial"]
LTK_HEX = dev["ltk"]
ACCOUNT_UUID = dev.get("account_uuid", "00000000-0000-0000-0000-000000000000")

BLE_AUTH_CHAR_UUID = "2dd10011-1c37-452d-8979-d1b4a787d0a4"
BLE_POWER_UUID = "2dd11005-1c37-452d-8979-d1b4a787d0a4"
BLE_BRIGHTNESS_LUMENS_UUID = "2dd11009-1c37-452d-8979-d1b4a787d0a4"
BLE_COLOR_TEMP_UUID = "2dd11001-1c37-452d-8979-d1b4a787d0a4"
BLE_MOTION_UUID = "2dd11008-1c37-452d-8979-d1b4a787d0a4"

BLE_HKDF_INFO = b"USER_AUTH_AES\x00\x00\x00"

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

def fragment_dyson_message(type_id: int, payload: bytes, capacity: int = 20) -> list[bytes]:
    import math
    logical = bytes([type_id]) + payload
    data_per_fragment = capacity - 1
    total_fragments = max(1, math.ceil(len(logical) / data_per_fragment))
    fragments = []
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

    def feed(self, fragment: bytes):
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

async def run_test():
    print(f"Connecting to {MAC} ({SERIAL})...")
    ltk_bytes = bytes.fromhex(LTK_HEX)
    enc_key = hkdf_derive_aes_key(ltk_bytes)
    print(f"Derived AES Key: {enc_key.hex()}")

    assembler = DysonFragmentAssembler()
    q = asyncio.Queue()

    def notif_handler(sender, data):
        msg = assembler.feed(bytes(data))
        if msg:
            print(f"  << Received Dyson message 0x{msg[0]:02X} ({len(msg[1])} bytes)")
            q.put_nowait(msg)

    async with BleakClient(MAC, timeout=15.0) as client:
        print("Connected to BLE device!")
        print("Starting notification on auth char...")
        await client.start_notify(BLE_AUTH_CHAR_UUID, notif_handler)

        async def send_msg(t_id, payload=b""):
            frags = fragment_dyson_message(t_id, payload)
            for f in frags:
                await client.write_gatt_char(BLE_AUTH_CHAR_UUID, f, response=False)

        async def wait_msg(expected, timeout=10.0):
            deadline = time.time() + timeout
            while time.time() < deadline:
                t_id, payload = await asyncio.wait_for(q.get(), timeout=max(0.1, deadline - time.time()))
                if t_id == expected:
                    return payload
            raise TimeoutError(f"Timeout waiting for 0x{expected:02X}")

        # Request Product Info (0x0A)
        print("Sending 0x0A (Request Product Info)...")
        await send_msg(0x0A)
        try:
            prod_info = await wait_msg(0x0B, timeout=5.0)
            print(f"Product Info (0x0B): {prod_info.hex()}")
        except Exception as e:
            print(f"Product Info timed out or skipped: {e}")

        # Send PayloadA (0x06)
        nonce = os.urandom(16)
        uuid_bytes = UUID(ACCOUNT_UUID).bytes
        encrypted_nonce = g20c_encrypt(enc_key, nonce)
        payload_a = uuid_bytes + b"\x00\x00" + encrypted_nonce
        print("Sending PayloadA (0x06)...")
        await send_msg(0x06, payload_a)

        # Wait for PayloadB (0x07)
        print("Waiting for PayloadB (0x07)...")
        payload_b = await wait_msg(0x07, timeout=15.0)
        print(f"PayloadB received: {len(payload_b)} bytes")
        
        iv = payload_b[2:18]
        ct = payload_b[18:50]
        mac_sig = payload_b[50:82]
        expected_sig = hmac.new(enc_key, ct, hashlib.sha256).digest()
        if not hmac.compare_digest(mac_sig, expected_sig):
            print("ERROR: PayloadB HMAC verification failed! Invalid LTK!")
            return False
        print("PayloadB HMAC Verified successfully!")

        dec = _aes_cbc_decrypt(enc_key, iv, ct)
        device_nonce = dec[16:32]
        print(f"Decrypted device challenge: {device_nonce.hex()}")

        # Send PayloadC (0x08)
        payload_c = b"\x00\x00" + g20c_encrypt(enc_key, device_nonce)
        print("Sending PayloadC (0x08)...")
        await send_msg(0x08, payload_c)

        # Wait for Connection Established (0x26)
        print("Waiting for 0x26 Connection Established...")
        await wait_msg(0x26, timeout=15.0)
        print(">>> DYSON AUTHENTICATION SUCCESSFUL! Connection Established! <<<")

        # Read states
        p_val = await client.read_gatt_char(BLE_POWER_UUID)
        b_val = await client.read_gatt_char(BLE_BRIGHTNESS_LUMENS_UUID)
        c_val = await client.read_gatt_char(BLE_COLOR_TEMP_UUID)
        power_st = bool(p_val and p_val[0] != 0)
        lumens = int.from_bytes(b_val[:2], "little") if len(b_val) >= 2 else 0
        kelvin = int.from_bytes(c_val[:2], "little") if len(c_val) >= 2 else 0
        print(f"Current State: Power={'ON' if power_st else 'OFF'} ({p_val.hex()}), Brightness={lumens} lm, Kelvin={kelvin} K")
        return True

if __name__ == "__main__":
    asyncio.run(run_test())
