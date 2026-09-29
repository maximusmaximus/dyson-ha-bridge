# dyson-ha-bridge

Native host BLE bridge daemon for the **Dyson Lightcycle Morph Desk Lamp** (`CD06 / Type 552 Variant A`) to **Home Assistant**, featuring full cryptographic LTK authentication, real-time bidirectional WebSocket synchronization, echo suppression, and circadian time-of-day lighting automation.

Runs natively on the Windows 11 host (`MCMINI`) to bypass VirtualBox VM Bluetooth passthrough limitations.

---

## Features

- **Proprietary Dyson BLE `g20c` Handshake:** Implements the full challenge-response authentication with AES-128-CBC encryption, HMAC-SHA256 validation, and HKDF session key derivation from the Long Term Key (LTK).
- **WinRT Fragmentation Pacing:** Handles Dyson's custom 20-byte packet fragmentation with 30ms pacing delays for robust transmission across Windows WinRT BLE stacks.
- **Zero-Firewall Outbound WebSocket:** Opens a reverse WebSocket client to Home Assistant (`ws://<ha-ip>:8123/api/websocket`), bypassing Windows Defender Firewall restrictions on inbound ports without requiring admin elevation.
- **Echo Suppression Architecture:** Tracks state changes and suppresses echo loops when executing HA-initiated commands. Intermediate BLE ramping notifications are debounced during transitions.
- **PIR Motion Sensor Integration:** Captures hardware motion events from the lamp's embedded passive infrared sensor (`2dd11008`) and pushes them to `binary_sensor.dyson_desk_lamp_motion`.
- **Circadian Time-of-Day Activation:**
  - **Morning ($< 12\text{ PM}$):** $6500\text{ K}$ (Coolest daylight white for alertness).
  - **Middle of the Day ($12\text{ PM} - \text{sunset}$):** $4000\text{ K}$ (Balanced neutral white).
  - **After Dark (sunset until dawn):** $2700\text{ K}$ (Warmest setting, down to $1800\text{ K}$ in ambient docked mode).
  - Physical button activations directly evaluate and apply circadian presets.
- **24/7 Watchdog & Windows Startup:** Auto-restarting watchdog (`start_bridge.ps1`) monitored via single-instance mutex and configured in Windows Startup (`DysonBridge.vbs`).

---

## Installation & Configuration

1. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

2. Copy `config.example.yaml` to `config.yaml` and configure your credentials:
   ```yaml
   bridge:
     entity_id: light.dyson_desk_lamp
     http_port: 8089
     motion_entity_id: binary_sensor.dyson_desk_lamp_motion

   device:
     account_uuid: "YOUR_DYSON_ACCOUNT_UUID"
     ltk: "YOUR_LONG_TERM_KEY_HEX"
     mac: "C4:5F:0E:CE:34:0E"
     serial: "E5M-US-NFA0140A"

   home_assistant:
     token: "YOUR_HA_LONG_LIVED_ACCESS_TOKEN"
     url: "http://192.168.50.106:8123"
   ```

3. Start the watchdog service:
   ```powershell
   pwsh -File start_bridge.ps1
   ```

4. For auto-start on Windows reboot, place `DysonBridge.vbs` in your Windows Startup directory (`shell:startup`):
   ```vbs
   Set objShell = CreateObject("WScript.Shell")
   objShell.Run "powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File ""C:\Users\worki\.gemini\antigravity\scratch\dyson-ha-bridge\start_bridge.ps1""", 0, False
   Set objShell = Nothing
   ```

---

## Hardware Characteristics

| UUID | Function | Type |
| :--- | :--- | :--- |
| `2dd10011-1c37-452d-8979-d1b4a787d0a4` | Auth & Product Info Channel | Write / Notify |
| `2dd11001-1c37-452d-8979-d1b4a787d0a4` | Power Control (0x00 / 0x01) | Read / Write / Notify |
| `2dd11002-1c37-452d-8979-d1b4a787d0a4` | Brightness (100 - 1000 Lumens, uint16 LE) | Read / Write / Notify |
| `2dd11003-1c37-452d-8979-d1b4a787d0a4` | Color Temp (1800 - 6500 Kelvin, uint16 LE) | Read / Write / Notify |
| `2dd11008-1c37-452d-8979-d1b4a787d0a4` | PIR Motion Detection Event | Notify |
| `2dd10021-1c37-452d-8979-d1b4a787d0a4` | Manual Control Mode Override | Write |
