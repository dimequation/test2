#!/data/data/com.termux/files/usr/bin/bash

RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
YELLOW=$'\033[1;33m'
BOLD=$'\033[1m'
RESET=$'\033[0m'

green() { printf '%s%s%s\n' "$GREEN" "$1" "$RESET"; }
red() { printf '%s%s%s\n' "$RED" "$1" "$RESET"; }
yellow() { printf '%s%s%s\n' "$YELLOW" "$1" "$RESET"; }

missing=()
command -v termux-wifi-connectioninfo >/dev/null 2>&1 || missing+=(termux-api)
command -v jq >/dev/null 2>&1 || missing+=(jq)
command -v ip >/dev/null 2>&1 || missing+=(iproute2)
command -v ping >/dev/null 2>&1 || missing+=(inetutils)
command -v traceroute >/dev/null 2>&1 || missing+=(traceroute)
command -v nmap >/dev/null 2>&1 || missing+=(nmap)
command -v upnpc >/dev/null 2>&1 || missing+=(miniupnpc)
command -v curl >/dev/null 2>&1 || missing+=(curl)
command -v openssl >/dev/null 2>&1 || missing+=(openssl-tool)
command -v dig >/dev/null 2>&1 || missing+=(dnsutils)
command -v python >/dev/null 2>&1 || missing+=(python)
command -v timeout >/dev/null 2>&1 || missing+=(coreutils)

if ((${#missing[@]} > 0)); then
    printf 'Установка: %s\n' "${missing[*]}"
    if ! pkg update -y >/dev/null 2>&1 ||
       ! pkg install -y "${missing[@]}" >/dev/null 2>&1; then
        red 'ПАКЕТЫ: ОШИБКА'
        exit 1
    fi
fi

SERVER_INPUT="${1:-}"
PORT_INPUT="${2:-}"
SERVER_INPUT="${SERVER_INPUT//$'\r'/}"
PORT_INPUT="${PORT_INPUT//$'\r'/}"
SERVER_HOST="$SERVER_INPUT"
SERVER_TARGET="$SERVER_INPUT"
PORT=''
PORT_SOURCE='DEFAULT'

if [[ -z "$PORT_INPUT" && "$SERVER_INPUT" =~ ^([^:]+):([0-9]{1,5})$ ]]; then
    SERVER_HOST="${BASH_REMATCH[1]}"
    SERVER_TARGET="$SERVER_HOST"
    PORT_INPUT="${BASH_REMATCH[2]}"
fi

if [[ "$PORT_INPUT" =~ ^[0-9]{1,5}$ ]] &&
   ((10#$PORT_INPUT >= 1 && 10#$PORT_INPUT <= 65535)); then
    PORT=$((10#$PORT_INPUT))
    PORT_SOURCE='EXPLICIT'
fi

if [[ -z "$PORT" && -n "$SERVER_HOST" ]]; then
    SRV_RECORD="$(dig +short SRV "_minecraft._tcp.$SERVER_HOST" 2>/dev/null | sort -n | head -n 1)"
    if [[ -n "$SRV_RECORD" ]]; then
        PORT="$(printf '%s\n' "$SRV_RECORD" | awk '{print $3}')"
        SERVER_TARGET="$(printf '%s\n' "$SRV_RECORD" | awk '{print $4}' | sed 's/\.$//')"
        PORT_SOURCE='SRV'
    fi
fi

if [[ -z "$PORT" ]]; then
    PORT=25565
    PORT_SOURCE='DEFAULT'
fi

SERVER_IP=''
STATUS_OK=0
STATUS_VERSION=''
STATUS_PROTOCOL=''
STATUS_PLAYERS=''
STATUS_LATENCY=''
STATUS_MOTD=''
STATUS_ERROR=''

if [[ -n "$SERVER_TARGET" ]]; then
    SERVER_IP="$(dig +short A "$SERVER_TARGET" 2>/dev/null | head -n 1)"
    STATUS_OUTPUT="$(timeout 10 python - "$SERVER_TARGET" "$SERVER_HOST" "$PORT" <<'PY_STATUS'
import json
import socket
import struct
import sys
import time

connect_host, handshake_host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])

def varint(value):
    value &= 0xffffffff
    out = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            byte |= 0x80
        out.append(byte)
        if not value:
            return bytes(out)

def read_varint(sock):
    value = 0
    for shift in range(0, 35, 7):
        byte = sock.recv(1)
        if not byte:
            raise EOFError("eof")
        value |= (byte[0] & 0x7f) << shift
        if not byte[0] & 0x80:
            return value
    raise ValueError("varint")

def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("eof")
        data.extend(chunk)
    return bytes(data)

def component_text(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(component_text(item) for item in value)
    if isinstance(value, dict):
        result = str(value.get("text", ""))
        return result + component_text(value.get("extra", []))
    return str(value)

try:
    start = time.perf_counter()
    with socket.create_connection((connect_host, port), timeout=5) as sock:
        sock.settimeout(5)
        host = handshake_host.encode("utf-8")
        handshake = b"\x00" + varint(767) + varint(len(host)) + host + struct.pack(">H", port) + b"\x01"
        sock.sendall(varint(len(handshake)) + handshake)
        sock.sendall(b"\x01\x00")
        read_varint(sock)
        packet_id = read_varint(sock)
        if packet_id != 0:
            raise ValueError("packet_id")
        payload_size = read_varint(sock)
        payload = read_exact(sock, payload_size)
        latency = round((time.perf_counter() - start) * 1000, 1)
        data = json.loads(payload.decode("utf-8"))
        version = data.get("version", {})
        players = data.get("players", {})
        motd = component_text(data.get("description", ""))
        motd = motd.replace("|", "/").replace("\r", " ").replace("\n", " ")
        print("OK|{}|{}|{}/{}|{}|{}".format(
            str(version.get("name", "")).replace("|", "/"),
            version.get("protocol", ""),
            players.get("online", ""),
            players.get("max", ""),
            latency,
            motd,
        ))
except Exception as error:
    print("ERROR|{}".format(str(error).replace("|", "/").replace("\n", " ")))
PY_STATUS
)"

    if [[ "$STATUS_OUTPUT" == OK\|* ]]; then
        STATUS_OK=1
        IFS='|' read -r _ STATUS_VERSION STATUS_PROTOCOL STATUS_PLAYERS STATUS_LATENCY STATUS_MOTD <<< "$STATUS_OUTPUT"
    else
        STATUS_ERROR="${STATUS_OUTPUT#ERROR|}"
    fi
fi

WIFI_OK=0
BSSID_OK=0
BSSID_LOCAL=0
GW_LOCAL=0
SSID_WINDOWS=0
FALLBACK=0
TRACE_ANOMALY=0
IGD=0
GW_WINDOWS=0
IPV6_GLOBAL=0
ROUTER_BANNER=0
ROUTER_SPOOF=0

WIFI="$(timeout 8 termux-wifi-connectioninfo 2>&1 || true)"
if printf '%s' "$WIFI" | jq -e . >/dev/null 2>&1; then
    WIFI_OK=1
    PHONE_IP="$(printf '%s' "$WIFI" | jq -r '.ip // empty')"
    SSID="$(printf '%s' "$WIFI" | jq -r '.ssid // empty')"
    BSSID="$(printf '%s' "$WIFI" | jq -r '.bssid // empty' | tr '[:upper:]' '[:lower:]')"
    FREQUENCY="$(printf '%s' "$WIFI" | jq -r '.frequency_mhz // empty')"
    RSSI="$(printf '%s' "$WIFI" | jq -r '.rssi // empty')"
else
    PHONE_IP=''
    SSID=''
    BSSID=''
    FREQUENCY=''
    RSSI=''
fi

if [[ -z "$PHONE_IP" ]]; then
    PHONE_CIDR="$(ip -o -4 addr show dev wlan0 2>/dev/null | awk 'NR==1 {print $4}')"
    PHONE_IP="${PHONE_CIDR%%/*}"
fi

if [[ "$BSSID" =~ ^[0-9a-f]{2}(:[0-9a-f]{2}){5}$ ]] &&
   [[ "$BSSID" != '02:00:00:00:00:00' ]]; then
    BSSID_OK=1
    FIRST="${BSSID%%:*}"
    (( (16#$FIRST & 2) != 0 )) && BSSID_LOCAL=1
fi

UPPER_SSID="${SSID^^}"
[[ "$UPPER_SSID" =~ ^(WIN-|DESKTOP-|LAPTOP-|DIRECT-) ]] && SSID_WINDOWS=1

ROUTES="$(ip -4 route show table all 2>/dev/null || true)"
GW="$(printf '%s\n' "$ROUTES" | awk '/^default / && /dev wlan0/ {for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')"
SUBNET="$(printf '%s\n' "$ROUTES" | awk '/dev wlan0/ && /scope link/ && $1~/\// {print $1; exit}')"

if [[ -z "$GW" || -z "$SUBNET" ]]; then
    if [[ "$PHONE_IP" =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+$ ]]; then
        BASE="${BASH_REMATCH[1]}"
        GW="${GW:-$BASE.1}"
        SUBNET="${SUBNET:-$BASE.0/24}"
        FALLBACK=1
    else
        red 'СЕТЬ: ОШИБКА'
        exit 1
    fi
fi

GW_PING="$(ping -c 2 -W 2 "$GW" 2>/dev/null || true)"
GW_TTL="$(printf '%s\n' "$GW_PING" | grep -Eio 'ttl=[0-9]+' | head -n 1 | cut -d= -f2)"
NEIGH="$(ip neigh show "$GW" 2>/dev/null || true)"
GW_MAC="$(printf '%s\n' "$NEIGH" | awk '{for(i=1;i<=NF;i++) if($i=="lladdr"){print $(i+1); exit}}' | tr '[:upper:]' '[:lower:]')"

if [[ "$GW_MAC" =~ ^[0-9a-f]{2}(:[0-9a-f]{2}){5}$ ]]; then
    FIRST="${GW_MAC%%:*}"
    (( (16#$FIRST & 2) != 0 )) && GW_LOCAL=1
fi

TEST_OUTPUT="$(nmap -Pn -n -sT --max-retries 0 --host-timeout 4s -p "$PORT" 192.0.2.1 198.51.100.1 203.0.113.1 2>/dev/null || true)"
OPEN_COUNT="$(printf '%s\n' "$TEST_OUTPUT" | awk -v p="$PORT" '$1==p"/tcp" && $2=="open"{n++} END{print n+0}')"

if ((PORT < 65535)); then
    ADJACENT=$((PORT + 1))
else
    ADJACENT=$((PORT - 1))
fi

ADJ_OUTPUT="$(nmap -Pn -n -sT --max-retries 0 --host-timeout 4s -p "$ADJACENT" 192.0.2.1 2>/dev/null || true)"
ADJ_OPEN="$(printf '%s\n' "$ADJ_OUTPUT" | awk -v p="$ADJACENT" '$1==p"/tcp" && $2=="open"{n++} END{print n+0}')"

TRACE="$(traceroute -4 -n -q 1 -w 2 -m 3 1.1.1.1 2>/dev/null || true)"
FIRST_HOP="$(printf '%s\n' "$TRACE" | awk '$1=="1" {print $2; exit}')"
[[ "$FIRST_HOP" == '*' ]] && FIRST_HOP=''
[[ -n "$FIRST_HOP" && "$FIRST_HOP" != "$GW" ]] && TRACE_ANOMALY=1

SCAN="$(nmap -sn -n "$SUBNET" 2>/dev/null || true)"
DEVICE_COUNT="$(printf '%s\n' "$SCAN" | grep -c '^Nmap scan report for' || true)"

UPNP="$(timeout 8 upnpc -s 2>&1 || true)"
printf '%s\n' "$UPNP" | grep -q 'Found valid IGD' && IGD=1
UPNP_LOCATION="$(printf '%s\n' "$UPNP" | grep -Eio 'https?://[^ ]+' | head -n 1)"
UPNP_IP="$(printf '%s\n' "$UPNP_LOCATION" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)"
[[ -n "$UPNP_IP" && "$UPNP_IP" != "$GW" ]] && ROUTER_SPOOF=1

GW_SERVICES="$(nmap --unprivileged -Pn -n -sT -sV --version-light --max-retries 0 --host-timeout 12s -p 80,135,139,443,445,2869,5357,5358,5985 "$GW" 2>/dev/null || true)"
GW_OPEN_PORTS="$(printf '%s\n' "$GW_SERVICES" | awk '$2=="open" {sub("/tcp","",$1); ports=ports (ports?",":"") $1} END{print ports}')"
printf '%s\n' "$GW_SERVICES" | grep -Eiq 'Microsoft|Windows|msrpc|wsdapi|httpapi' && GW_WINDOWS=1

HTTP_META="$(timeout 7 curl --noproxy '*' -sk -D - -o /dev/null --connect-timeout 3 --max-time 7 "http://$GW/" 2>/dev/null || true)"
HTTP_LOCATION="$(printf '%s\n' "$HTTP_META" | grep -i '^location:' | head -n 1)"
HTTP_LOCATION_IP="$(printf '%s\n' "$HTTP_LOCATION" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)"
[[ -n "$HTTP_LOCATION_IP" && "$HTTP_LOCATION_IP" != "$GW" ]] && ROUTER_SPOOF=1

TLS_META="$(timeout 7 openssl s_client -connect "$GW:443" -servername "$GW" </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer 2>/dev/null || true)"
ROUTER_META="$GW_SERVICES
$HTTP_META
$TLS_META
$UPNP"
printf '%s\n' "$ROUTER_META" | grep -Eiq 'TP-Link|Keenetic|RouterOS|OpenWrt|Huawei|ZTE|MikroTik|lighttpd|uhttpd|miniupnp|Samba smbd' && ROUTER_BANNER=1

if ((ROUTER_BANNER == 1)) && ((BSSID_LOCAL == 1 || GW_LOCAL == 1)); then
    ROUTER_SPOOF=1
fi

ip -6 addr show dev wlan0 scope global 2>/dev/null | grep -q 'inet6 ' && IPV6_GLOBAL=1

HOTSPOT_SCORE=0
ROUTER_SCORE=0
((SSID_WINDOWS == 1)) && HOTSPOT_SCORE=$((HOTSPOT_SCORE + 3))
((BSSID_LOCAL == 1)) && HOTSPOT_SCORE=$((HOTSPOT_SCORE + 2))
((GW_LOCAL == 1)) && HOTSPOT_SCORE=$((HOTSPOT_SCORE + 2))
((DEVICE_COUNT <= 1)) && HOTSPOT_SCORE=$((HOTSPOT_SCORE + 1))
((GW_WINDOWS == 1)) && HOTSPOT_SCORE=$((HOTSPOT_SCORE + 2))

if [[ -n "$BSSID" && -n "$GW_MAC" && "$BSSID" == "$GW_MAC" ]]; then
    HOTSPOT_SCORE=$((HOTSPOT_SCORE + 1))
fi

((BSSID_OK == 1 && BSSID_LOCAL == 0)) && ROUTER_SCORE=$((ROUTER_SCORE + 2))
((GW_LOCAL == 0 && -n "$GW_MAC")) && ROUTER_SCORE=$((ROUTER_SCORE + 2))
((IGD == 1)) && ROUTER_SCORE=$((ROUTER_SCORE + 2))
((DEVICE_COUNT > 1)) && ROUTER_SCORE=$((ROUTER_SCORE + 1))
[[ -n "$FIRST_HOP" && "$FIRST_HOP" == "$GW" ]] && ROUTER_SCORE=$((ROUTER_SCORE + 1))

FAKER_NETWORK_SCORE=0
if ((HOTSPOT_SCORE >= 4)); then
    ((TRACE_ANOMALY == 1)) && FAKER_NETWORK_SCORE=$((FAKER_NETWORK_SCORE + 2))
    [[ "$GW_TTL" == '64' ]] && FAKER_NETWORK_SCORE=$((FAKER_NETWORK_SCORE + 1))
    ((ROUTER_SPOOF == 1)) && FAKER_NETWORK_SCORE=$((FAKER_NETWORK_SCORE + 3))
fi

echo
printf '%s=== РЕЗУЛЬТАТ ===%s\n' "$BOLD" "$RESET"
printf 'Сервер: %s\n' "${SERVER_HOST:-не указан}"
printf 'Target: %s\n' "${SERVER_TARGET:-не указан}"
printf 'Server IP: %s\n' "${SERVER_IP:-не найден}"
printf 'Порт: %s\n' "$PORT"
printf 'Источник порта: %s\n' "$PORT_SOURCE"
printf 'Minecraft status: %s\n' "$([[ "$STATUS_OK" == 1 ]] && printf OK || printf ERROR)"
printf 'Версия: %s\n' "${STATUS_VERSION:-неизвестна}"
printf 'Protocol: %s\n' "${STATUS_PROTOCOL:-неизвестен}"
printf 'Игроки: %s\n' "${STATUS_PLAYERS:-неизвестно}"
printf 'Latency: %s ms\n' "${STATUS_LATENCY:-неизвестна}"
printf 'MOTD: %s\n' "${STATUS_MOTD:-неизвестен}"
printf 'IP: %s\n' "${PHONE_IP:-неизвестен}"
printf 'Шлюз: %s\n' "$GW"
printf 'Подсеть: %s\n' "$SUBNET"
printf 'SSID: %s\n' "${SSID:-неизвестен}"
printf 'BSSID: %s\n' "${BSSID:-неизвестен}"
printf 'MAC шлюза: %s\n' "${GW_MAC:-неизвестен}"
printf 'Частота: %s MHz\n' "${FREQUENCY:-неизвестна}"
printf 'RSSI: %s dBm\n' "${RSSI:-неизвестен}"
printf 'Устройств: %s\n' "$DEVICE_COUNT"
printf 'Первый hop: %s\n' "${FIRST_HOP:-нет ответа}"
printf 'TTL шлюза: %s\n' "${GW_TTL:-нет ответа}"
printf 'Порты шлюза: %s\n' "${GW_OPEN_PORTS:-нет}"
printf 'HTTP Location IP: %s\n' "${HTTP_LOCATION_IP:-нет}"
printf 'UPnP Location IP: %s\n' "${UPNP_IP:-нет}"
printf 'TEST-NET: %s/3\n' "$OPEN_COUNT"
printf 'Hotspot score: %s\n' "$HOTSPOT_SCORE"
printf 'Router score: %s\n' "$ROUTER_SCORE"
printf 'Faker network score: %s\n' "$FAKER_NETWORK_SCORE"

green 'ПАКЕТЫ: OK'

if [[ "$PORT_SOURCE" == 'EXPLICIT' || "$PORT_SOURCE" == 'SRV' ]]; then
    green "ПОРТ: $PORT ($PORT_SOURCE)"
else
    yellow "ПОРТ: $PORT (DEFAULT)"
fi

if [[ -z "$SERVER_HOST" ]]; then
    yellow 'MINECRAFT STATUS: СЕРВЕР НЕ УКАЗАН'
elif ((STATUS_OK == 1)); then
    green 'MINECRAFT STATUS: OK'
else
    red "MINECRAFT STATUS: ${STATUS_ERROR:-ОШИБКА}"
fi

if ((WIFI_OK == 1 && BSSID_OK == 1)); then
    green 'TERMUX API: OK'
else
    red 'TERMUX API: НЕТ WIFI-ДАННЫХ'
fi

if ((FALLBACK == 0)); then
    green 'МАРШРУТ: ОПРЕДЕЛЁН'
else
    yellow 'МАРШРУТ: РАСЧЁТ .1/24'
fi

if ((BSSID_LOCAL == 1)); then
    red 'BSSID: LOCAL'
elif ((BSSID_OK == 1)); then
    green 'BSSID: GLOBAL'
else
    yellow 'BSSID: НЕИЗВЕСТЕН'
fi

if ((GW_LOCAL == 1)); then
    red 'MAC ШЛЮЗА: LOCAL'
elif [[ -n "$GW_MAC" ]]; then
    green 'MAC ШЛЮЗА: GLOBAL'
else
    yellow 'MAC ШЛЮЗА: НЕИЗВЕСТЕН'
fi

if ((TRACE_ANOMALY == 1)); then
    red 'TRACEROUTE: АНОМАЛИЯ'
elif [[ -n "$FIRST_HOP" ]]; then
    green 'TRACEROUTE: НОРМА'
else
    yellow 'TRACEROUTE: НЕТ ОТВЕТА'
fi

if ((IGD == 1)); then
    green 'UPNP ROUTER: ДА'
else
    yellow 'UPNP ROUTER: НЕТ ОТВЕТА'
fi

if ((GW_WINDOWS == 1)); then
    red 'ШЛЮЗ WINDOWS: ДА'
else
    yellow 'ШЛЮЗ WINDOWS: НЕ ОБНАРУЖЕН'
fi

if ((IPV6_GLOBAL == 1)); then
    green 'IPV6: GLOBAL'
else
    yellow 'IPV6: НЕТ GLOBAL'
fi

if ((OPEN_COUNT == 3 && ADJ_OPEN == 0)); then
    red 'FAKER REDIRECT: ОБНАРУЖЕН'
elif ((ROUTER_SPOOF == 1 && HOTSPOT_SCORE >= 4)); then
    red 'FAKER ROUTER SPOOF: ПОДОЗРЕНИЕ'
elif ((FAKER_NETWORK_SCORE >= 2)); then
    red 'FAKER: ПОДОЗРЕНИЕ'
else
    yellow 'FAKER: НЕОПРЕДЕЛЕНО'
fi

if ((WIFI_OK == 0)); then
    yellow 'HOTSPOT: НЕДОСТАТОЧНО ДАННЫХ'
elif ((HOTSPOT_SCORE >= 4)); then
    red 'HOTSPOT: ОБНАРУЖЕН'
elif ((ROUTER_SCORE >= 5)); then
    green 'HOTSPOT: НЕ ОБНАРУЖЕН'
else
    yellow 'HOTSPOT: НЕОПРЕДЕЛЕНО'
fi
