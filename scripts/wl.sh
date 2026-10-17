#!/usr/bin/env bash
#
# Helper script untuk mendaftarkan atau menghapus IP publik dari remote-whitelist.
# Penggunaan:
#   ./wl.sh on [service_url] [auth_token] [--winbox]
#   ./wl.sh off [service_url] [auth_token] [--winbox]
#
set -euo pipefail

ACTION="${1:-}"
SERVICE_URL="${2:-${WL_SERVICE_URL:-https://wl.contoh.co.id}}"
AUTH_TOKEN="${3:-${WL_AUTH_TOKEN:-${AUTH_BEARER_TOKEN:-}}}"

if [[ "$ACTION" != "on" && "$ACTION" != "off" ]]; then
    echo "Penggunaan: $0 {on|off} [service_url] [auth_token] [--winbox]"
    echo ""
    echo "Perintah:"
    echo "  on   - Tambah atau perpanjang IP publik ke remote-whitelist"
    echo "  off  - Hapus IP publik dari remote-whitelist"
    echo ""
    echo "Opsi:"
    echo "  --winbox       - Izinkan juga IP untuk mengakses layanan Winbox MikroTik"
    echo ""
    echo "Environment Variable:"
    echo "  WL_SERVICE_URL - URL whitelist service (default: https://wl.contoh.co.id)"
    echo "  WL_AUTH_TOKEN  - Bearer token autentikasi (opsional jika server mengaktifkan bearer)"
    echo "  WL_HOSTNAME    - Hostname custom (default: otomatis dari hostname sistem)"
    echo "  WL_WINBOX      - Set true / 1 untuk selalu mengizinkan akses Winbox"
    exit 1
fi

ENABLE_WINBOX=false
if [[ "${WL_WINBOX:-}" == "true" || "${WL_WINBOX:-}" == "1" ]]; then
    ENABLE_WINBOX=true
fi
for arg in "$@"; do
    if [[ "$arg" == "--winbox" || "$arg" == "winbox" ]]; then
        ENABLE_WINBOX=true
    fi
done

echo "Mendeteksi IP publik via https://ifconfig.me (timeout 5s)..."
if ! IP=$(curl -sS --max-time 5 https://ifconfig.me 2>/dev/null) || [[ -z "${IP//[[:space:]]/}" ]]; then
    echo "ERROR: Gagal mengambil IP publik dari https://ifconfig.me (koneksi timeout atau gagal)." >&2
    echo "Permintaan ke whitelist service TIDAK dikirim." >&2
    exit 1
fi

# Bersihkan whitespace/newline
IP=$(echo "$IP" | tr -d '[:space:]')
echo "IP Publik terdeteksi: $IP"

detect_hostname() {
    if [[ -n "${WL_HOSTNAME:-}" ]]; then
        echo "$WL_HOSTNAME"
        return
    fi
    local h=""
    # 1. Try hostname command
    if command -v hostname >/dev/null 2>&1; then
        h=$(hostname 2>/dev/null || true)
    fi
    # 2. Try uname -n
    if [[ -z "$h" || "$h" == "localhost" || "$h" == "localhost.localdomain" ]] && command -v uname >/dev/null 2>&1; then
        h=$(uname -n 2>/dev/null || true)
    fi
    # 3. Try /etc/hostname
    if [[ -z "$h" || "$h" == "localhost" || "$h" == "localhost.localdomain" ]] && [[ -f /etc/hostname ]]; then
        h=$(head -n 1 /etc/hostname 2>/dev/null || true)
    fi
    # 4. Try $HOSTNAME env variable
    if [[ -z "$h" || "$h" == "localhost" || "$h" == "localhost.localdomain" ]] && [[ -n "${HOSTNAME:-}" ]]; then
        h="$HOSTNAME"
    fi
    # 5. Fallback to user
    if [[ -z "$h" || "$h" == "localhost" || "$h" == "localhost.localdomain" ]]; then
        h="${USER:-$(whoami 2>/dev/null || id -un 2>/dev/null || echo "")}"
    fi
    h=$(echo "$h" | tr -d '[:space:]')
    echo "$h"
}

CLIENT_HOSTNAME=$(detect_hostname)
if [[ -n "$CLIENT_HOSTNAME" ]]; then
    echo "Hostname terdeteksi otomatis: $CLIENT_HOSTNAME"
fi

if [[ "$ENABLE_WINBOX" == "true" ]]; then
    echo "Akses Winbox: aktif (--winbox)"
fi

TARGET_ENDPOINT="${SERVICE_URL%/}/v1/whitelist"

AUTH_HEADER=()
if [[ -n "$AUTH_TOKEN" ]]; then
    AUTH_HEADER=(-H "Authorization: Bearer $AUTH_TOKEN")
fi

if [[ "$ACTION" == "on" ]]; then
    echo "Mengirim permintaan whitelist (POST)..."
    POST_HEADERS=("${AUTH_HEADER[@]}")
    if [[ -n "$CLIENT_HOSTNAME" ]]; then
        POST_HEADERS+=(-H "X-Hostname: $CLIENT_HOSTNAME")
    fi
    POST_ARGS=(-d "ip=$IP")
    if [[ -n "$CLIENT_HOSTNAME" ]]; then
        POST_ARGS+=(-d "hostname=$CLIENT_HOSTNAME")
    fi
    if [[ "$ENABLE_WINBOX" == "true" ]]; then
        POST_ARGS+=(-d "winbox")
    fi
    curl -sS "${POST_HEADERS[@]}" "${POST_ARGS[@]}" "$TARGET_ENDPOINT"
    echo ""
elif [[ "$ACTION" == "off" ]]; then
    echo "Mengirim permintaan penghapusan whitelist (DELETE)..."
    DELETE_ARGS=(-d "ip=$IP")
    if [[ "$ENABLE_WINBOX" == "true" ]]; then
        DELETE_ARGS+=(-d "winbox")
    fi
    curl -sS -X DELETE "${AUTH_HEADER[@]}" "${DELETE_ARGS[@]}" "$TARGET_ENDPOINT"
    echo ""
fi
