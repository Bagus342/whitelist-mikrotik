#!/usr/bin/env bash
#
# Helper script untuk mendaftarkan atau menghapus IP publik dari remote-whitelist.
# Penggunaan:
#   ./wl.sh on [service_url] [auth_token]
#   ./wl.sh off [service_url] [auth_token]
#
set -euo pipefail

ACTION="${1:-}"
SERVICE_URL="${2:-${WL_SERVICE_URL:-https://wl.contoh.co.id}}"
AUTH_TOKEN="${3:-${WL_AUTH_TOKEN:-${AUTH_BEARER_TOKEN:-}}}"

if [[ "$ACTION" != "on" && "$ACTION" != "off" ]]; then
    echo "Penggunaan: $0 {on|off} [service_url] [auth_token]"
    echo ""
    echo "Perintah:"
    echo "  on   - Tambah atau perpanjang IP publik ke remote-whitelist"
    echo "  off  - Hapus IP publik dari remote-whitelist"
    echo ""
    echo "Environment Variable:"
    echo "  WL_SERVICE_URL - URL whitelist service (default: https://wl.contoh.co.id)"
    echo "  WL_AUTH_TOKEN  - Bearer token autentikasi (opsional jika server mengaktifkan bearer)"
    exit 1
fi

echo "Mendeteksi IP publik via https://ifconfig.me (timeout 5s)..."
if ! IP=$(curl -sS --max-time 5 https://ifconfig.me 2>/dev/null) || [[ -z "${IP//[[:space:]]/}" ]]; then
    echo "ERROR: Gagal mengambil IP publik dari https://ifconfig.me (koneksi timeout atau gagal)." >&2
    echo "Permintaan ke whitelist service TIDAK dikirim." >&2
    exit 1
fi

# Bersihkan whitespace/newline
IP=$(echo "$IP" | tr -d '[:space:]')
echo "IP Publik terdeteksi: $IP"

TARGET_ENDPOINT="${SERVICE_URL%/}/v1/whitelist"

AUTH_HEADER=()
if [[ -n "$AUTH_TOKEN" ]]; then
    AUTH_HEADER=(-H "Authorization: Bearer $AUTH_TOKEN")
fi

if [[ "$ACTION" == "on" ]]; then
    echo "Mengirim permintaan whitelist (POST)..."
    curl -sS "${AUTH_HEADER[@]}" -d "ip=$IP" "$TARGET_ENDPOINT"
    echo ""
elif [[ "$ACTION" == "off" ]]; then
    echo "Mengirim permintaan penghapusan whitelist (DELETE)..."
    curl -sS -X DELETE "${AUTH_HEADER[@]}" -d "ip=$IP" "$TARGET_ENDPOINT"
    echo ""
fi
