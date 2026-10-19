# MikroTik IP Whitelist Service

Layanan HTTP sederhana, aman, dan *production-ready* yang dibangun dengan Go untuk memungkinkan karyawan remote mendaftarkan atau memperpanjang masa berlaku IP publik mereka ke firewall `address-list` MikroTik RouterOS (`remote-whitelist`).

## Fitur Utama

- **Web Portal UI Interaktif (HTMX)**: Antarmuka web modern, cepat, dan responsif dengan tema korporat PT Jagat Teknologi Indonesia. Mendukung auto-deteksi IP & hostname klien, pendaftaran/perpanjangan masa aktif IP, toggle izin Winbox, switching loading overlay, notifikasi toast, serta visualisasi tabel address-list MikroTik secara live.
- **Otomatisasi Whitelist**: Menambahkan IP baru dengan timeout terbatas atau memperpanjang masa berlaku jika IP sudah ada (`POST /v1/whitelist` atau via Web UI).
- **Identifikasi Hostname Target**: Komentar entri MikroTik disimpan dengan format `wl|<nama_hostname_target>` yang diambil dari parameter `hostname` klien, hasil resolusi reverse DNS IP target, atau fallback ke IP target jika tidak ditemukan.
- **Autentikasi Bearer Token**: Mengamankan endpoint `/v1/whitelist` dengan Bearer Token (`Authorization: Bearer <token>`) yang diverifikasi dengan constant-time comparison (bebas timing attack). Endpoint `/healthz` tetap terbuka untuk health probe.
- **Auto-Unblock dari Abuse List**: Jika IP target terdaftar di address-list `port-forward-abuse`, entri tersebut otomatis dihapus dari list abuse sebelum didaftarkan ke `remote-whitelist`.
- **Akses Layanan Winbox (Opsional)**: Dengan menyertakan parameter `winbox` di body request (`POST`), IP target otomatis ditambahkan ke daftar alamat yang diizinkan pada service Winbox MikroTik (`/ip service set [find name=winbox] address=([get [find name=winbox] address],<target_ip>/32)`). Pada `DELETE`, parameter `winbox` akan menghapus IP dari service Winbox.
- **Pembersihan Bersih**: Menghapus IP dari whitelist (`DELETE /v1/whitelist`) hanya jika entri dibuat oleh sistem (berawalan komentar `wl|`), sehingga entri manual admin terlindungi.
- **Validasi IP Ketat**:
  - Menghapus trailing whitespace/newline (output umum `curl https://ifconfig.me`).
  - Menolak IP kosong, malformed, private (RFC 1918), loopback, link-local, CGNAT (`100.64.0.0/10`), multicast, unspecified (`0.0.0.0`), dan IP publik kantor sendiri (`OFFICE_PUBLIC_IPS`).
  - Mendukung IPv4 secara default (IPv6 di balik flag `ALLOW_IPV6`).
- **Resilience MikroTik**:
  - Re-use koneksi TCP port 8728 secara aman (concurrency-safe via mutex).
  - Timeout 5 detik per perintah dan *automatic reconnect/retry* sekali jika koneksi terputus.
  - Kredensial MikroTik dan detail internal tidak pernah bocor ke klien (error MikroTik diterjemahkan menjadi `ERROR internal (req=<id>)` status 502).
- **Audit Logging**: `log/slog` berformat JSON terstruktur mencatat request ID, aksi (`whitelist_add`, `whitelist_extend`, `whitelist_remove`, `rejected`), IP target, client proxy source IP (`X-Real-IP` / `X-Forwarded-For`), User-Agent, dan durasi eksekusi tanpa mencatat kredensial.
- **Dual Output**: Respons default berupa teks satu baris (`text/plain`), serta mendukung output JSON jika request menyertakan header `Accept: application/json`.
- **Health Check**: Endpoint `GET /healthz` untuk probe liveness/readiness yang memverifikasi koneksi aktif ke MikroTik.

---

## Arsitektur Sistem

```
+-------------------+       +-----------------------+       +------------------------+       +-------------------+
|  Remote Employee  | ----> | Reverse Proxy Manager | ----> |  wlservice (Go HTTP)   | ----> | MikroTik RouterOS |
|  (curl / script)  | HTTPS | (NPM / Nginx / Caddy) | HTTP  | 127.0.0.1:8080         | API   | Port 8728 (LAN)   |
+-------------------+       +-----------------------+       +------------------------+       +-------------------+
```

- **Reverse Proxy**: Menangani SSL/TLS, autentikasi (jika ada), rate limiting, serta meneruskan header `X-Real-IP` atau `X-Forwarded-For`.
- **wlservice**: Berjalan di LAN kantor, mendengarkan hanya di `127.0.0.1` atau IP internal, dan berkomunikasi langsung dengan MikroTik melalui RouterOS API (port 8728).

---

## Struktur Direktori

```
.
├── cmd/
│   └── wlservice/
│       └── main.go           # Entrypoint utama aplikasi
├── internal/
│   ├── config/               # Parser & validator konfigurasi env
│   ├── httpserver/           # HTTP router, middleware, handlers & unit tests
│   ├── ipcheck/              # Validasi IP dan filter subnet terlarang
│   └── mikrotik/             # Client RouterOS API v7 & mock untuk testing
├── scripts/
│   ├── wl.sh                 # Helper script Bash (Linux/macOS)
│   └── wl.ps1                # Helper script PowerShell (Windows)
├── mikrotik-setup.rsc        # Skrip konfigurasi awal RouterOS v7
├── go.mod
├── go.sum
└── README.md
```

---

## Konfigurasi Lingkungan (Environment Variables)

Aplikasi membaca konfigurasi dari environment variables. Tersedia template [`.env.example`](file:///home/xsliearn/jti/whitelist-mikrotik/.env.example) yang dapat disalin:
```bash
cp .env.example .env
```

| Variabel | Tipe | Default | Wajib | Keterangan |
|---|---|---|---|---|
| `LISTEN_ADDR` | String | `127.0.0.1:8080` | Tidak | Alamat bind HTTP server (gunakan IP lokal/loopback). |
| `MIKROTIK_HOST` | String | - | **Ya** | Alamat IP LAN dari router MikroTik (contoh: `192.168.88.1`). |
| `MIKROTIK_PORT` | Integer | `8728` | Tidak | Port RouterOS API plaintext. |
| `MIKROTIK_USER` | String | - | **Ya** | Username akun API MikroTik khusus layanan ini. |
| `MIKROTIK_PASSWORD`| String | - | **Ya** | Password akun API MikroTik. |
| `AUTH_BEARER_TOKEN` | String | `""` | Tidak | Token Bearer untuk memproteksi endpoint API `/v1/whitelist` dan Web UI jika password tidak diset. |
| `WEB_ADMIN_USERNAME`| String | `admin` | Tidak | Username administrator untuk login Web UI Portal. |
| `WEB_ADMIN_PASSWORD`| String | `AUTH_BEARER_TOKEN` | Tidak | Password login Web UI (dapat berupa string atau hash PBKDF2). Default mewarisi `AUTH_BEARER_TOKEN`. |
| `WHITELIST_LIST_NAME` | String | `remote-whitelist` | Tidak | Nama firewall address-list target di MikroTik. |
| `PORT_FORWARD_ABUSE_LIST_NAME` | String | `port-forward-abuse` | Tidak | Nama firewall address-list deteksi abuse di MikroTik (otomatis dibersihkan saat whitelist). |
| `WHITELIST_TTL` | String | `8h` | Tidak | Masa berlaku IP di MikroTik (format RouterOS: `8h`, `12h`, `1d`). |
| `OFFICE_PUBLIC_IPS` | String | `""` | Tidak | Daftar IP atau subnet publik kantor (dipisahkan koma) untuk ditolak agar tidak sengaja di-whitelist. |
| `ALLOW_IPV6` | Boolean | `false` | Tidak | Set `true` untuk mengizinkan alamat IPv6 publik. |
| `TZ` | String | `Asia/Jakarta` | Tidak | Zona waktu untuk kalkulasi timestamp kedaluwarsa. |

---

## Build dan Kompilasi

Memerlukan Go 1.22 atau lebih baru.

```bash
# Download dependencies
go mod download

# Jalankan seluruh unit test
go test -v ./...

# Build binary mandiri (stripped symbols)
CGO_ENABLED=0 go build -ldflags="-s -w" -o wlservice ./cmd/wlservice
```

---

## Setup MikroTik (RouterOS v7)

Jalankan skrip yang telah disediakan di router Anda via Terminal Winbox atau SSH:

1. Buka file `mikrotik-setup.rsc`.
2. Sesuaikan nilai `<IP_SERVER_APLIKASI>` dan `<PASSWORD_KUAT>`.
3. Import atau jalankan skrip di terminal MikroTik:

```routeros
/import file-name=mikrotik-setup.rsc
```

Ringkasan keamanan konfigurasi MikroTik:
- Grup user `api-whitelist` hanya memiliki policy `api,read,write` (tanpa `winbox`, `ssh`, `ftp`, `policy`).
- User dibatasi hanya dapat login dari IP server aplikasi (`address=<IP_SERVER>/32`).
- Service API `port 8728` hanya dibuka ke IP server aplikasi, dan `api-ssl` dimatikan jika tidak dipakai.
- Input rule firewall memblokir akses port 8728 dari interface WAN.
- Rule firewall forward hanya membuka layanan internal yang dibutuhkan kantor (Web, VPN, dll.), **TIDAK PERNAH** membuka Winbox/SSH/Webfig router ke publik.

---

## Deployment Systemd (Linux Non-Root)

1. Buat user dan grup sistem khusus non-root:
   ```bash
   sudo useradd -r -s /bin/false wlservice
   ```

2. Salin binary ke `/usr/local/bin/`:
   ```bash
   sudo cp wlservice /usr/local/bin/wlservice
   sudo chmod 755 /usr/local/bin/wlservice
   ```

3. Buat file environment `/etc/wlservice/wlservice.env`:
   ```bash
   sudo mkdir -p /etc/wlservice
   sudo nano /etc/wlservice/wlservice.env
   ```
   Isi file dengan:
   ```ini
   LISTEN_ADDR=127.0.0.1:8080
   MIKROTIK_HOST=192.168.88.1
   MIKROTIK_PORT=8728
   MIKROTIK_USER=wl-service
   MIKROTIK_PASSWORD=GantiDenganPasswordRahasiaAnda
   WHITELIST_LIST_NAME=remote-whitelist
   PORT_FORWARD_ABUSE_LIST_NAME=port-forward-abuse
   WHITELIST_TTL=8h
   OFFICE_PUBLIC_IPS=203.0.113.100,198.51.100.0/24
   ALLOW_IPV6=false
   TZ=Asia/Jakarta
   ```
   Kunci hak akses file env agar hanya bisa dibaca root dan user wlservice:
   ```bash
   sudo chown -R root:wlservice /etc/wlservice
   sudo chmod 640 /etc/wlservice/wlservice.env
   ```

4. Buat systemd service `/etc/systemd/system/wlservice.service`:
   ```ini
   [Unit]
   Description=MikroTik IP Whitelist Service
   After=network.target

   [Service]
   Type=simple
   User=wlservice
   Group=wlservice
   EnvironmentFile=/etc/wlservice/wlservice.env
   ExecStart=/usr/local/bin/wlservice
   Restart=always
   RestartSec=5s

   # Hardening Keamanan
   NoNewPrivileges=true
   ProtectSystem=strict
   ProtectHome=true
   PrivateTmp=true
   PrivateDevices=true
   ProtectKernelTunables=true
   ProtectControlGroups=true
   CapabilityBoundingSet=

   [Install]
   WantedBy=multi-user.target
   ```

5. Aktifkan dan jalankan service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now wlservice
   sudo systemctl status wlservice
   ```

---

## Konfigurasi Reverse Proxy Manager

### 1. Nginx / Nginx Proxy Manager (NPM)

Tambahkan konfigurasi location pada server block domain publik Anda (misal `https://wl.contoh.co.id`):

```nginx
server {
    server_name wl.contoh.co.id;
    listen 443 ssl http2;

    # SSL Certificates dikelola oleh Let's Encrypt / Proxy Manager
    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    # Client body limit 10 KB (layanan membatasi maksimal 1 KB)
    client_max_body_size 10k;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;

        # Teruskan IP asli klien
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeout proxy
        proxy_connect_timeout 5s;
        proxy_read_timeout 15s;
        proxy_send_timeout 15s;
    }
}
```

### 2. Caddy Server

```caddy
wl.contoh.co.id {
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Real-IP {remote_host}
    }
}
```

---

## Penggunaan Klien

### 1. Menggunakan Web Portal Dashboard (Browser)

Buka browser Anda dan akses alamat portal:
```
http://<ip-server>:8080/
```
Fitur Web Portal:
- **Deteksi Otomatis**: Mendeteksi IP publik/klien dan hostname perangkat pengguna secara otomatis.
- **Interaksi Instan dengan HTMX**:
  - Tombol **"Aktifkan Whitelist"** / **"Perpanjang"** untuk mendaftarkan IP ke MikroTik RouterOS.
  - Kartu toggle **"Akses Winbox"** untuk mengizinkan atau mencabut akses port Winbox 8291.
  - Tombol **"Hapus Whitelist"** untuk membatalkan pendaftaran.
- **Switching Overlay**: Animasi loading dan konfirmasi perpindahan status mirip dashboard ISP Switcher JTI.
- **Tabel Live Firewall**: Menampilkan daftar seluruh IP yang sedang aktif ter-whitelist lengkap dengan sisa masa berlaku (timeout) dan filter pencarian real-time.
- **Autentikasi Terintegrasi**: Jika `AUTH_BEARER_TOKEN` diaktifkan, portal menyediakan dialog input token yang tersimpan di cookie browser.

### 2. Menggunakan Helper Script

#### Linux & macOS (`scripts/wl.sh`)
```bash
# Daftarkan IP publik ke whitelist
./scripts/wl.sh on

# Daftarkan IP publik ke whitelist SEKALIGUS allow akses Winbox
./scripts/wl.sh on --winbox

# Hapus IP publik dari whitelist (dan dari Winbox jika --winbox disertakan)
./scripts/wl.sh off --winbox

# Menggunakan URL service custom dan Bearer token
./scripts/wl.sh on https://wl.contoh.co.id "token_anda" --winbox

# Atau atur via environment variables:
export WL_SERVICE_URL="https://wl.contoh.co.id"
export WL_AUTH_TOKEN="token_anda"
export WL_WINBOX=true
./scripts/wl.sh on
```

#### Windows PowerShell (`scripts/wl.ps1`)
```powershell
# Daftarkan IP publik ke whitelist
.\scripts\wl.ps1 on

# Daftarkan IP publik ke whitelist SEKALIGUS allow akses Winbox
.\scripts\wl.ps1 on -Winbox

# Hapus IP publik dari whitelist (dan dari Winbox jika -Winbox disertakan)
.\scripts\wl.ps1 off -Winbox

# Menggunakan URL service custom dan Bearer token
.\scripts\wl.ps1 on -ServiceUrl "https://wl.contoh.co.id" -AuthToken "token_anda" -Winbox

# Atau atur via environment variable:
$env:WL_AUTH_TOKEN = "token_anda"
$env:WL_WINBOX = "true"
.\scripts\wl.ps1 on
```

### 2. Menggunakan Perintah Manual `curl`

#### Mendaftarkan / Memperpanjang IP (POST)
- **Linux / macOS (Deteksi IP & Hostname Otomatis)**:
  ```bash
  # Whitelist standar
  curl -sS -H "Authorization: Bearer <TOKEN>" \
    -d "ip=$(curl -s https://ifconfig.me)" \
    -d "hostname=$(hostname 2>/dev/null || uname -n)" \
    https://wl.contoh.co.id/v1/whitelist

  # Whitelist + Allow Winbox
  curl -sS -H "Authorization: Bearer <TOKEN>" \
    -d "ip=$(curl -s https://ifconfig.me)" \
    -d "hostname=$(hostname 2>/dev/null || uname -n)" \
    -d "winbox" \
    https://wl.contoh.co.id/v1/whitelist
  ```
- **Windows (PowerShell - Deteksi IP & Hostname Otomatis)**:
  ```powershell
  # Whitelist + Allow Winbox
  curl.exe -sS -H "Authorization: Bearer <TOKEN>" `
    -d "ip=$(curl.exe -s https://ifconfig.me)" `
    -d "hostname=$env:COMPUTERNAME" `
    -d "winbox" `
    https://wl.contoh.co.id/v1/whitelist
  ```
- **Menggunakan Body JSON**:
  ```bash
  curl -sS -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" \
    -d "{\"ip\": \"$(curl -s https://ifconfig.me)\", \"hostname\": \"$(hostname 2>/dev/null || uname -n)\", \"winbox\": true}" \
    https://wl.contoh.co.id/v1/whitelist
  ```
- **Contoh Respons (text/plain)**:
  ```text
  OK ip=180.252.167.103 expires=2026-10-18T03:00:00+07:00 winbox=allowed
  ```
- **Respons JSON (dengan `Accept: application/json`)**:
  ```json
  {
    "status": "ok",
    "ip": "180.252.167.103",
    "hostname": "laptop-engineer",
    "expires": "2026-10-18T03:00:00+07:00",
    "action": "added",
    "winbox_allowed": true,
    "req": "a1b2c3d4e5f60708"
  }
  ```

#### Menghapus IP dari Whitelist (DELETE)
- **Hanya Hapus dari Whitelist**:
  ```bash
  curl -sS -H "Authorization: Bearer <TOKEN>" -X DELETE -d "ip=$(curl -s https://ifconfig.me)" https://wl.contoh.co.id/v1/whitelist
  ```
- **Hapus dari Whitelist dan Winbox**:
  ```bash
  curl -sS -H "Authorization: Bearer <TOKEN>" -X DELETE -d "ip=$(curl -s https://ifconfig.me)" -d "winbox" https://wl.contoh.co.id/v1/whitelist
  ```
- **Contoh Respons (text/plain)**:
  ```text
  OK ip=180.252.167.103 action=removed winbox=removed
  ```

#### Health Check
```bash
curl -i https://wl.contoh.co.id/healthz
```
Respons HTTP `200 OK`:
```text
ok
```
