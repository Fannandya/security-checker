# Deployment Guide: OSC Web Scanner di Proxmox LXC 100150

Dokumen ini adalah panduan langkah demi langkah implementasi hosting OSC Web Scanner pada LXC `100150`, konfigurasi Ingress Gateway Traefik v3 (`10080`), Cloudflare Tunnel, dan GitHub Actions Runner lokal sesuai standar [`docs/HOMELAB-SSOT.md`](file:///Users/macbookpro/tama/projek/security-checker/docs/HOMELAB-SSOT.md).

---

## 1. Spesifikasi Infrastruktur

| Parameter | Nilai |
|---|---|
| **LXC ID** | `100150` |
| **Hostname** | `osc-scanner` |
| **IP Address** | `192.168.0.150/24` (Statis) |
| **Default Gateway** | `192.168.0.1` |
| **OS Template** | Ubuntu 24.04 LTS / Debian 12 (Unprivileged Container) |
| **Port Internal** | `8000` (FastAPI / Uvicorn) |
| **Domain Publik** | `osc.yowman.my.id` |
| **Gateway Ingress** | LXC `10080` (`192.168.0.80`) — Traefik v3.1 + Cloudflare Tunnel |
| **Runner CI/CD** | GitHub Actions Self-Hosted Runner (Systemd service di LXC `100150`) |

---

## 2. Langkah Setup di Proxmox VE Host

### 2.1 Buat LXC Container 100150
Jalankan di shell Proxmox VE (`192.168.0.10`):

```bash
pct create 100150 local:vztmpl/ubuntu-24.04-standard_24.04-2_amd64.tar.zst \
  --hostname osc-scanner \
  --cores 2 \
  --memory 2048 \
  --swap 1024 \
  --net0 name=eth0,bridge=vmbr0,ip=192.168.0.150/24,gw=192.168.0.1 \
  --storage local-lvm \
  --rootfs volume=local-lvm:20 \
  --features nesting=1,keyctl=1 \
  --unprivileged 1 \
  --start 1
```

> [!NOTE]
> Flag `--features nesting=1,keyctl=1` wajib aktif agar Docker daemon dapat berjalan di dalam unprivileged LXC container.

---

## 3. Langkah Setup di Dalam LXC 100150

Masuk ke container:
```bash
pct enter 100150
```

### 3.1 Jalankan Skrip Provisioning Otomatis
Salin dan jalankan skrip [`deploy/setup-lxc-100150.sh`](file:///Users/macbookpro/tama/projek/security-checker/deploy/setup-lxc-100150.sh):
```bash
bash deploy/setup-lxc-100150.sh
```
Skrip ini akan:
1. Memperbarui paket OS (`apt-get update`).
2. Menginstal Docker Engine & Docker Compose plugin.
3. Membuat user `runner` dan memasukkannya ke grup `docker`.
4. Menyiapkan direktori aplikasi `/opt/osc/output`.
5. Mengonfigurasi firewall UFW agar port `8000` dapat diakses dari gateway `192.168.0.80`.

### 3.2 Daftarkan GitHub Actions Self-Hosted Runner
1. Buka repository GitHub Anda di browser:
   `Settings` -> `Actions` -> `Runners` -> Klik **New self-hosted runner**.
2. Masuk sebagai user `runner` di LXC:
   ```bash
   su - runner
   cd /home/runner/actions-runner
   ```
3. Unduh dan ekstrak runner binary:
   ```bash
   curl -o actions-runner-linux-x64.tar.gz -L https://github.com/actions/runner/releases/download/v2.321.0/actions-runner-linux-x64-2.321.0.tar.gz
   tar xzf ./actions-runner-linux-x64.tar.gz
   ```
4. Hubungkan runner ke repository (gunakan token dari GitHub):
   ```bash
   ./config.sh --url https://github.com/<OWNER>/<REPO> \
               --token <GITHUB_RUNNER_REGISTRATION_TOKEN> \
               --name lxc-100150-runner \
               --labels self-hosted,linux,x64,lxc100150 \
               --unattended
   ```
5. Instal dan jalankan runner sebagai background service systemd (kembali ke root):
   ```bash
   exit # kembali ke root
   cd /home/runner/actions-runner
   ./svc.sh install runner
   ./svc.sh start
   ./svc.sh status
   ```

---

## 4. Konfigurasi Traefik di Gateway Ingress (LXC 10080)

Pada LXC `10080` (`192.168.0.80`), tambahkan konfigurasi dinamis File Provider Traefik:

1. Buat file `/opt/ingress/dynamic/osc.yml`:
   ```yaml
   http:
     routers:
       osc-web-router:
         rule: "Host(`osc.yowman.my.id`)"
         entryPoints:
           - web
         service: osc-web-service

     services:
       osc-web-service:
         loadBalancer:
           servers:
             - url: "http://192.168.0.150:8000"
           passHostHeader: true
   ```
2. Traefik otomatis mendeteksi file baru karena `--providers.file.watch=true`.
3. Periksa log Traefik:
   ```bash
   docker logs --tail 50 traefik
   ```

---

## 5. Konfigurasi Cloudflare Tunnel & Zero Trust Access

Sesuai pola SSOT homelab:

1. **Cloudflare Zero Trust Dashboard**:
   - Buka **Networks** -> **Tunnels** -> Pilih Tunnel yang aktif untuk homelab.
   - Tambahkan **Public Hostname**:
     - Subdomain: `osc`
     - Domain: `yowman.my.id`
     - Type: `HTTP`
     - URL: `traefik:80` (karena Traefik berada dalam network bridge Docker yang sama dengan cloudflared) atau `192.168.0.80:80`.
2. **Proteksi Akses (Cloudflare Access / Zero Trust)**:
   - Buka **Access** -> **Applications** -> Klik **Add an application** -> **Self-hosted**.
   - Application name: `OSC Web Scanner`
   - Application domain: `osc.yowman.my.id`
   - Buat policy: Izinkan hanya email Anda (misal `One-time PIN` atau Google OAuth).
   - Simpan. Sekarang hanya Anda yang dapat mengakses antarmuka testing web scanner.

---

## 6. Verifikasi Operasional & Health Check

1. **Health Check Lokal dari LXC 100150:**
   ```bash
   curl -i http://127.0.0.1:8000/api/health
   # Respons: HTTP/1.1 200 OK {"status":"ok","version":"2.5.0","scanner":"EnhancedOSCScanner"}
   ```

2. **Pemeriksaan dari Gateway LXC 10080:**
   ```bash
   curl -i http://192.168.0.150:8000/api/health
   ```

3. **Pemeriksaan Melalui Domain Publik:**
   Buka `https://osc.yowman.my.id/` di browser. Setelah lolos autentikasi Cloudflare Zero Trust, dashboard OSC Web Scanner akan tampil secara interaktif.
