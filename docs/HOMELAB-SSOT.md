# HOMELAB-SSOT.md
## Single Source of Truth — Proxmox, CI/CD, Cloudflare Tunnel, Traefik, dan Deployment Aplikasi

> **Status dokumen:** Draft awal berdasarkan keputusan percakapan dan dokumen konfigurasi `gateway-ingress`.
>
> **Tujuan:** Menjadi acuan utama bagi developer dan AI agent saat merancang, membangun, menguji, men-deploy, serta memelihara proyek di homelab.
>
> **Aturan penting:** Bedakan kondisi aktual, rancangan target, contoh, dan informasi yang belum dikonfirmasi. Jangan menganggap placeholder atau contoh sebagai konfigurasi aktual.

---

## 1. Tujuan dan cakupan

Dokumen ini mencakup:

- Proxmox VE dan pembagian LXC.
- LXC `10080` sebagai ingress gateway.
- Cloudflare Tunnel dan Traefik v3.
- Routing dari gateway ke aplikasi pada LXC/VM lain.
- GitHub Actions self-hosted runner untuk CI/CD multi-repository.
- GitHub Container Registry (GHCR) sebagai registry image.
- Standar deployment berbasis SSH.
- Keamanan, secret management, verifikasi, backup, rollback, dan aturan operasional AI agent.

Dokumen ini bukan pengganti konfigurasi aktual pada server. Jika kondisi server berbeda dari dokumen, periksa kondisi aktual dan perbarui dokumen setelah perubahan disetujui.

## 2. Status informasi

### 2.1 Kondisi dan keputusan yang sudah diketahui

| Item | Nilai/status | Keterangan |
|---|---|---|
| Hypervisor | Proxmox VE | Aktif digunakan |
| RAM host | 32 GB | Informasi dari pemilik homelab |
| Gateway LXC ID | `10080` | Sudah ada |
| Gateway hostname | `gateway-ingress` | Sesuai dokumen konfigurasi gateway |
| Gateway IP | `192.168.0.80` | Statis, sesuai dokumen gateway |
| Default gateway jaringan | `192.168.0.1` | Jaringan `/24` |
| Jaringan internal | `192.168.0.0/24` | Perlu diverifikasi pada konfigurasi aktual Proxmox/router |
| IP host Proxmox | `192.168.0.10` | Tercatat dalam dokumen gateway |
| Ingress stack | Docker Compose | Berjalan di LXC `10080` |
| Reverse proxy | Traefik `v3.1` | Entry point HTTP pada port `80` |
| Tunnel | `cloudflared` | Berjalan sebagai service Docker |
| Docker network gateway | `web-gateway` | External bridge network |
| Direktori stack ingress | `/opt/ingress` | Sesuai dokumen gateway |
| Direktori konfigurasi dinamis | `/opt/ingress/dynamic` | Dipantau oleh Traefik File Provider |
| GitHub Actions runner | Belum dibuat/dikonfirmasi | Targetnya LXC khusus |
| Strategi runner | Satu runner pusat, satu job pada satu waktu | Untuk repository yang diizinkan |
| Deployment | SSH dari runner ke LXC target | Pilihan awal yang disepakati |
| Registry image | GHCR | Target rancangan CI/CD |
| IP runner | TBD | Belum ditentukan |
| IP LXC aplikasi | TBD | Belum ditentukan |
| Domain utama | TBD | Belum dikonfirmasi |

### 2.2 Topologi target

Topologi yang dituju memisahkan ingress, CI/CD, dan aplikasi produksi:

```text
Internet
   |
Cloudflare Edge
   |
Cloudflare Tunnel
   |
LXC 10080 — gateway-ingress
  - cloudflared
  - Traefik
   |
   +---------------------------> LXC aplikasi A
   +---------------------------> LXC aplikasi B
   +---------------------------> LXC aplikasi C
                                      ^
                                      |
GitHub -> GitHub Actions -> Runner LXC khusus -> GHCR
                                      |
                                      +-- SSH deployment ke LXC target
```

Contoh pembagian tanggung jawab:

| Komponen | Tanggung jawab |
|---|---|
| LXC `10080` | Cloudflare Tunnel, Traefik, routing ingress |
| LXC runner (ID/IP TBD) | Menjalankan job CI/CD, build/test image, push image ke GHCR, memulai deployment |
| LXC aplikasi (ID/IP TBD) | Menjalankan aplikasi produksi dan Docker Compose |
| GHCR | Menyimpan image container hasil build |
| GitHub repository | Menyimpan source code, workflow, dan dokumentasi proyek |

**Penting:** ID `100`, `101`, `102`, `103` yang muncul dalam percakapan sebelumnya hanyalah contoh. Jangan menganggap ID tersebut sudah tersedia atau ditetapkan.

## 3. LXC 10080 — Ingress Gateway

### 3.1 Peran

LXC `10080` adalah pintu masuk bersama untuk trafik HTTP publik yang diteruskan melalui Cloudflare Tunnel. Traefik menentukan tujuan berdasarkan hostname/router, lalu meneruskan request ke layanan terkait.

Aplikasi di LXC lain tidak perlu memiliki tunnel sendiri selama dapat dijangkau dari gateway dan routing Cloudflare diarahkan ke Traefik.

### 3.2 Komponen dan lokasi

| Item | Nilai |
|---|---|
| LXC ID | `10080` |
| Hostname | `gateway-ingress` |
| IP | `192.168.0.80` |
| Gateway jaringan | `192.168.0.1` |
| Stack | `/opt/ingress/docker-compose.yml` |
| Environment file | `/opt/ingress/.env` |
| Dynamic config directory | `/opt/ingress/dynamic` |
| Docker network | `web-gateway` |
| Traefik image | `traefik:v3.1` |
| Cloudflared image | `cloudflare/cloudflared:latest` |
| Traefik HTTP entry point | `:80` |
| Dashboard | `http://192.168.0.80:8080/dashboard/` — hanya akses privat yang diizinkan |

### 3.3 Konfigurasi stack yang tercatat

File `/opt/ingress/.env` menggunakan variabel:

```ini
TUNNEL_TOKEN=<CLOUDFLARE_TUNNEL_TOKEN>
```

Jangan pernah memasukkan nilai token sebenarnya ke repository, dokumen yang dibagikan, log, atau prompt agent. File `.env` harus dibatasi aksesnya dan tidak di-commit.

Docker Compose yang tercatat dalam dokumen konfigurasi gateway:

```yaml
services:
  traefik:
    image: traefik:v3.1
    container_name: traefik
    restart: unless-stopped
    command:
      - "--api.dashboard=true"
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--providers.file.directory=/etc/traefik/dynamic"
      - "--providers.file.watch=true"
      - "--entrypoints.web.address=:80"
    ports:
      - "80:80"
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /opt/ingress/dynamic:/etc/traefik/dynamic:ro
    networks:
      - web-gateway

  cloudflared:
    image: cloudflare/cloudflared:latest
    container_name: cloudflared
    restart: unless-stopped
    command: tunnel --no-autoupdate run --token ${TUNNEL_TOKEN}
    networks:
      - web-gateway
    depends_on:
      - traefik

networks:
  web-gateway:
    external: true
```

Network dibuat sebagai external bridge network:

```bash
docker network create web-gateway
```

Direktori dynamic config:

```bash
mkdir -p /opt/ingress/dynamic
```

> **Catatan:** Ini adalah rekaman konfigurasi yang diberikan, bukan instruksi untuk menimpa stack yang sedang berjalan. Sebelum mengubahnya, periksa konfigurasi aktual dan lakukan backup. Image `cloudflare/cloudflared:latest` dapat berubah mengikuti rilis; evaluasi kebijakan pinning versi sebelum perubahan produksi.

### 3.4 Keamanan gateway — wajib ditinjau

Konfigurasi di atas mencatat `--api.insecure=true` dan pemetaan port `8080:8080`. Dashboard harus benar-benar dibatasi ke jaringan privat/Tailscale dan tidak boleh dipublikasikan sebagai hostname publik tanpa autentikasi dan perlindungan yang sesuai.

Sebelum mengubah konfigurasi dashboard, periksa cara akses aktual dan aturan firewall. Jangan mengekspos dashboard hanya dengan mengandalkan anggapan bahwa port tersebut privat.

Mount Docker socket meskipun menggunakan `:ro` tetap perlu diperlakukan sebagai akses sensitif terhadap Docker API. Jangan memperluas akses ini ke container atau agent yang tidak tepercaya.

## 4. Cloudflare Tunnel dan routing publik

### 4.1 Pola routing yang dituju

Semua hostname publik yang dikelola gateway diarahkan ke Traefik melalui satu tunnel:

```text
Public hostname
   -> Cloudflare Tunnel
   -> Traefik service pada jaringan Docker web-gateway, port 80
   -> Router Traefik berdasarkan Host header
   -> Aplikasi yang sesuai
```

Dokumen konfigurasi yang diberikan mencatat target service tunnel sebagai `http://traefik:80` (nama service/container dapat di-resolve pada Docker network yang sama).

**Jangan mengarahkan hostname publik langsung ke container aplikasi individual** jika aplikasi tersebut seharusnya mengikuti ingress gateway terpusat.

### 4.2 Domain dan hostname

Domain utama belum dikonfirmasi. Gunakan placeholder seperti `app.example.com` dalam contoh sampai domain aktual ditetapkan.

Untuk setiap aplikasi baru, dokumentasikan:
- Hostname publik.
- Target LXC dan IP privat.
- Port internal aplikasi.
- Protokol backend (HTTP atau HTTPS).
- Router/provider Traefik yang digunakan.
- Kebutuhan autentikasi, middleware, dan pembatasan akses.

### 4.3 TLS

Konfigurasi saat ini mencatat Traefik menerima HTTP pada port `80`, sementara terminasi HTTPS berada di Cloudflare Edge. Jangan mengubah asumsi TLS backend tanpa memeriksa konfigurasi Cloudflare Tunnel, mode SSL/TLS Cloudflare, dan kebutuhan aplikasi.

## 5. Traefik — routing layanan

Traefik dikonfigurasi menggunakan dua provider:
1. **Docker Provider** untuk container yang dapat ditemukan oleh Docker Engine yang dipantau Traefik.
2. **File Provider** untuk tujuan eksternal seperti LXC atau VM lain yang dijangkau melalui jaringan internal Proxmox.

### 5.1 Aplikasi dalam Docker Engine yang sama dengan Traefik

Untuk container yang memang berjalan pada Docker Engine yang sama dan bergabung dengan network `web-gateway`, gunakan label Traefik. Pola ini tidak otomatis membuat container pada Docker Engine di LXC lain dapat ditemukan.

Contoh pola label:

```yaml
services:
  app:
    image: ghcr.io/OWNER/REPOSITORY:COMMIT_SHA
    restart: unless-stopped
    networks:
      - web-gateway
      - internal-net
    labels:
      - "traefik.enable=true"
      - "traefik.docker.network=web-gateway"
      - "traefik.http.routers.my-service.rule=Host(`app.example.com`)"
      - "traefik.http.routers.my-service.entrypoints=web"
      - "traefik.http.services.my-service.loadbalancer.server.port=3000"

networks:
  web-gateway:
    external: true
  internal-net:
    driver: bridge
```

Ketentuan:
- Gunakan nama router/service yang unik.
- Tentukan port internal aplikasi dengan eksplisit.
- Jika service terhubung ke beberapa network, tetapkan `traefik.docker.network=web-gateway`.
- Jangan menambahkan host port binding hanya untuk membuat aplikasi bisa diakses Traefik jika koneksi privat melalui `web-gateway` sudah mencukupi.
- Jangan memasukkan database ke network publik/gateway kecuali ada kebutuhan yang ditinjau secara khusus.
- Variabel `OWNER`, `REPOSITORY`, `COMMIT_SHA`, hostname, dan port di atas adalah placeholder.

### 5.2 Aplikasi pada LXC atau VM terpisah — pola target utama

Untuk aplikasi pada LXC/VM lain, gunakan Traefik File Provider. Traefik mengakses IP privat dan port aplikasi melalui jaringan internal Proxmox; Docker Provider pada gateway tidak otomatis menemukan container di LXC lain.

Contoh `/opt/ingress/dynamic/external-services.yml`:

```yaml
http:
  routers:
    app-external-router:
      rule: "Host(`app.example.com`)"
      entryPoints:
        - web
      service: app-external-service

  services:
    app-external-service:
      loadBalancer:
        servers:
          - url: "http://192.168.0.X:3000"
```

Ganti `192.168.0.X`, port, hostname, dan nama router/service dengan nilai aktual sebelum menerapkan. Jangan deploy konfigurasi dengan placeholder yang belum diganti.

File Provider dikonfigurasi dengan:

```yaml
--providers.file.directory=/etc/traefik/dynamic
--providers.file.watch=true
```

Perubahan file di `/opt/ingress/dynamic` seharusnya dipantau oleh Traefik. Setelah perubahan, periksa log dan dashboard untuk memastikan router/service valid.

### 5.3 Persyaratan jaringan backend

- Aplikasi pada LXC target harus listen pada alamat yang dapat dijangkau dari gateway, bukan hanya `127.0.0.1`.
- IP target harus stabil (misalnya static IP atau DHCP reservation).
- Firewall harus mengizinkan koneksi dari gateway ke port aplikasi yang dibutuhkan.
- Port backend tidak perlu dibuka ke internet.
- Pilih HTTP atau HTTPS antara Traefik dan backend berdasarkan konfigurasi aplikasi; jangan menebak skema.
- Dokumentasikan IP, port, protokol, dan hostname untuk setiap route.

## 6. CI/CD — GitHub Actions, self-hosted runner, dan GHCR

### 6.1 Arsitektur yang disepakati

- Satu LXC khusus untuk self-hosted GitHub Actions runner.
- Satu runner pusat melayani repository yang diizinkan.
- Pada tahap awal, satu runner menjalankan satu job dalam satu waktu; job tambahan menunggu antrean.
- Runner melakukan build dan test, kemudian push image ke GHCR.
- Deployment dimulai oleh workflow melalui SSH ke LXC produksi yang sesuai.
- LXC produksi tidak memerlukan runner GitHub Actions masing-masing.

Runner LXC ID dan IP belum ditentukan. Jangan menetapkan nilai tanpa konfirmasi.

### 6.2 Alur standar

```text
Developer push/merge ke branch yang diizinkan
   -> GitHub Actions workflow
   -> self-hosted runner
   -> checkout source
   -> dependency install
   -> lint/test/build
   -> build Docker image
   -> tag image dengan commit SHA
   -> push image ke GHCR
   -> SSH ke LXC target
   -> pull image yang tepat
   -> docker compose up -d
   -> health check
   -> catat hasil deployment
```

Build/test yang gagal harus menghentikan workflow sebelum deployment. Image yang dibuat sebaiknya memiliki tag immutable berdasarkan commit SHA. Tag `latest` boleh digunakan sebagai convenience tag, tetapi jangan menjadi satu-satunya referensi deployment yang dapat dilacak.

### 6.3 Tanggung jawab masing-masing komponen

| Komponen | Tanggung jawab |
|---|---|
| GitHub repository | Source code, workflow, Dockerfile, Compose template, dokumentasi |
| GitHub Actions | Orkestrasi job |
| Self-hosted runner | Menjalankan job build/test/deployment yang diizinkan |
| GHCR | Menyimpan image hasil build |
| LXC produksi | Menarik image yang ditentukan dan menjalankan aplikasi |
| Traefik pada LXC `10080` | Meneruskan trafik ke hostname/IP/port aplikasi |

GHCR tidak otomatis memicu deployment hanya karena image baru di-push. Workflow harus menjalankan langkah deployment secara eksplisit atau mekanisme deployment terpisah harus dikonfigurasi.

### 6.4 Runner dan akses antar-LXC

- Runner harus dapat mengakses GitHub/GHCR dan SSH ke LXC target.
- Setiap repository hanya boleh menggunakan runner jika cakupan pendaftaran runner dan kebijakan repository mengizinkannya.
- Satu runner tidak berarti semua repository otomatis memiliki akses; konfigurasi runner dan izin GitHub tetap harus disetel.
- Gunakan user deployment khusus pada LXC target, dengan hak minimum yang dibutuhkan.
- Simpan private key dan token di GitHub Secrets atau mekanisme secret manager yang disetujui.
- Jangan menyimpan private key, token GHCR, token Cloudflare, password, atau file `.env` rahasia di repository.
- Hindari menjalankan workflow dari pull request yang tidak tepercaya pada runner yang memiliki akses ke produksi.
- Jangan menjalankan runner sebagai root jika tidak benar-benar diperlukan.
- Batasi akses jaringan dan kredensial runner; perlakukan workflow repository sebagai kode yang dapat dieksekusi.

### 6.5 Kerangka workflow

Workflow tiap repository harus disesuaikan dengan stack dan kebutuhan proyek. Kerangka tahapnya:

```yaml
name: Build and Deploy

on:
  push:
    branches:
      - main

permissions:
  contents: read
  packages: write

jobs:
  build-test-publish:
    runs-on: self-hosted
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      # Tambahkan setup runtime, install dependencies,
      # lint, test, dan build sesuai stack proyek.

      # Login ke GHCR dengan kredensial/token yang sesuai.
      # Build image dan beri tag berdasarkan commit SHA.
      # Push image ke GHCR.

  deploy:
    needs: build-test-publish
    runs-on: self-hosted
    steps:
      # Gunakan SSH key dari GitHub Secrets.
      # Deploy hanya ke target yang ditetapkan untuk repository ini.
      # Jalankan skrip deployment yang terdokumentasi.
      # Verifikasi health check dan laporkan hasilnya.
```

Kerangka ini sengaja tidak berisi perintah login/push/SSH yang siap jalan, karena nama image, akses registry, host target, secret names, user deployment, direktori aplikasi, dan health check belum ditetapkan. Agent wajib mengisi nilai berdasarkan konfigurasi proyek yang nyata dan tidak boleh menebaknya.

### 6.6 Standar tag image

Gunakan pola yang konsisten, misalnya:

```text
ghcr.io/<owner>/<repository>:<commit-sha>
```

Contoh di atas adalah format, bukan nama image aktual. Catat image tag yang di-deploy agar rollback dapat menunjuk versi yang spesifik.

## 7. Standar deployment aplikasi

Setiap aplikasi produksi sebaiknya memiliki:
- `Dockerfile` yang sesuai dengan stack.
- `compose.yaml` atau `docker-compose.yml`.
- `.env.example` berisi nama variabel tanpa secret.
- `.gitignore` yang mengecualikan `.env` dan file sensitif.
- Health check atau endpoint pemeriksaan kesehatan.
- Volume/storage yang eksplisit untuk data persisten.
- Kebijakan restart.
- Dokumentasi port internal dan hostname.
- Skrip deployment yang idempotent bila memungkinkan.
- Cara melihat log, melakukan rollback, dan memulihkan data.

### 7.1 Database dan data persisten

- Jangan menganggap data di writable layer container sebagai data persisten.
- Simpan database dan file pengguna pada volume atau storage yang direncanakan.
- Database sebaiknya berada pada network privat dan tidak diekspos ke internet secara langsung.
- Backup database dan file persisten harus diuji dengan prosedur restore.
- Jangan menjalankan migrasi database yang destruktif tanpa backup dan persetujuan.
- Jangan menghapus volume saat melakukan pembaruan aplikasi kecuali ada persetujuan eksplisit.

### 7.2 Health check, rollback, dan kegagalan

Sebelum deployment:
1. Pastikan build dan test berhasil.
2. Catat image yang sedang berjalan.
3. Pastikan variabel environment dan storage tersedia.
4. Pastikan target dan hostname sesuai.

Setelah deployment:
1. Pastikan container berjalan.
2. Periksa log.
3. Jalankan health check lokal dari target.
4. Verifikasi routing melalui Traefik.
5. Jika pemeriksaan gagal, jangan menyatakan deployment sukses.
6. Ikuti prosedur rollback yang sudah disetujui dan gunakan image tag sebelumnya yang diketahui baik.

Agent tidak boleh menghapus versi lama atau data persisten sebagai bagian dari cleanup tanpa memeriksa dampaknya.

## 8. Standar networking

### 8.1 Data jaringan yang tercatat

| Item | Nilai |
|---|---|
| Subnet | `192.168.0.0/24` |
| Default gateway | `192.168.0.1` |
| Proxmox host | `192.168.0.10` |
| Gateway LXC `10080` | `192.168.0.80` |
| Runner IP | TBD |
| App LXC IPs | TBD |

Alamat di atas berasal dari jawaban pemilik dan dokumen gateway. Verifikasi dengan konfigurasi aktual sebelum perubahan jaringan.

### 8.2 Aturan komunikasi

| Sumber | Tujuan | Jalur |
|---|---|---|
| Internet | Aplikasi publik | Cloudflare Tunnel -> Traefik -> aplikasi |
| Traefik | Aplikasi pada LXC lain | IP internal LXC dan port backend |
| Container satu Compose/network | Service lain | Docker internal DNS dan port internal |
| Runner | GitHub/GHCR | Koneksi keluar yang diperlukan |
| Runner | LXC target | SSH dengan kredensial terbatas |
| Laptop admin | Dashboard gateway | LAN/Tailscale saja, sesuai aturan akses |

Jangan mengasumsikan Docker network bridge dapat melintasi Docker Engine/LXC berbeda. Untuk LXC lain, gunakan alamat IP dan port pada jaringan internal kecuali arsitektur jaringan khusus telah dikonfigurasi dan didokumentasikan.

## 9. Kebijakan keamanan untuk AI agent

AI agent harus mematuhi aturan berikut:

1. **Jangan menebak kondisi aktual.** Periksa konfigurasi aktual jika akses tersedia; jika tidak, tandai `TBD` dan minta konfirmasi untuk keputusan yang berisiko.
2. **Jangan mengubah gateway secara sembarangan.** Sebelum mengubah LXC `10080`, backup file konfigurasi yang relevan dan jelaskan dampak pada semua aplikasi yang melewati gateway.
3. **Jangan mengekspos port aplikasi ke internet secara langsung** jika trafik seharusnya melalui Cloudflare Tunnel dan Traefik.
4. **Jangan mempublikasikan dashboard administrasi** (Traefik, Docker, Proxmox, database, dan sejenisnya) tanpa persetujuan eksplisit dan kontrol akses yang tepat.
5. **Jangan mencetak atau menyimpan secret** di source code, commit, dokumentasi publik, issue, atau log.
6. **Jangan menjalankan perintah destruktif tanpa persetujuan.** Termasuk penghapusan volume, database, direktori produksi, konfigurasi gateway, dan perubahan firewall berisiko.
7. **Gunakan least privilege.** Runner dan user deployment hanya memperoleh akses yang diperlukan.
8. **Jangan jalankan kode PR tidak tepercaya** pada runner yang memiliki akses ke secret atau produksi.
9. **Gunakan tag image yang dapat dilacak** dan jangan deploy image yang tidak diketahui asalnya.
10. **Lakukan verifikasi setelah perubahan** dan laporkan hasil aktual, bukan sekadar perintah yang dijalankan.
11. **Dokumentasikan perubahan** pada README proyek dan perbarui bagian terkait dalam SSOT jika perubahan memengaruhi infrastruktur bersama.
12. **Jangan menganggap contoh sebagai nilai final.** Ganti semua `TBD`, `example.com`, `OWNER`, `REPOSITORY`, `192.168.0.X`, dan placeholder lainnya sebelum menjalankan deployment.

## 10. Prosedur menambahkan proyek baru

Untuk setiap proyek baru:

1. Tentukan repository, stack, dan branch deployment.
2. Tentukan target LXC/VM, IP privat, hostname, port internal, dan kebutuhan storage.
3. Tentukan variabel environment; buat `.env.example` tanpa secret.
4. Siapkan Dockerfile dan Compose.
5. Tambahkan lint/test/build yang relevan.
6. Buat GitHub Actions workflow menggunakan runner pusat yang diizinkan.
7. Bangun image dan tag dengan commit SHA.
8. Push image ke GHCR dengan permission minimum.
9. Siapkan akses SSH terbatas ke target.
10. Buat skrip deployment yang menarik image yang tepat dan menjalankan Compose.
11. Tambahkan route Traefik:
    - gunakan Docker labels hanya jika container dapat ditemukan oleh Docker Provider gateway;
    - gunakan File Provider untuk aplikasi di LXC/VM lain.
12. Pastikan Cloudflare Tunnel mengarahkan hostname publik ke Traefik.
13. Verifikasi health check dan akses melalui hostname.
14. Dokumentasikan log, rollback, backup, dan pemulihan.
15. Perbarui inventaris layanan di bagian 12.

## 11. Troubleshooting ingress

### 11.1 Log

Pada LXC `10080`:

```bash
cd /opt/ingress
docker compose ps
docker compose logs --tail=200 traefik
docker compose logs --tail=200 cloudflared
```

### 11.2 Periksa Docker network

```bash
docker network inspect web-gateway
```

Gunakan pemeriksaan ini untuk layanan yang memang seharusnya bergabung ke network `web-gateway` pada Docker Engine gateway. Jangan mengharapkan container dari Docker Engine LXC lain muncul di daftar tersebut.

### 11.3 Dashboard Traefik

Dashboard yang tercatat:

```text
http://192.168.0.80:8080/dashboard/
```

Akses hanya melalui jalur privat yang diizinkan. Jika tidak dapat diakses, periksa status container, binding port, firewall, dan konektivitas LAN/Tailscale.

### 11.4 502 Bad Gateway atau 504 Gateway Timeout

Periksa secara berurutan:
1. Apakah aplikasi target berjalan?
2. Apakah IP target benar dan dapat dijangkau dari LXC `10080`?
3. Apakah aplikasi listen pada alamat yang dapat diakses dari jaringan?
4. Apakah port internal pada konfigurasi Traefik benar?
5. Apakah protokol backend (HTTP/HTTPS) benar?
6. Apakah firewall mengizinkan gateway mengakses port tersebut?
7. Untuk Docker Provider: apakah container terhubung ke `web-gateway`, `traefik.enable=true`, dan port label benar?
8. Untuk File Provider: apakah file YAML valid, berada di direktori yang benar, dan router/service muncul di log/dashboard?

## 12. Inventaris layanan dan keputusan tertunda

### 12.1 Inventaris awal

| Layanan | LXC/VM | IP | Domain/hostname | Port | Status |
|---|---|---|---|---|---|
| Cloudflare Tunnel | LXC `10080` | `192.168.0.80` | TBD | Keluar melalui tunnel | Sudah dikonfigurasi menurut dokumen |
| Traefik | LXC `10080` | `192.168.0.80` | Internal dashboard | `80`, `8080` | Sudah dikonfigurasi menurut dokumen |
| OSC Web Scanner & Testing UI | LXC `100150` | `192.168.0.150` | `osc.yowman.my.id` | `8000` | Siap di-deploy (FastAPI + Docker Compose) |
| GitHub Actions Runner (OSC) | LXC `100150` | `192.168.0.150` | N/A | Systemd service host | In-host runner bersama aplikasi OSC |


### 12.2 Keputusan yang masih harus dikonfirmasi

- [ ] Domain utama dan pola hostname.
- [ ] ID, OS, resource, dan IP LXC runner.
- [ ] ID, OS, resource, IP, dan peran LXC aplikasi.
- [ ] Nama/owner repository dan kebijakan akses runner.
- [ ] GHCR namespace dan kebijakan akses image.
- [ ] Nama GitHub Secrets yang akan digunakan (jangan simpan nilainya di dokumen).
- [ ] User SSH deployment dan lokasi direktori aplikasi pada setiap target.
- [ ] Kebijakan backup dan lokasi penyimpanan backup.
- [ ] Kebijakan health check dan rollback tiap aplikasi.
- [ ] Konfirmasi pembatasan akses dashboard Traefik hanya melalui LAN/Tailscale.
- [ ] Verifikasi konfigurasi aktual Cloudflare Tunnel agar seluruh hostname yang dimaksud diarahkan ke `traefik:80`.

## 13. Cara menjaga SSOT tetap akurat

Setiap kali arsitektur berubah:
1. Periksa keadaan aktual terlebih dahulu.
2. Buat backup sebelum perubahan berisiko.
3. Terapkan perubahan secara terukur.
4. Verifikasi layanan dan routing.
5. Perbarui dokumen ini dengan tanggal, alasan, dan dampak perubahan.
6. Jangan menghapus catatan konfigurasi lama yang masih diperlukan untuk audit/rollback tanpa kebijakan retensi yang jelas.

**Prinsip akhir:** Dokumen ini adalah acuan arsitektur dan kebijakan. Konfigurasi aktual pada server tetap harus diverifikasi sebelum tindakan operasional, dan setiap ketidaksesuaian harus dilaporkan alih-alih ditebak.
