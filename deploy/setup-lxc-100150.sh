#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Provisioning & GitHub Actions Runner Setup for LXC 100150 (osc.yowman.my.id)
# Host IP: 192.168.0.150/24 | Gateway: 192.168.0.1

set -euo pipefail

echo "=========================================================="
echo " [OSC] Setting up Proxmox LXC 100150 (192.168.0.150)"
echo "=========================================================="

# 1. Update OS Packages & Prerequisites
echo "[*] Updating apt repositories..."
apt-get update -y
apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    git \
    tar \
    jq \
    ufw

# 2. Install Docker & Docker Compose Plugin (Official Docker Repo)
if ! command -v docker &> /dev/null; then
    echo "[*] Installing Docker Engine..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg || \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    ARCH=$(dpkg --print-architecture)
    ID=$(. /etc/os-release && echo "$ID")
    VERSION_CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME")

    echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
        | tee /etc/apt/sources.list.d/docker.list > /dev/null

    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
    echo "[+] Docker installed successfully."
else
    echo "[+] Docker is already installed."
fi

# 3. Setup Deployment Directory
APP_DIR="/opt/osc"
echo "[*] Setting up application directory at ${APP_DIR}..."
mkdir -p "${APP_DIR}/output"
chmod 775 "${APP_DIR}/output"

# 4. Configure Firewall (Allow traffic to port 8000 from Gateway 192.168.0.80 or LAN)
if ufw status | grep -q "Status: active"; then
    echo "[*] Configuring UFW for Traefik Ingress (192.168.0.80)..."
    ufw allow from 192.168.0.80 to any port 8000 proto tcp comment 'OSC Web from Traefik Gateway'
    ufw allow from 192.168.0.0/24 to any port 8000 proto tcp comment 'OSC Web from LAN'
fi

# 5. Setup Dedicated Runner User & Directory
RUNNER_USER="runner"
RUNNER_DIR="/home/${RUNNER_USER}/actions-runner"

if ! id "${RUNNER_USER}" &>/dev/null; then
    echo "[*] Creating user '${RUNNER_USER}' with docker group..."
    useradd -m -s /bin/bash "${RUNNER_USER}"
    usermod -aG docker "${RUNNER_USER}"
else
    usermod -aG docker "${RUNNER_USER}"
fi

echo "[*] Preparing runner directory at ${RUNNER_DIR}..."
mkdir -p "${RUNNER_DIR}"
chown -R "${RUNNER_USER}:${RUNNER_USER}" "${RUNNER_DIR}"
chown -R "${RUNNER_USER}:${RUNNER_USER}" "${APP_DIR}"

echo ""
echo "=========================================================="
echo " [OK] LXC 100150 base setup complete!"
echo "=========================================================="
echo ""
echo "NEXT STEPS TO REGISTER GITHUB ACTIONS RUNNER:"
echo "1. Go to your GitHub repository -> Settings -> Actions -> Runners -> New self-hosted runner."
echo "2. Switch to user 'runner':"
echo "     su - ${RUNNER_USER}"
echo "     cd ${RUNNER_DIR}"
echo "3. Download runner package (check GitHub for latest version):"
echo "     curl -o actions-runner-linux-x64.tar.gz -L https://github.com/actions/runner/releases/download/v2.321.0/actions-runner-linux-x64-2.321.0.tar.gz"
echo "     tar xzf ./actions-runner-linux-x64.tar.gz"
echo "4. Configure runner with token from GitHub:"
echo "     ./config.sh --url https://github.com/<OWNER>/<REPO> --token <TOKEN> --name lxc-100150-runner --labels self-hosted,linux,x64,lxc100150"
echo "5. Install and start as a systemd service (as root):"
echo "     exit # back to root"
echo "     cd ${RUNNER_DIR}"
echo "     ./svc.sh install ${RUNNER_USER}"
echo "     ./svc.sh start"
echo "=========================================================="
