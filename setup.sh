#!/bin/bash
# -----------------------------------------------------------------------------
# ULAK AI - Native Deployment & Management Agent
# Description: Automated installer for eBPF sensing and local AI analysis.
# -----------------------------------------------------------------------------

set -e

# --- Professional Color Codes ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

SERVICE_NAME="ulak"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME.service"
INSTALL_DIR=$(pwd)

# --- Help / Usage Function ---
usage() {
    echo -e "${CYAN}ULAK AI Security Agent - Installer${NC}"
    echo "Usage: sudo ./setup.sh [OPTION]"
    echo ""
    echo "Options:"
    echo "  -i, --install      Complete setup: Docker, dependencies, and service (Default)"
    echo "  -u, --uninstall    Stop service, remove container and systemd files"
    echo "  -h, --help         Show this professional help message"
    echo ""
    echo "Examples:"
    echo "  sudo ./setup.sh --install"
    echo "  sudo ./setup.sh -u"
    exit 0
}

# --- 🗑️ Uninstall Logic ---
uninstall_ulak() {
    echo -e "${RED}[!] Uninstalling ULAK AI...${NC}"
    
    # Stop and disable systemd service
    if [ -f "$SERVICE_PATH" ]; then
        echo -e "${YELLOW}[1/3] Stopping and removing systemd service...${NC}"
        sudo systemctl stop $SERVICE_NAME || true
        sudo systemctl disable $SERVICE_NAME || true
        sudo rm -f $SERVICE_PATH
        sudo systemctl daemon-reload
    fi

    # Cleanup Docker container
    if [ "$(docker ps -a -q -f name=ulak_ollama)" ]; then
        echo -e "${YELLOW}[2/3] Removing Docker container 'ulak_ollama'...${NC}"
        docker stop ulak_ollama || true
        docker rm ulak_ollama || true
    fi

    echo -e "${GREEN}[SUCCESS] ULAK AI has been removed from your system.${NC}"
    exit 0
}

# --- 🚀 Install Logic ---
install_ulak() {
    echo -e "${CYAN}--------------------------------------------------${NC}"
    echo -e "${GREEN}      ULAK AI - Native Deployment Agent           ${NC}"
    echo -e "${CYAN}--------------------------------------------------${NC}"

    # 1. Check & Install Docker Engine (Fedora optimized)
    if ! command -v docker &> /dev/null; then
        echo -e "${YELLOW}[1/6] Docker not found. Installing Docker Engine...${NC}"
        sudo dnf install -y dnf-plugins-core
        sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
        sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
        sudo systemctl enable --now docker
        echo -e "${GREEN}[OK] Docker Engine installed and started.${NC}"
    else
        echo -e "${GREEN}[1/6] Docker Engine is already installed.${NC}"
    fi

    # 2. System Dependencies for eBPF
    echo -e "${YELLOW}[2/6] Installing eBPF Dependencies (BCC & Headers)...${NC}"
    sudo dnf install -y bcc-devel bcc-tools python3-bcc kernel-devel-$(uname -r)

    # 3. Python Requirements
    echo -e "${YELLOW}[3/6] Installing Python libraries from requirements.txt...${NC}"
    pip install -r requirements.txt

    # 4. Local AI Setup (Ollama & TinyLlama)
    echo -e "${YELLOW}[4/6] Configuring Local AI Engine (Ollama)...${NC}"
    if [ ! "$(docker ps -a -q -f name=ulak_ollama)" ]; then
        echo -e "${CYAN}[INFO] Creating 'ulak_ollama' container...${NC}"
        docker run -d --name ulak_ollama -p 11434:11434 ollama/ollama
    fi
    docker start ulak_ollama
    echo -e "${CYAN}[INFO] Pulling TinyLlama (Optimized for speed)...${NC}"
    docker exec ulak_ollama ollama pull tinyllama

    # 5. Create Systemd Service File
    echo -e "${YELLOW}[5/6] Creating Systemd Service...${NC}"
    sudo bash -c "cat > $SERVICE_PATH" <<EOF
[Unit]
Description=ULAK AI - eBPF Native Security Agent
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/src/main.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    # 6. Activation & Launch
    echo -e "${YELLOW}[6/6] Activating ULAK Service...${NC}"
    sudo systemctl daemon-reload
    sudo systemctl enable $SERVICE_NAME
    sudo systemctl start $SERVICE_NAME

    echo -e "${GREEN}--------------------------------------------------${NC}"
    echo -e "${GREEN}[SUCCESS] ULAK AI is now active and monitoring!${NC}"
    echo -e "${CYAN}Dashboard: http://localhost:8000${NC}"
    echo -e "${CYAN}View Logs: sudo journalctl -u $SERVICE_NAME -f${NC}"
    echo -e "${GREEN}--------------------------------------------------${NC}"
}

# --- Standard Argument Parsing ---
case "$1" in
    -u|--uninstall|-uninstall)
        uninstall_ulak
        ;;
    -h|--help|-help|help)
        usage
        ;;
    -i|--install|-install|"")
        install_ulak
        ;;
    *)
        echo -e "${RED}[!] Unknown option: $1${NC}"
        usage
        ;;
esac