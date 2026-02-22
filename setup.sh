#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${GREEN}[INFO] Sistem paketleri yükleniyor (BCC & Kernel Headers)...${NC}"
# eBPF için gerekli sistem kütüphaneleri (Fedora)
sudo dnf install -y bcc-devel bcc-tools python3-bcc kernel-devel-$(uname -r)

echo -e "${YELLOW}[INFO] Python kütüphaneleri yükleniyor...${NC}"
pip install -r requirements.txt

echo -e "${CYAN}[INFO] AI Motoru Optimizasyonu (TinyLlama)...${NC}"
# Konteynerın çalıştığından emin ol ve hafif modeli çek
if [ "$(docker ps -q -f name=ulak_ollama)" ]; then
    docker exec ulak_ollama ollama pull tinyllama
    echo -e "${GREEN}[SUCCESS] TinyLlama modeli başarıyla yüklendi.${NC}"
else
    echo -e "${YELLOW}[WARNING] ulak_ollama konteynırı çalışmıyor! Model yüklenemedi.${NC}"
fi

echo -e "${GREEN}[SUCCESS] Kurulum bitti. Artık 'sudo python3 src/ebpf/handler.py' ile sistemi başlatabilirsin.${NC}"