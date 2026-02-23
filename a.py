import json
import os
import requests
import shutil

# --- DOSYA YOLLARI (Ana dizine göre ayarlandı) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.join(BASE_DIR, "config/rules.json")
BACKUP_PATH = os.path.join(BASE_DIR, "config/rules_backup.json")

# Ollama API Adresi (Varsayılan yerel port)
OLLAMA_URL = "http://localhost:11434/api/generate"

# DİKKAT: Sisteminde yüklü olan modeli buraya yaz (Örn: tinyllama, mistral, llama3)
# JSON çıktısı vermede büyük modeller (llama3, mistral) çok daha başarılıdır.
OLLAMA_MODEL = "llama3" 

def load_rules():
    if not os.path.exists(RULES_PATH):
        print(f"[X] Hata: {RULES_PATH} bulunamadı!")
        return None
    with open(RULES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_rules(data):
    # Önce yedek al
    shutil.copy(RULES_PATH, BACKUP_PATH)
    print(f"[i] Orijinal dosyanın yedeği alındı: {BACKUP_PATH}")
    
    # Yeni veriyi kaydet
    with open(RULES_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"[✓] Kurallar başarıyla yapay zeka tarafından güncellendi: {RULES_PATH}")

def ask_ollama_to_fill_actions(service_patterns):
    prompt = f"""
Sen uzman bir Linux Sistem Yöneticisi ve Siber Güvenlik Uzmanısın.
Aşağıda verilen JSON verisindeki her bir kural için, orijinal alanları SAKIN DEĞİŞTİRME.
Sadece her kurala şu iki alanı ekle:
1. "action": Sorunu çözmek için kısa bir İngilizce açıklama.
2. "action_cmd": Bu sorunu çözmek için çalıştırılabilecek TEK SATIRLIK, güvenli bir bash komutu. Eğer tehditse süreci öldüren (kill) bir komut yaz. Komut yoksa "" bırak.

SADECE VE SADECE GEÇERLİ BİR JSON FORMATI DÖNDÜR. BAŞKA HİÇBİR AÇIKLAMA YAZMA.

İşte JSON verisi:
{json.dumps(service_patterns, indent=2)}
"""

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json" # Ollama'nın sadece JSON döndürmesini zorlar
    }

    print(f"[*] Ollama ({OLLAMA_MODEL}) ile iletişim kuruluyor...")
    print("[*] Lütfen bekleyin, bu işlem modelin hızına göre biraz sürebilir...")
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=600)
        response.raise_for_status()
        result = response.json()
        
        # Ollama'dan dönen metni JSON nesnesine çevir
        ai_response_text = result.get("response", "{}")
        updated_patterns = json.loads(ai_response_text)
        return updated_patterns
        
    except requests.exceptions.RequestException as e:
        print(f"[X] Ollama API'sine ulaşılamadı. Ollama'nın (ollama serve) çalıştığından emin ol: {e}")
        return None
    except json.JSONDecodeError:
        print(f"[X] Ollama geçerli bir JSON formatı döndüremedi. Model kafası karışmış olabilir.")
        print("Dönen Raw Veri:\n", ai_response_text)
        return None

def main():
    print("=== ULAK AI: Kural Seti Zenginleştirici ===")
    
    rules = load_rules()
    if not rules:
        return

    service_patterns = rules.get("service_patterns", {})
    if not service_patterns:
        print("[!] İçeride güncellenecek 'service_patterns' bulunamadı.")
        return

    # Sadece service_patterns kısmını Ollama'ya gönderiyoruz
    updated_patterns = ask_ollama_to_fill_actions(service_patterns)
    
    if updated_patterns:
        # Eski pattern'leri yeni AI destekli pattern'lerle değiştir
        rules["service_patterns"] = updated_patterns
        save_rules(rules)
        print("[✓] İşlem tamamlandı! rules.json dosyan güncellendi.")

if __name__ == "__main__":
    main()