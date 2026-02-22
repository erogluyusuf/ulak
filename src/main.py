import sys
import json
import time
import os
from collector.listener import MultiSourceCollector
from analyzer.llm_engine import LLMAnalyzer

def main():
    """
    Ulak Sistemi Ana Orkestratör Modülü.
    Toplayıcı (Collector) ve Analizör (LLM) arasındaki veri akışını yönetir.
    """
    print("=" * 70)
    print(f"{'[ ULAK AI LOG ANALYZER ]':^70}")
    print("=" * 70)
    print("[INFO] Ulak Orkestratör başlatılıyor...")

    # Adım 1: Yapay Zeka Motoru (LLM) Başlatma ve Bağlantı Kontrolü
    # Hibrit yapıda llm_engine.py içinde localhost:11434 ayarlı olmalıdır.
    analyzer = LLMAnalyzer(model_name="llama3")
    
    print("[INFO] AI Motoru bağlantısı kontrol ediliyor...")
    if not analyzer.check_connection():
        print("[ERROR] AI Motoruna bağlanılamadı!")
        print("[HINT] Lütfen 'docker start ulak_ollama' komutu ile servisin çalıştığından emin olun.")
        sys.exit(1)
        
    print("[INFO] AI Motoru bağlantısı başarılı. (Model: Llama3)")

    # Adım 2: İzlenecek Log Dosyalarının Belirlenmesi
    # Hibrit yapıda olduğumuz için doğrudan sistem yollarını kullanıyoruz.
    target_files = [
        "/var/log/syslog",
        "/var/log/auth.log"
    ]
    
    # Mevcut olmayan dosyaları listeden çıkararak hata almayı önleyelim
    existing_files = [f for f in target_files if os.path.exists(f)]
    if not existing_files:
        print("[ERROR] İzlenecek hiçbir log dosyası bulunamadı! Yol ayarlarını kontrol edin.")
        sys.exit(1)

    # Adım 3: Kolektörü Başlat
    collector = MultiSourceCollector(log_files=existing_files)
    collector.start()
    
    print(f"[INFO] Sistem aktif. İzlenen dosyalar: {existing_files}")
    print("[INFO] Kritik olaylar bekleniyor...\n")
    print("-" * 70)

    # Adım 4: Ana Olay Döngüsü (Event Loop)
    try:
        for alert in collector.get_alerts():
            print(f"\n{'-' * 30} YENİ OLAY {'-' * 30}")
            print(f"[LOG] -> {alert}")
            
            print("[AI] 5W1H analizi yapılıyor, lütfen bekleyin...")
            start_time = time.time()
            
            # Yakalanan logu analiz etmesi için Llama3'e gönder
            diagnostic_report = analyzer.generate_5w1h_report(alert)
            
            end_time = time.time()
            print(f"[INFO] Analiz {end_time - start_time:.2f} saniyede tamamlandı.")
            
            print("\n--- 5W1H DİAGNOSTİK RAPORU ---")
            # Eğer analizde hata oluştuysa daha okunabilir basalım
            if "error" in diagnostic_report:
                print(f"[ERROR] Analiz Hatası: {diagnostic_report['error']}")
            else:
                print(json.dumps(diagnostic_report, indent=4, ensure_ascii=False))
            
            print("=" * 70)

    except KeyboardInterrupt:
        print("\n[INFO] Kapatma sinyali alındı. Ulak kapatılıyor...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[FATAL ERROR] Beklenmeyen sistem hatası: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()