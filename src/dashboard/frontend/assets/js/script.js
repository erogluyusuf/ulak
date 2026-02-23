const { createApp, ref, onMounted, onUnmounted, computed } = Vue;

createApp({
    setup() {
        // ========================= STATE =========================
        const incidents = ref([]);
        const lastUpdate = ref('--:--:--');
        let refreshInterval = null;

        // Modal States
        const showDetailModal = ref(false);
        const selectedLog = ref(null); // <-- KRİTİK DÜZELTME: İsim HTML ile eşitlendi
        
        const showFixModal = ref(false);
        const fixCommand = ref("");
        const pendingFixLog = ref(null);

        // ========================= COMPUTED =========================
        const aiRatio = computed(() => {
            if (!Array.isArray(incidents.value) || incidents.value.length === 0) return 0;
            const aiCount = incidents.value.filter(i => i?.raw_data?.source && i.raw_data.source.includes("AI")).length;
            return Math.round((aiCount / incidents.value.length) * 100);
        });

        // ========================= FETCH DATA =========================
        const fetchData = async () => {
            // Eğer fix ekranı veya detay ekranı açıksa yenilemeyi atla ki kullanıcının ekranı kaymasın
            if (showFixModal.value || showDetailModal.value) return;

            try {
                const res = await fetch("/data");
                if (!res.ok) return;
                const data = await res.json();
                if (Array.isArray(data)) {
                    incidents.value = data;
                }
                lastUpdate.value = new Date().toLocaleTimeString();
            } catch (err) {
                console.error("❌ Veri alınamadı:", err);
            }
        };

        const getRiskColor = (score) => {
            if (score >= 90) return 'risk-critical';
            if (score >= 70) return 'risk-high';
            if (score >= 40) return 'risk-medium';
            return 'risk-low';
        };

        // ========================= MODAL: DETAY =========================
        const openDetails = (log) => {
            if (!log) return;
            selectedLog.value = log; // <-- Artık veriyi doğru değişkene aktarıyor
            showDetailModal.value = true;
        };

        // ========================= MODAL: FIX TETİKLE =========================
        const triggerFix = async (log) => {
            if (!log?.raw_data?.cmd) {
                alert("Geçersiz olay verisi.");
                return;
            }

            try {
                const res = await fetch("/fix", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(log)
                });

                if (!res.ok) throw new Error("Backend hata döndürdü");
                const data = await res.json();

                if (data.status === "ready_for_approval") {
                    fixCommand.value = data.command;
                    pendingFixLog.value = log;
                    showFixModal.value = true; // Modal'ı Aç
                } else {
                    alert("Sistem onarım komutu üretemedi.");
                }
            } catch (err) {
                console.error("❌ FIX bağlantı hatası:", err);
                alert("Backend iletişim hatası.");
            }
        };

        // ========================= EXECUTE FIX =========================
        const executeFix = async () => {
            showFixModal.value = false; // Tıklanınca hemen kapat
            
            try {
                const execRes = await fetch('/execute_fix', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ command: fixCommand.value })
                });
                
                const execData = await execRes.json();

                if (execData.status === 'success') {
                    alert(`✅ İŞLEM BAŞARILI!\n\nÇıktı:\n${execData.output || 'Sistem sessizce temizlendi.'}`);
                    // İşlem bittiğinde veriyi zorla yenile
                    showFixModal.value = false;
                    setTimeout(fetchData, 500); 
                } else {
                    alert(`❌ İŞLEM BAŞARISIZ!\n\nDetay:\n${execData.error}\n${execData.output}`);
                }
            } catch (err) {
                console.error("❌ Komut çalıştırma hatası:", err);
                alert("İşletim sistemine komut gönderilemedi.");
            }
        };

        // ========================= LIFECYCLE =========================
        onMounted(() => {
            fetchData();
            refreshInterval = setInterval(fetchData, 4000);
        });

        onUnmounted(() => {
            if (refreshInterval) clearInterval(refreshInterval);
        });

        return {
            incidents, lastUpdate, aiRatio, fetchData, getRiskColor,
            showDetailModal, selectedLog, openDetails, // <-- KRİTİK DÜZELTME: HTML'e doğru ismi gönderdik
            showFixModal, fixCommand, triggerFix, executeFix
        };
    }
}).mount("#app");