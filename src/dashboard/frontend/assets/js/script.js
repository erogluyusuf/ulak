const { createApp, ref, onMounted, computed } = Vue;

createApp({
    setup() {

        const incidents = ref([]);
        const lastUpdate = ref('--:--:--');

        const aiRatio = computed(() => {
            if (incidents.value.length === 0) return 0;
            const aiCount = incidents.value.filter(
                i => i.raw_data.source === 'AI'
            ).length;
            return Math.round((aiCount / incidents.value.length) * 100);
        });

        const fetchData = async () => {
            try {
                const res = await fetch('/data');
                incidents.value = await res.json();
                lastUpdate.value = new Date().toLocaleTimeString();
            } catch (err) {
                console.error("Veri alınamadı");
            }
        };

        const openDetails = (log) => {
            alert("ANALYSIS:\n\n" + JSON.stringify(log, null, 2));
        };

        const triggerFix = (log) => {
            if(confirm(`${log.raw_data.cmd} için onarım başlatılsın mı?`)){
                alert("Fix protokolü başlatıldı.");
            }
        };

        onMounted(() => {
            fetchData();
            setInterval(fetchData, 4000);
        });

        return {
            incidents,
            lastUpdate,
            aiRatio,
            fetchData,
            openDetails,
            triggerFix
        };
    }
}).mount("#app");