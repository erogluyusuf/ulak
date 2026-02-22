#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct data_t {
    u32 pid;
    int exit_code;
    char comm[TASK_COMM_LEN];
    char msg[128]; // Hata metnini burada taşıyacağız
};

BPF_PERF_OUTPUT(events);

// 1. Yazma işlemlerini izle (Özellikle stderr)
KFUNC_PROBE(vfs_write, struct file *file, const char __user *buf, size_t count, loff_t *pos) {
    struct data_t data = {};
    
    // Sadece stderr (fd 2) akışını yakalamaya çalışıyoruz
    // Basitleştirilmiş mantık: Yazılan veriyi al
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Mesajı kullanıcı alanından çek (Grok analizi için lazım)
    bpf_probe_read_user(&data.msg, sizeof(data.msg), buf);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// 2. Çıkış kodunu hala takip ediyoruz
void trace_do_exit(struct pt_regs *ctx, long code) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.exit_code = (code >> 8) & 0xFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    if (data.exit_code > 0) {
        events.perf_submit(ctx, &data, sizeof(data));
    }
}