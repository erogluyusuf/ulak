#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>

// --- STRUCTURES ---

// 1. Exit & Error Tracking
struct data_t {
    u32 pid;
    int exit_code;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

// 2. Command Execution Tracking
struct exec_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    char fname[128];
};
BPF_PERF_OUTPUT(exec_events);

// 3. File Integrity Monitoring (FIM)
struct file_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};
BPF_PERF_OUTPUT(file_events);

// --- KERNEL HOOKS ---

// HOOK: Process Exit (Hata takibi için)
void trace_do_exit(struct pt_regs *ctx, long code) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.exit_code = (code >> 8) & 0xFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    if (data.exit_code > 0) {
        events.perf_submit(ctx, &data, sizeof(data));
    }
}

// HOOK: Command Execution (Süreç zinciri takibi için)
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Çalıştırılan dosya yolunu oku
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), args->filename);

    // Ebeveyn (Parent) bilgilerini al
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&data.ppid, sizeof(data.ppid), &task->real_parent->tgid);
    bpf_probe_read_kernel(&data.pcomm, sizeof(data.pcomm), &task->real_parent->comm);

    exec_events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// HOOK: File Write (Bütünlük izleme için)
// Arkadaşının dediği gibi kprobe üzerinden temiz takip
int trace_vfs_write_entry(struct pt_regs *ctx, struct file *file) {
    struct file_event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Dentry üzerinden dosya ismini yakala
    struct dentry *de = file->f_path.dentry;
    struct qstr d_name = de->d_name;

    // Kernel string okuma (Basename yakalar)
    bpf_probe_read_kernel_str(&event.filename, sizeof(event.filename), d_name.name);

    // Gürültü engelleme: Sadece ismi olan dosyaları raporla
    if (event.filename[0] != 0) {
        file_events.perf_submit(ctx, &event, sizeof(event));
    }

    return 0;
}