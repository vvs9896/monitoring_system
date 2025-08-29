#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <net/sock.h>

#define MIN(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

#define FILE_NAME_LEN 256
#define WRITE_BUF_MAX_LEN 2048
#define MOUNT_DATA_MAX_LEN 1024

// __ptrace_request 
#define PTRACE_ATTACH 16

// ===== СТРУКТУРЫ ДАННЫХ =====

// Для CVE-2022-0492 detection
struct write_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    int fd;
    char comm[TASK_COMM_LEN];
    char filename[FILE_NAME_LEN];
    char buf[WRITE_BUF_MAX_LEN];
    int len;
};

struct mount_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char source[FILE_NAME_LEN];
    char target[FILE_NAME_LEN];
    char data[MOUNT_DATA_MAX_LEN];
};

struct unshare_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    int flags;
};

// Для Docker socket detection
struct connect_unix_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    int sockfd;
    char sock_filename[FILE_NAME_LEN];
    int retval;
};

// Для GDB attach detection
struct ptrace_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 target_pid;
};

struct pwrite_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    int fd;
    char filename[FILE_NAME_LEN];
    unsigned char buf[WRITE_BUF_MAX_LEN];
    u64 len;
    u64 offset;
};

// Для load module detection
struct finit_module_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char pathname[FILE_NAME_LEN];
};

// Для mknod detection
struct mknod_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char pathname[FILE_NAME_LEN];
    int mode;
};

// Для proc/sys write detection
struct proc_sys_write_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    int fd;
    char filename[FILE_NAME_LEN];
    unsigned char buf[WRITE_BUF_MAX_LEN];
    u64 len;
};

struct opened_file_data_t {
    int fd;
    char pathname[FILE_NAME_LEN];
};

// ===== PERF OUTPUT БУФЕРЫ =====
// таблицы для передачи событий из ядра в пользовательское пространство
// https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#2-bpf_perf_output
BPF_PERF_OUTPUT(write_events);
BPF_PERF_OUTPUT(mount_events);
BPF_PERF_OUTPUT(unshare_events);
BPF_PERF_OUTPUT(connect_unix_events);
BPF_PERF_OUTPUT(ptrace_events);
BPF_PERF_OUTPUT(pwrite_events);
BPF_PERF_OUTPUT(finit_module_events);
BPF_PERF_OUTPUT(mknod_events);
BPF_PERF_OUTPUT(proc_sys_write_events);

// ===== МАССИВЫ ДЛЯ ОБХОДА ОГРАНИЧЕНИЙ СТЕКА =====
// массивы для обхода ограничения bpf в 512 байт на стэк
// одно из обсуждений с этой "проблемой"
// https://github.com/iovisor/bcc/issues/2306
BPF_ARRAY(write_data, struct write_data_t, 1);
BPF_ARRAY(mount_data, struct mount_data_t, 1);
BPF_ARRAY(connect_data, struct connect_unix_data_t, 1);
BPF_ARRAY(pwrite_data, struct pwrite_data_t, 1);
BPF_ARRAY(proc_sys_write_data, struct proc_sys_write_data_t, 1);

// ===== ХЭШ-ТАБЛИЦЫ =====
// промежуточная таблица для сохранения имени файла между входом и выходом из openat
BPF_HASH(temp_opened_files, u64, const char *);
// промежуточная таблица для сохранения имени файла между входом и выходом из dup
BPF_HASH(temp_dup_files, u64, int);
// итоговая таблица сопастовления fd и имени файла
BPF_HASH(opened_files, u64, struct opened_file_data_t);

// ===== ФУНКЦИИ ОТСЛЕЖИВАНИЯ ФАЙЛОВ =====
// отслеживаем вызовы openat для "резолва" имен файлов в последующих вызовах ( в частности во write )
// https://man7.org/linux/man-pages/man2/openat.2.html
int syscall__openat(struct pt_regs *ctx, int dirfd, const char *pathname, int flags, mode_t mode)
{
    u64 file_id = bpf_get_current_pid_tgid();

    // используем id процесса и потока в качестве "идентификатора" файла находящегося в процессе открытия
    // и сохраняем имя файла для последующего мапинга с полученным при выходе дескриптором
    // далее связка "имя файла" -> номер дескриптора будет использована в других вызовах ( напр. write)
    // для получения имени файла, к которому осуществляется обращение

    temp_opened_files.update(&file_id, &pathname);
    return 0;
}

int syscall__openat_ret(struct pt_regs *ctx)
{
    // используем id процесса и потока в качестве "идентификатора" файла находящегося в процессе открытия
    u64 temp_file_id = bpf_get_current_pid_tgid();

    // получаем возвращаемое значение
    // -1 при ошибке
    // иначе - вернется номер открытого дескриптора
    int retval = PT_REGS_RC(ctx);
    
    // ищем ранее сохраненное имя файла с полученным выше "идентификатором" temp_file_id
    const char **pathname = temp_opened_files.lookup(&temp_file_id);
    if (!pathname)
        return 0;

    // при ошибке более не отслеживаем этот файл и удаляем из хэш-таблицы
    if ( retval == -1 ) {
        temp_opened_files.delete(&temp_file_id);
        return 0;
    }

    // получаем "итоговый" id файла из id потока и номера полученного дескриптора
    u64 file_id = (bpf_get_current_pid_tgid() & 0xFFFFFFFF00000000) + retval;

    struct opened_file_data_t opened_file = {};
    
    opened_file.fd = retval;
    bpf_probe_read_user(opened_file.pathname, sizeof(opened_file.pathname), *pathname);

    // сохраняем в хэш-таблицу хранящую имена файлов и дескрипторов открытых файлов
    opened_files.update(&file_id, &opened_file);

    // удаляем из хэш-таблицы хранящую файлы в процессе открытия
    temp_opened_files.delete(&temp_file_id);

    return 0;
}

// https://man7.org/linux/man-pages/man2/dup.2.html
int syscall__dup2(struct pt_regs *ctx, int oldfd, int newfd) {
    // используем id процесса и потока в качестве "идентификатора" файла находящегося в процессе дублирования
    // и сохраняем номер переданного ( старого ) дескриптора для последующего мапинга с полученным при выходе дублированным дескриптором
    // далее связка "номер старого дескриптора" -> "номер нового дескриптора" будет использована при выходе из вызова
    // для создания записи в хэш-таблицы открытых файлов с имени файла для старого дескриптора, но с новым номером дескриптора ( дублированным )
    
    u64 temp_old_id = bpf_get_current_pid_tgid();
    temp_dup_files.update(&temp_old_id, &oldfd);
    return 0;
}

int syscall__dup2_ret(struct pt_regs *ctx) {
    // получаем возвращаемое значение
    // -1 при ошибке
    // иначе - номер дублированного дискриптора
    int retval = PT_REGS_RC(ctx);

    if ( retval == -1 ) {
        return 0;
    }

    // используем id процесса и потока в качестве "идентификатора" файла находящегося в процессе дублирования
    u64 temp_dup_file_id = bpf_get_current_pid_tgid();

    // получаем номер дублируемого дескриптора
    int *old_file_id = temp_dup_files.lookup(&temp_dup_file_id);

    // если дублируемый дескриптор найден, то создаем запись в хэш-таблице открытых файлов
    if (old_file_id) {
        u64 pid_tgid = bpf_get_current_pid_tgid();

        // получаем id для записи хранящей имя файла ассоциированного с дублируемым дескриптором в хэш-таблице открытых файлов
        u64 old_opened_file_id = (pid_tgid & 0xFFFFFFFF00000000) + *old_file_id;

        // получаем запись из хэш-таблицы открытых файлов
        struct opened_file_data_t *target_file = opened_files.lookup(&old_opened_file_id);
        if (!target_file)
            return 0;
        
        // получаем "итоговый" id файла из id потока и номера полученного дескриптора
        u64 dup_file_id = (pid_tgid & 0xFFFFFFFF00000000) + retval;
        
        struct opened_file_data_t dup_file = {};

        // сохраняем новый дискриптор
        dup_file.fd = retval;

        // и старое имя файла
        bpf_probe_read_kernel(dup_file.pathname, sizeof(dup_file.pathname), target_file->pathname);

        // сохраняем в хэш-таблицу открытых файлов
        opened_files.update(&dup_file_id, &dup_file);

        // удаляем из хэш-таблицы хранящую дескрипторы в процессе дублирования
        temp_dup_files.delete(&temp_dup_file_id);
    }

    return 0;
}

// https://man7.org/linux/man-pages/man2/close.2.html
int syscall__close(struct pt_regs *ctx, int fd)
{
    u64 file_id = ( bpf_get_current_pid_tgid() & 0xFFFFFFFF00000000 ) + fd;

    struct opened_file_data_t *opened_file = opened_files.lookup(&file_id);
    if (opened_file)
        opened_files.delete(&file_id);

    return 0;
}

// ===== CVE-2022-0492 DETECTION =====
// https://man7.org/linux/man-pages/man2/write.2.html
int syscall__write(struct pt_regs *ctx, int fd, void *buf, u64 buf_len)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 file_id  = ( pid_tgid & 0xFFFFFFFF00000000 ) + fd;

    struct opened_file_data_t *opened_file = opened_files.lookup(&file_id);
    if (!opened_file) return 0;

    int index = 0;

    struct write_data_t *data = write_data.lookup(&index);
    if (data == NULL) return 1;
    
    memset(data->filename, 0, FILE_NAME_LEN);

    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    data->pid  = pid_tgid >> 32;
    data->ppid = task->real_parent->tgid;
    data->fd   = fd;
    data->uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 result_len = MIN(WRITE_BUF_MAX_LEN, buf_len);
    bpf_probe_read_user(data->buf, result_len, buf);
    data->len = result_len;
    bpf_get_current_comm(data->comm, sizeof(data->comm));

    bpf_probe_read_kernel(data->filename, sizeof(data->filename), opened_file->pathname);

    write_events.perf_submit(ctx, data, sizeof(*data));

    return 0;
}

// https://man7.org/linux/man-pages/man2/mount.2.html
int syscall__mount(struct pt_regs *ctx,
    const char *source, const char *target,
    const char *filesystemtype, unsigned long mountflags,
    const void *m_data)
{
    int index = 0;

    struct mount_data_t *data = mount_data.lookup(&index);
    if (data == NULL) return 1;
    
    memset(data->source, 0, FILE_NAME_LEN);
    memset(data->target, 0, FILE_NAME_LEN);

    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    data->pid  = bpf_get_current_pid_tgid() >> 32;
    data->ppid = task->real_parent->tgid;
    data->uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(data->comm, sizeof(data->comm));
    bpf_probe_read_user(data->source, sizeof(data->source), source);
    bpf_probe_read_user(data->target, sizeof(data->target), target);
    bpf_probe_read_user_str(data->data, sizeof(data->data), m_data);

    mount_events.perf_submit(ctx, data, sizeof(*data));

    return 0;
}

int syscall__unshare(struct pt_regs *ctx, int flags){
    struct unshare_data_t unshare_data = {};

    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    unshare_data.pid  = bpf_get_current_pid_tgid() >> 32;
    unshare_data.ppid = task->real_parent->tgid;
    unshare_data.uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    unshare_data.flags = flags;
    bpf_get_current_comm(&unshare_data.comm, sizeof(unshare_data.comm));

    unshare_events.perf_submit(ctx, &unshare_data, sizeof(unshare_data));

    return 0;
}

// ===== DOCKER SOCKET DETECTION =====
// https://man7.org/linux/man-pages/man2/connect.2.html
int syscall__connect(struct pt_regs *ctx, int sockfd, struct sockaddr *saddr, u64 addrlen)
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u32 pid       = pid_tgid >> 32;
    u32 ppid      = task->real_parent->tgid;
    u32 uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    if ( saddr->sa_family == 1 ) // sa_family == UNIX
    {
        struct sockaddr_un *saddr_un = (struct sockaddr_un*) saddr;

        if ( saddr_un->sun_path[0] == 0) // sun_path пустой
            return 0;
        
        int index = 0;

        struct connect_unix_data_t *data = connect_data.lookup(&index);
        if (data == NULL) return 1;
        
        data->pid     = pid;
        data->ppid    = ppid;
        data->uid     = uid;
        data->sockfd  = sockfd;

        bpf_probe_read_user(data->sock_filename, sizeof(data->sock_filename), saddr_un->sun_path);

        u64 socket_id = ( pid_tgid & 0xFFFFFFFF00000000 ) + sockfd;

        struct opened_file_data_t opened_socket = {};

        opened_socket.fd = sockfd;
        bpf_probe_read_user(opened_socket.pathname, sizeof(opened_socket.pathname), saddr_un->sun_path);

        opened_files.update(&socket_id, &opened_socket);

        connect_unix_events.perf_submit(ctx, data, sizeof(*data));
    }

    return 0;
}

// https://man7.org/linux/man-pages/man2/sendto.2.html
int syscall__sendto(struct pt_regs *ctx, int fd, void *buf, u64 buf_len, int flags, struct sockaddr *dest_addr, int addrlen)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 file_id  = ( pid_tgid & 0xFFFFFFFF00000000 ) + fd;

    struct opened_file_data_t *opened_file = opened_files.lookup(&file_id);
    if (!opened_file) return 0;

    int index = 0;

    struct write_data_t *data = write_data.lookup(&index);
    if (data == NULL) return 1;
    
    memset(data->filename, 0, FILE_NAME_LEN);

    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    data->pid  = pid_tgid >> 32;
    data->ppid = task->real_parent->tgid;
    data->fd   = fd;
    data->uid  = bpf_get_current_uid_gid() & 0xffffffff;
    u32 result_len = MIN(WRITE_BUF_MAX_LEN, buf_len);
    bpf_probe_read_user(data->buf, result_len, buf);
    data->len = result_len;
    bpf_get_current_comm(data->comm, sizeof(data->comm));

    bpf_probe_read_kernel(data->filename, sizeof(data->filename), opened_file->pathname);

    write_events.perf_submit(ctx, data, sizeof(*data));

    return 0;
}

// ===== GDB ATTACH DETECTION =====
// https://man7.org/linux/man-pages/man2/ptrace.2.html
int syscall__ptrace(struct pt_regs *ctx,
    u32 request, u32 pid,
    void *addr, void *data)
{
    // отслеживаем только события PTRACE_ATTACH
    if ( request != PTRACE_ATTACH )
        return 0;

    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct ptrace_data_t ptrace_data = {};

    ptrace_data.pid  = pid_tgid >> 32;
    ptrace_data.ppid = task->real_parent->tgid;
    ptrace_data.uid  = bpf_get_current_uid_gid() & 0xffffffff;

    ptrace_data.target_pid = pid;

    ptrace_events.perf_submit(ctx, &ptrace_data, sizeof(ptrace_data));

    return 0;
}

// https://man7.org/linux/man-pages/man2/pwrite64.2.html
int syscall__pwrite64(struct pt_regs *ctx, int fd, void *buf, u64 buf_len, u64 offset)
{   
    int index = 0;
    struct pwrite_data_t *data = pwrite_data.lookup(&index);

    if (data == NULL) return 1;

    memset(data->filename, 0, FILE_NAME_LEN);

    u64 pid_tgid  = bpf_get_current_pid_tgid();

    // формируем id для хэш-таблице хранящей "маппинг" дескрипторов и имен файлов
    u64 file_id = ( pid_tgid & 0xFFFFFFFF00000000 ) + fd;

    struct opened_file_data_t *opened_file = opened_files.lookup(&file_id);
    if (!opened_file)
        return 0;

    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    data->pid  = pid_tgid >> 32;
    data->ppid = task->real_parent->tgid;
    data->fd   = fd;
    data->uid  = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_probe_read_kernel(data->filename, sizeof(data->filename), opened_file->pathname);
    u32 result_len = MIN(WRITE_BUF_MAX_LEN, buf_len);
    bpf_probe_read_user(data->buf, result_len, buf);
    data->len    = result_len;
    data->offset = offset;

    // выводим данные в userspace
    pwrite_events.perf_submit(ctx, data, sizeof(struct pwrite_data_t));

    return 0;
}

// ===== LOAD MODULE DETECTION =====
// https://man7.org/linux/man-pages/man2/finit_module.2.html
int syscall__finit_module(struct pt_regs *ctx, int fd, const char *param_values, int flags){
    struct finit_module_data_t finit_module_data = {};

    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u64 file_id   = ( pid_tgid & 0xFFFFFFFF00000000 ) + fd;

    struct opened_file_data_t *opened_file = opened_files.lookup(&file_id);
    if (!opened_file)
        return 0;
    
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    finit_module_data.pid  = pid_tgid >> 32;
    finit_module_data.ppid = task->real_parent->tgid;
    finit_module_data.uid  = bpf_get_current_uid_gid() & 0xffffffff;

    bpf_probe_read_kernel(finit_module_data.pathname, sizeof(finit_module_data.pathname), opened_file->pathname);

    finit_module_events.perf_submit(ctx, &finit_module_data, sizeof(finit_module_data));

    return 0;
}

// ===== MKNOD DETECTION =====
// https://man7.org/linux/man-pages/man2/mknod.2.html
int syscall__mknod(struct pt_regs *ctx, int dirfd, const char *pathname, mode_t mode, dev_t dev)
{
    struct mknod_data_t mknod_data = {};

    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    mknod_data.pid  = bpf_get_current_pid_tgid() >> 32;
    mknod_data.ppid = task->real_parent->tgid;
    mknod_data.uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&mknod_data.comm, sizeof(mknod_data.comm));
    bpf_probe_read_user(mknod_data.pathname, sizeof(mknod_data.pathname), pathname);
    mknod_data.mode = mode;

    mknod_events.perf_submit(ctx, &mknod_data, sizeof(mknod_data));

    return 0;
}

// ===== PROC/SYS WRITE DETECTION =====

int syscall__proc_sys_write(struct pt_regs *ctx, int fd, void *buf, u64 buf_len)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 file_id  = ( pid_tgid & 0xFFFFFFFF00000000 ) + fd;

    struct opened_file_data_t *opened_file = opened_files.lookup(&file_id);
    if (!opened_file) return 0;

    int index = 0;
    struct proc_sys_write_data_t *data = proc_sys_write_data.lookup(&index);
    
    if (data == NULL) return 1;
    
    memset(data->filename, 0, FILE_NAME_LEN);

    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    data->pid  = pid_tgid >> 32;
    data->ppid = task->real_parent->tgid;
    data->fd = fd;
    data->uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u32 result_len = MIN(WRITE_BUF_MAX_LEN, buf_len);
    bpf_probe_read_user(data->buf, result_len, buf);
    data->len = result_len;
    bpf_probe_read_kernel(data->filename, sizeof(data->filename), opened_file->pathname);

    proc_sys_write_events.perf_submit(ctx, data, sizeof(*data));

    return 0;
} 