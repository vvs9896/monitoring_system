#!/usr/bin/env python3

from bcc import BPF
from util import *
import stat
import os

# Имя файла с кодом kernel-части
current_dir = os.path.dirname(os.path.abspath(__file__))
BPF_FILENAME = os.path.join(current_dir, "ebpf_agent.c")

try:
    with open(BPF_FILENAME, "r") as bpf_file:
        bpf_text = bpf_file.read()
except:
    print(f"ERROR: cant open {BPF_FILENAME}")
    exit(1)

# Инициализируем BPF
bpf = BPF(text=bpf_text, cflags=["-Wno-macro-redefined"])

# Получаем имена для системных вызовов
openat_fname        = bpf.get_syscall_fnname("openat")
dup2_fname          = bpf.get_syscall_fnname("dup2")
close_fnname        = bpf.get_syscall_fnname("close")
write_fnname        = bpf.get_syscall_fnname("write")
mount_fnname        = bpf.get_syscall_fnname("mount")
unshare_fnname      = bpf.get_syscall_fnname("unshare")
connect_fnname      = bpf.get_syscall_fnname("connect")
sendto_fnname       = bpf.get_syscall_fnname("sendto")
ptrace_fname        = bpf.get_syscall_fnname("ptrace")
pwrite_fname        = bpf.get_syscall_fnname("pwrite64")
finit_module_fnname = bpf.get_syscall_fnname("finit_module")
mknod_fnname        = bpf.get_syscall_fnname("mknodat")

# Прикрепляемся к системным вызовам
bpf.attach_kprobe(event=openat_fname,        fn_name="syscall__openat")
bpf.attach_kretprobe(event=openat_fname,     fn_name="syscall__openat_ret")
bpf.attach_kprobe(event=dup2_fname,          fn_name="syscall__dup2")
bpf.attach_kretprobe(event=dup2_fname,       fn_name="syscall__dup2_ret")
bpf.attach_kprobe(event=close_fnname,        fn_name="syscall__close")

# CVE-2022-0492 detection
bpf.attach_kprobe(event=write_fnname,        fn_name="syscall__write")
bpf.attach_kprobe(event=mount_fnname,        fn_name="syscall__mount")
bpf.attach_kprobe(event=unshare_fnname,      fn_name="syscall__unshare")

# Docker socket detection
bpf.attach_kprobe(event=connect_fnname,      fn_name="syscall__connect")
bpf.attach_kprobe(event=sendto_fnname,       fn_name="syscall__sendto")

# GDB attach detection
bpf.attach_kprobe(event=ptrace_fname,        fn_name="syscall__ptrace")
bpf.attach_kprobe(event=pwrite_fname,        fn_name="syscall__pwrite64")

# Load module detection
bpf.attach_kprobe(event=finit_module_fnname, fn_name="syscall__finit_module")

# Mknod detection
bpf.attach_kprobe(event=mknod_fnname,        fn_name="syscall__mknod")

# Proc/sys write detection - используем обычный write с фильтрацией
bpf.attach_kprobe(event=write_fnname,        fn_name="syscall__proc_sys_write")

# Глобальные переменные для отслеживания состояния
ptraced_pids = {}

# ===== ОБРАБОТЧИКИ СОБЫТИЙ =====

# CVE-2022-0492 Detection handlers
def handle_write_event(cpu, data, size):
    event = bpf["write_events"].event(data)

    proc = Process(event)

    if not proc.in_container():
        return
    
    target = event.filename.decode("ascii", errors="ignore")

    if target.endswith("/release_agent") or target.endswith("/notify_on_release"):
        write_buf = event.buf[:event.len].decode("ascii", errors='ignore')
        message = f"[CVE-2022-0492] writing to {target}\n[data]\n{write_buf}"
        print_event_message(proc, message)

def handle_mount_event(cpu, data, size):
    event = bpf["mount_events"].event(data)
    
    proc = Process(event)

    if not proc.from_container():
        return
    
    source = event.source.decode("ascii")
    target = event.target.decode("ascii")
    data_str = event.data.decode("ascii", errors="ignore")
    
    if source == "cgroup" and "rdma" in data_str:
        message = f"[CVE-2022-0492] mounting {source} to {target} [options/data]: {data_str}"
        print_event_message(proc, message)
    else:
        # Общее отслеживание mount операций
        if not data_str:
            data_str = "none"
        message = f"[MOUNT] mounting {source} to {target} [options/data]: {data_str}"
        print_event_message(proc, message)

CLONE_NEWCGROUP = 0x02000000 # new cgroup namespace
CLONE_NEWUSER   = 0x10000000 # new user namespace

def handle_unshare_event(cpu, data, size):
    event = bpf["unshare_events"].event(data)

    proc = Process(event)
    if not proc.from_container():
        return
    
    flags = event.flags

    if (flags & CLONE_NEWUSER) and (flags & CLONE_NEWCGROUP):
        message = f"[CVE-2022-0492] unshare ({flags}) with user and cgroup namespace from container"
        print_event_message(proc, message)

# Docker Socket Detection handlers
def handle_connect_unix_event(cpu, data, size):
    event = bpf["connect_unix_events"].event(data)

    proc = Process(event)

    sock_name = event.sock_filename.decode("ascii")

    if sock_name.endswith("/docker.sock") and proc.in_container():
        message = f"[DOCKER-SOCK] connecting to {sock_name}"
        print_event_message(proc, message)

# GDB Attach Detection handlers
def handle_ptrace_event(cpu, data, size):
    global ptraced_pids

    event = bpf["ptrace_events"].event(data)

    proc = Process(event)

    target_pid = event.target_pid
    target_exe = get_pid_realpath(target_pid)

    message = f"[GDB-ATTACH] ptrace attach to pid: {target_pid} ( {target_exe} )"

    ptraced_pids[target_pid] = target_exe

    print_event_message(proc, message)
    
def handle_pwrite_event(cpu, data, size):
    event = bpf["pwrite_events"].event(data)

    proc = Process(event)

    target = event.filename.decode("ascii", errors='ignore')

    if not target.endswith("/mem"):
        return
    
    target_pid = int(target.split("/")[-2])
    ptraced_pid = ptraced_pids.get(target_pid)

    if not ptraced_pid:
        return 
    
    pwrite_buf = bytes(event.buf)[:event.len].hex()
    
    message = f"[GDB-ATTACH] pwrite to {target} [ {pwrite_buf} ]"

    print_event_message(proc, message)

# Load Module Detection handler
def handle_finit_module(cpu, data, size):
    event = bpf["finit_module_events"].event(data)

    proc = Process(event)

    if not proc.from_container():
        return
    
    pathname = event.pathname.decode("ascii")
    
    message = f"[LOAD-MODULE] loading {pathname} module from container"

    print_event_message(proc, message)

# Mknod Detection handler
def handle_mknod_event(cpu, data, size):
    event = bpf["mknod_events"].event(data)

    proc = Process(event)

    pathname = event.pathname.decode("ascii")
    mode = event.mode

    if stat.S_ISBLK(mode) and proc.from_container():
        message = f"[MKNOD] creating block device {pathname} from container"
        print_event_message(proc, message)

# Proc/Sys Write Detection handler
def handle_proc_sys_write_event(cpu, data, size):
    event = bpf["proc_sys_write_events"].event(data)

    proc = Process(event)

    target = event.filename.decode("ascii")

    if target.endswith("/core_pattern") or target.endswith("/uevent_helper"):
        write_buf = bytes(event.buf)[:event.len].decode("ascii", errors='ignore')
        message = f"[PROC-SYS-WRITE] writing to {target}\n[data]\n{write_buf}"
        print_event_message(proc, message)

# Дополнительная обработка для Docker socket write events
def handle_docker_write_event(cpu, data, size):
    event = bpf["write_events"].event(data)

    proc = Process(event)

    target = event.filename.decode("ascii", errors='ignore')

    if target.endswith("/docker.sock") and proc.in_container():
        write_buf = event.buf[:event.len].decode("ascii", errors='ignore')

        if '/containers/create' in write_buf:
            if '"Privileged":true' in write_buf:
                message = f"[DOCKER-SOCK] creating privileged container from container\n[data]\n{write_buf}"
                print_event_message(proc, message)
            elif '"Binds":[' in write_buf:
                message = f"[DOCKER-SOCK] creating container with \"binds\" from container\n[data]\n{write_buf}"
                print_event_message(proc, message)

# Объединенный обработчик для write событий
def handle_combined_write_event(cpu, data, size):
    handle_write_event(cpu, data, size)
    handle_docker_write_event(cpu, data, size)

# Прикрепляем обработчики к событиям
bpf["write_events"].open_perf_buffer(handle_combined_write_event)
bpf["mount_events"].open_perf_buffer(handle_mount_event)
bpf["unshare_events"].open_perf_buffer(handle_unshare_event)
bpf["connect_unix_events"].open_perf_buffer(handle_connect_unix_event)
bpf["ptrace_events"].open_perf_buffer(handle_ptrace_event)
bpf["pwrite_events"].open_perf_buffer(handle_pwrite_event)
bpf["finit_module_events"].open_perf_buffer(handle_finit_module)
bpf["mknod_events"].open_perf_buffer(handle_mknod_event)
bpf["proc_sys_write_events"].open_perf_buffer(handle_proc_sys_write_event)

print("=== COMBINED eBPF SECURITY MONITOR ===")
print("Monitoring:")
print("  - CVE-2022-0492 (cgroup release_agent escape)")
print("  - Docker socket access from containers")
print("  - Mount operations")
print("  - GDB attach and memory write operations")
print("  - Kernel module loading")
print("  - Block device creation (mknod)")
print("  - Proc/sys write operations")
print("")

print("%-12s %-7s %-14s %-7s %-40s      %-16s %s" % 
("CONTAINER_ID", "PID", "PCONTAINER_ID", "PPID", "PCOMM", "COMM", "MESSAGE"))

# В бесконечном цикле получаем и обрабатываем поступающие события
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nShutting down...")
        exit() 