#!/usr/bin/env python3

import os
import sys
import signal
import logging
import argparse
import json
import stat
from pathlib import Path
from bcc import BPF
from util import *

# Настройка логирования для systemd/journald
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('ebpf-monitor')

class EBPFMonitor:
    def __init__(self, config_file=None):
        self.config = self.load_config(config_file)
        self.bpf = None
        self.running = False
        self.ptraced_pids = {}
        
        # Настройка обработчиков сигналов
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def load_config(self, config_file):
        """Загрузка конфигурации из файла"""
        default_config = {
            "rabbitmq": {
                "host": "localhost",
                "port": 5672,
                "username": "admin",
                "password": "admin",
                "exchange": "events_exchange",
                "queue": "events_queue",
                "routing_key": "event_key"
            },
            "ebpf": {
                "program_file": "ebpf_agent.c"
            }
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
                    logger.info(f"Loaded configuration from {config_file}")
            except Exception as e:
                logger.warning(f"Failed to load config file {config_file}: {e}")
                logger.info("Using default configuration")
        
        return default_config
    
    def signal_handler(self, signum, frame):
        """Обработчик сигналов для корректного завершения"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def initialize_bpf(self):
        """Инициализация eBPF программы"""
        try:
            # Получаем путь к eBPF программе
            current_dir = os.path.dirname(os.path.abspath(__file__))
            bpf_filename = os.path.join(current_dir, self.config['ebpf']['program_file'])
            
            if not os.path.exists(bpf_filename):
                raise FileNotFoundError(f"eBPF program file not found: {bpf_filename}")
            
            with open(bpf_filename, "r") as bpf_file:
                bpf_text = bpf_file.read()
            
            logger.info("Initializing eBPF program...")
            self.bpf = BPF(text=bpf_text, cflags=["-Wno-macro-redefined"])
            
            self.attach_kprobes()
            self.setup_event_handlers()
            
            logger.info("eBPF program initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize eBPF program: {e}")
            raise
    
    def attach_kprobes(self):
        """Прикрепление к системным вызовам"""
        syscalls = [
            ("openat", "syscall__openat", "syscall__openat_ret"),
            ("dup2", "syscall__dup2", "syscall__dup2_ret"),
            ("close", "syscall__close", None),
            ("write", "syscall__write", None),
            ("mount", "syscall__mount", None),
            ("unshare", "syscall__unshare", None),
            ("connect", "syscall__connect", None),
            ("sendto", "syscall__sendto", None),
            ("ptrace", "syscall__ptrace", None),
            ("pwrite64", "syscall__pwrite64", None),
            ("finit_module", "syscall__finit_module", None),
            ("mknodat", "syscall__mknod", None)
        ]
        
        for syscall, entry_fn, exit_fn in syscalls:
            try:
                fname = self.bpf.get_syscall_fnname(syscall)
                self.bpf.attach_kprobe(event=fname, fn_name=entry_fn)
                logger.debug(f"Attached kprobe to {syscall} -> {entry_fn}")
                
                if exit_fn:
                    self.bpf.attach_kretprobe(event=fname, fn_name=exit_fn)
                    logger.debug(f"Attached kretprobe to {syscall} -> {exit_fn}")
                    
            except Exception as e:
                logger.warning(f"Failed to attach to {syscall}: {e}")
        
        # Дополнительное прикрепление для proc/sys write detection
        write_fname = self.bpf.get_syscall_fnname("write")
        self.bpf.attach_kprobe(event=write_fname, fn_name="syscall__proc_sys_write")
    
    def setup_event_handlers(self):
        """Настройка обработчиков событий"""
        event_handlers = [
            ("write_events", self.handle_combined_write_event),
            ("mount_events", self.handle_mount_event),
            ("unshare_events", self.handle_unshare_event),
            ("connect_unix_events", self.handle_connect_unix_event),
            ("ptrace_events", self.handle_ptrace_event),
            ("pwrite_events", self.handle_pwrite_event),
            ("finit_module_events", self.handle_finit_module),
            ("mknod_events", self.handle_mknod_event),
            ("proc_sys_write_events", self.handle_proc_sys_write_event)
        ]
        
        for event_name, handler in event_handlers:
            try:
                self.bpf[event_name].open_perf_buffer(handler)
                logger.debug(f"Set up event handler for {event_name}")
            except Exception as e:
                logger.warning(f"Failed to set up handler for {event_name}: {e}")
    
    def handle_combined_write_event(self, cpu, data, size):
        """Объединенный обработчик для write событий"""
        try:
            self.handle_write_event(cpu, data, size)
            self.handle_docker_write_event(cpu, data, size)
        except Exception as e:
            logger.error(f"Error in combined write event handler: {e}")
    
    def handle_write_event(self, cpu, data, size):
        """CVE-2022-0492 Detection handler"""
        try:
            event = self.bpf["write_events"].event(data)
            proc = Process(event)

            if not proc.in_container():
                return
            
            target = event.filename.decode("ascii", errors="ignore")

            if target.endswith("/release_agent") or target.endswith("/notify_on_release"):
                write_buf = event.buf[:event.len].decode("ascii", errors='ignore')
                message = f"[CVE-2022-0492] writing to {target}\n[data]\n{write_buf}"
                self.log_event_message(proc, message, "CRITICAL")
                
        except Exception as e:
            logger.error(f"Error in write event handler: {e}")

    def handle_mount_event(self, cpu, data, size):
        """Mount event handler"""
        try:
            event = self.bpf["mount_events"].event(data)
            proc = Process(event)

            if not proc.from_container():
                return
            
            source = event.source.decode("ascii")
            target = event.target.decode("ascii")
            data_str = event.data.decode("ascii", errors="ignore")
            
            if source == "cgroup" and "rdma" in data_str:
                message = f"[CVE-2022-0492] mounting {source} to {target} [options/data]: {data_str}"
                self.log_event_message(proc, message, "CRITICAL")
            else:
                if not data_str:
                    data_str = "none"
                message = f"[MOUNT] mounting {source} to {target} [options/data]: {data_str}"
                self.log_event_message(proc, message, "INFO")
                
        except Exception as e:
            logger.error(f"Error in mount event handler: {e}")

    def handle_unshare_event(self, cpu, data, size):
        """Unshare event handler"""
        try:
            event = self.bpf["unshare_events"].event(data)
            proc = Process(event)
            
            if not proc.from_container():
                return
            
            flags = event.flags
            CLONE_NEWCGROUP = 0x02000000
            CLONE_NEWUSER = 0x10000000

            if (flags & CLONE_NEWUSER) and (flags & CLONE_NEWCGROUP):
                message = f"[CVE-2022-0492] unshare ({flags}) with user and cgroup namespace from container"
                self.log_event_message(proc, message, "CRITICAL")
                
        except Exception as e:
            logger.error(f"Error in unshare event handler: {e}")

    def handle_connect_unix_event(self, cpu, data, size):
        """Docker socket connection handler"""
        try:
            event = self.bpf["connect_unix_events"].event(data)
            proc = Process(event)

            sock_name = event.sock_filename.decode("ascii")

            if sock_name.endswith("/docker.sock") and proc.in_container():
                message = f"[DOCKER-SOCK] connecting to {sock_name}"
                self.log_event_message(proc, message, "MEDIUM")
                
        except Exception as e:
            logger.error(f"Error in connect unix event handler: {e}")

    def handle_ptrace_event(self, cpu, data, size):
        """GDB attach detection handler"""
        try:
            event = self.bpf["ptrace_events"].event(data)
            proc = Process(event)

            target_pid = event.target_pid
            target_exe = get_pid_realpath(target_pid)

            message = f"[GDB-ATTACH] ptrace attach to pid: {target_pid} ( {target_exe} )"
            self.ptraced_pids[target_pid] = target_exe
            self.log_event_message(proc, message, "CRITICAL")
            
        except Exception as e:
            logger.error(f"Error in ptrace event handler: {e}")
    
    def handle_pwrite_event(self, cpu, data, size):
        """PWrite event handler"""
        try:
            event = self.bpf["pwrite_events"].event(data)
            proc = Process(event)

            target = event.filename.decode("ascii", errors='ignore')

            if not target.endswith("/mem"):
                return
            
            target_pid = int(target.split("/")[-2])
            ptraced_pid = self.ptraced_pids.get(target_pid)

            if not ptraced_pid:
                return 
            
            pwrite_buf = bytes(event.buf)[:event.len].hex()
            message = f"[GDB-ATTACH] pwrite to {target} [ {pwrite_buf} ]"
            self.log_event_message(proc, message, "CRITICAL")
            
        except Exception as e:
            logger.error(f"Error in pwrite event handler: {e}")

    def handle_finit_module(self, cpu, data, size):
        """Kernel module loading handler"""
        try:
            event = self.bpf["finit_module_events"].event(data)
            proc = Process(event)

            if not proc.from_container():
                return
            
            pathname = event.pathname.decode("ascii")
            message = f"[LOAD-MODULE] loading {pathname} module from container"
            self.log_event_message(proc, message, "CRITICAL")
            
        except Exception as e:
            logger.error(f"Error in finit module handler: {e}")

    def handle_mknod_event(self, cpu, data, size):
        """Mknod detection handler"""
        try:
            event = self.bpf["mknod_events"].event(data)
            proc = Process(event)

            pathname = event.pathname.decode("ascii")
            mode = event.mode

            if stat.S_ISBLK(mode) and proc.from_container():
                message = f"[MKNOD] creating block device {pathname} from container"
                self.log_event_message(proc, message, "CRITICAL")
                
        except Exception as e:
            logger.error(f"Error in mknod event handler: {e}")

    def handle_proc_sys_write_event(self, cpu, data, size):
        """Proc/sys write detection handler"""
        try:
            event = self.bpf["proc_sys_write_events"].event(data)
            proc = Process(event)

            target = event.filename.decode("ascii")

            if target.endswith("/core_pattern") or target.endswith("/uevent_helper"):
                write_buf = bytes(event.buf)[:event.len].decode("ascii", errors='ignore')
                message = f"[PROC-SYS-WRITE] writing to {target}\n[data]\n{write_buf}"
                self.log_event_message(proc, message, "CRITICAL")
                
        except Exception as e:
            logger.error(f"Error in proc sys write event handler: {e}")

    def handle_docker_write_event(self, cpu, data, size):
        """Docker socket write events handler"""
        try:
            event = self.bpf["write_events"].event(data)
            proc = Process(event)

            target = event.filename.decode("ascii", errors='ignore')

            if target.endswith("/docker.sock") and proc.in_container():
                write_buf = event.buf[:event.len].decode("ascii", errors='ignore')

                if '/containers/create' in write_buf:
                    if '"Privileged":true' in write_buf:
                        message = f"[DOCKER-SOCK] creating privileged container from container\n[data]\n{write_buf}"
                        self.log_event_message(proc, message, "CRITICAL")
                    elif '"Binds":[' in write_buf:
                        message = f"[DOCKER-SOCK] creating container with \"binds\" from container\n[data]\n{write_buf}"
                        self.log_event_message(proc, message, "CRITICAL")
                        
        except Exception as e:
            logger.error(f"Error in docker write event handler: {e}")
    
    def log_event_message(self, proc, message, severity="INFO"):
        """Логирование события с отправкой в RabbitMQ и journald"""
        try:
            # Форматированное сообщение для вывода
            formatted_message = "%-12s %-7d %-14s %-7d %-40s  ->  %-16s %s" % (
                proc.container_id, proc.pid, proc.parent_container_id, 
                proc.ppid, proc.parent_comm, proc.comm, message
            )
            
            # Логирование в journald с соответствующим уровнем
            if severity == "CRITICAL":
                logger.critical(formatted_message)
            elif severity == "MEDIUM":
                logger.warning(formatted_message)
            else:
                logger.info(formatted_message)
            
            # Отправка в RabbitMQ (используем существующую функцию)
            print_event_message(proc, message)
            
        except Exception as e:
            logger.error(f"Error logging event message: {e}")
    
    def run(self):
        """Основной цикл мониторинга"""
        try:
            self.initialize_bpf()
            self.running = True
            
            logger.info("=== CONTAINER SECURITY MONITOR STARTED ===")
            logger.info("Monitoring for container escape attacks:")
            logger.info("  - CVE-2022-0492 (cgroup release_agent escape)")
            logger.info("  - Docker socket access from containers")
            logger.info("  - Mount operations")
            logger.info("  - GDB attach and memory write operations")
            logger.info("  - Kernel module loading")
            logger.info("  - Block device creation (mknod)")
            logger.info("  - Proc/sys write operations")
            logger.info("")
            logger.info("%-12s %-7s %-14s %-7s %-40s      %-16s %s" % 
                       ("CONTAINER_ID", "PID", "PCONTAINER_ID", "PPID", "PCOMM", "COMM", "MESSAGE"))
            
            # Основной цикл обработки событий
            while self.running:
                try:
                    self.bpf.perf_buffer_poll(timeout=1000)  # 1 секунда таймаут
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    logger.error(f"Error in event polling: {e}")
                    
        except Exception as e:
            logger.error(f"Critical error in monitor: {e}")
            return 1
        finally:
            logger.info("Container security monitor stopped")
            return 0

def main():
    parser = argparse.ArgumentParser(description='eBPF Container Security Monitor')
    parser.add_argument('--config', '-c', 
                       help='Configuration file path',
                       default='/etc/ebpf-monitor/config.json')
    parser.add_argument('--debug', '-d', 
                       action='store_true',
                       help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Проверяем права root
    if os.geteuid() != 0:
        logger.error("This program requires root privileges to load eBPF programs")
        return 1
    
    monitor = EBPFMonitor(config_file=args.config)
    return monitor.run()

if __name__ == "__main__":
    sys.exit(main()) 