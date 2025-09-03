import os
import json
import logging
import pika
import stat
from typing import Optional

logger = logging.getLogger('ebpf-monitor')

class RabbitMQConnection:
    """Класс для управления подключением к RabbitMQ"""
    
    def __init__(self, config: dict):
        self.config = config
        self.connection = None
        self.channel = None
        self._setup_connection()
    
    def _setup_connection(self):
        """Установка соединения с RabbitMQ"""
        try:
            rabbitmq_config = self.config.get('rabbitmq', {})
            
            credentials = pika.PlainCredentials(
                rabbitmq_config.get('username', 'admin'),
                rabbitmq_config.get('password', 'admin')
            )
            
            parameters = pika.ConnectionParameters(
                host=rabbitmq_config.get('host', 'localhost'),
                port=rabbitmq_config.get('port', 5672),
                credentials=credentials
            )
            
            self.connection = pika.BlockingConnection(parameters)
            self.channel = self.connection.channel()
            
            # Объявляем exchange
            exchange_name = rabbitmq_config.get('exchange', 'events_exchange')
            self.channel.exchange_declare(
                exchange=exchange_name, 
                exchange_type='direct', 
                durable=True
            )
            
            # Объявляем очередь и привязываем к exchange
            queue_name = rabbitmq_config.get('queue', 'events_queue')
            self.channel.queue_declare(queue=queue_name, durable=True)
            self.channel.queue_bind(
                exchange=exchange_name,
                queue=queue_name,
                routing_key=rabbitmq_config.get('routing_key', 'event_key')
            )
            
            logger.info(f"Connected to RabbitMQ at {rabbitmq_config.get('host', 'localhost')}")
            
        except Exception as e:
            logger.error(f"Failed to connect to RabbitMQ: {e}")
            self.connection = None
            self.channel = None
    
    def publish_message(self, message: str) -> bool:
        """Публикация сообщения в RabbitMQ"""
        if not self.channel:
            logger.warning("RabbitMQ channel not available, attempting to reconnect...")
            self._setup_connection()
            
        if not self.channel:
            return False
            
        try:
            rabbitmq_config = self.config.get('rabbitmq', {})
            
            self.channel.basic_publish(
                exchange=rabbitmq_config.get('exchange', 'events_exchange'),
                routing_key=rabbitmq_config.get('routing_key', 'event_key'),
                body=message.encode('utf-8'),
                properties=pika.BasicProperties(delivery_mode=2)  # Персистентное сообщение
            )
            return True
            
        except Exception as e:
            logger.error(f"Failed to publish message to RabbitMQ: {e}")
            return False
    
    def close(self):
        """Закрытие соединения"""
        if self.connection and not self.connection.is_closed:
            self.connection.close()

# Глобальная переменная для RabbitMQ подключения
_rabbitmq_connection: Optional[RabbitMQConnection] = None

def initialize_rabbitmq(config: dict):
    """Инициализация RabbitMQ подключения"""
    global _rabbitmq_connection
    _rabbitmq_connection = RabbitMQConnection(config)

def get_ppid(pid: int) -> Optional[int]:
    """Получение PPID процесса"""
    try:
        with open(f"/proc/{pid}/status") as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except (IOError, ValueError) as e:
        logger.debug(f"Failed to get PPID for process {pid}: {e}")
        return None

def get_container_id(pid: int) -> str:
    """Получение ID контейнера для процесса"""
    container_id = ""

    try:
        with open(f"/proc/{pid}/cpuset", "r") as cpuset_file:
            cpuset = cpuset_file.read().strip()
    except IOError as e:
        logger.debug(f"Failed to read cpuset for process {pid}: {e}")
        return container_id
    
    if "/docker" in cpuset:
        container_id = cpuset.split("/")[-1].replace("docker-", "")[:12]
    elif cpuset and cpuset != "/":
        # Попытка извлечь ID из других типов контейнеров
        parts = cpuset.split("/")
        if len(parts) > 1:
            container_id = parts[-1][:12]

    return container_id if container_id else "-"

def get_pid_realpath(pid: int) -> str:
    """Получение пути к исполняемому файлу процесса"""
    try:
        path = os.readlink(f"/proc/{pid}/exe")
        return path
    except (IOError, OSError) as e:
        logger.debug(f"Failed to get exe path for process {pid}: {e}")
        return ""

def print_event_message(proc, message: str):
    """Вывод и отправка сообщения о событии"""
    # Форматированное сообщение
    formatted_message = "%-12s %-7d %-14s %-7d %-40s  ->  %-16s %s" % (
        proc.container_id, proc.pid, proc.parent_container_id, 
        proc.ppid, proc.parent_comm, proc.comm, message
    )

    # Отправка в RabbitMQ
    if _rabbitmq_connection:
        success = _rabbitmq_connection.publish_message(formatted_message)
        if not success:
            logger.warning("Failed to send message to RabbitMQ")
    else:
        logger.warning("RabbitMQ connection not initialized")

    # Вывод в stdout (будет перехвачен journald)
    print(formatted_message)

class Process:
    """Класс для представления процесса и его метаданных"""
    
    def __init__(self, event):
        # Текущий процесс
        self.pid = event.pid

        # Получение имени команды
        self.comm = self._get_comm_from_event(event)
        if not self.comm:
            self.comm = get_pid_realpath(self.pid) or "-"
        
        self.container_id = get_container_id(self.pid)

        # Родительский процесс
        self.ppid = getattr(event, 'ppid', None)
        if not self.ppid:
            self.ppid = get_ppid(self.pid)

        if self.ppid:
            self.parent_container_id = get_container_id(self.ppid)
            self.parent_comm = get_pid_realpath(self.ppid)
        else:
            self.parent_container_id = "-"
            self.parent_comm = "-"
    
    def _get_comm_from_event(self, event) -> str:
        """Извлечение имени команды из события"""
        try:
            if hasattr(event, 'comm'):
                return event.comm.decode("ascii", errors="ignore")
        except (AttributeError, UnicodeDecodeError) as e:
            logger.debug(f"Failed to decode comm from event: {e}")
        return ""
    
    def in_container(self) -> bool:
        """Проверка, выполняется ли процесс в контейнере"""
        return self.container_id != "-" and self.container_id != ""
    
    def from_container(self) -> bool:
        """Проверка, запущен ли процесс из контейнера (родитель в контейнере)"""
        return self.parent_container_id != "-" and self.parent_container_id != ""

def create_event_json(proc: Process, message: str, severity: str = "INFO") -> str:
    """Создание JSON представления события для структурированного логирования"""
    event_data = {
        "timestamp": logger.handlers[0].formatter.formatTime(logging.LogRecord("", 0, "", 0, "", (), None)),
        "severity": severity,
        "event_type": "container_security",
        "process": {
            "pid": proc.pid,
            "comm": proc.comm,
            "container_id": proc.container_id
        },
        "parent_process": {
            "pid": proc.ppid,
            "comm": proc.parent_comm,
            "container_id": proc.parent_container_id
        },
        "message": message
    }
    
    return json.dumps(event_data, ensure_ascii=False)

def cleanup_rabbitmq():
    """Очистка ресурсов RabbitMQ"""
    global _rabbitmq_connection
    if _rabbitmq_connection:
        _rabbitmq_connection.close()
        _rabbitmq_connection = None 