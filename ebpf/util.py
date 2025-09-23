import os
import pika
import logging

# Глобальные переменные для подключения
connection = None
channel = None

def init_rabbitmq():
    """Инициализация подключения к RabbitMQ"""
    global connection, channel
    
    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='localhost', credentials=pika.PlainCredentials('admin', 'admin'))
        )
        channel = connection.channel()

        # Объявляем exchange
        channel.exchange_declare(exchange='events_exchange', exchange_type='direct', durable=True)

        # Объявляем очередь и привязываем к exchange
        channel.queue_declare(queue='events_queue', durable=True)
        channel.queue_bind(
            exchange='events_exchange',
            queue='events_queue',
            routing_key='event_key'
        )
        return True
    except Exception as e:
        logging.error(f"Failed to connect to RabbitMQ: {e}")
        connection = None
        channel = None
        return False

def ensure_connection():
    """Проверяет и восстанавливает соединение при необходимости"""
    global connection, channel
    
    if connection is None or connection.is_closed or channel is None or channel.is_closed:
        return init_rabbitmq()
    return True

# Инициализация при загрузке модуля
init_rabbitmq()

def get_ppid(pid):
    try:
        with open(f"/proc/{pid}/status") as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        return None

def get_container_id(pid):
    container_id = ""

    try:
        with open(f"/proc/{pid}/cpuset", "r") as cpuset_file:
            cpuset = cpuset_file.read()
    except IOError:
        return container_id
    
    if "/docker" in cpuset:
        container_id = cpuset.split("/")[-1].replace("docker-", "")[:12]

    return container_id

def get_pid_realpath(pid):
    try:
        path = os.readlink(f"/proc/{pid}/exe")
    except IOError:
        return ""
    
    return path

# def print_event_message(proc, message):
#     print("%-12s %-7d %-14s %-7d %-40s  ->  %-16s %s" % 
#     (proc.container_id, proc.pid, proc.parent_container_id, proc.ppid, proc.parent_comm, proc.comm, message))

def print_event_message(proc, message):
    global channel
    
    # Форматы сообщения
    formatted_message = "%-12s %-7d %-14s %-7d %-40s  ->  %-16s %s" % (
        proc.container_id, proc.pid, proc.parent_container_id, proc.ppid, proc.parent_comm, proc.comm, message)

    # Проверяем соединение и переподключаемся при необходимости
    if not ensure_connection():
        logging.error("Failed to ensure RabbitMQ connection")
        print(formatted_message)  # Выводим локально если RabbitMQ недоступен
        return

    try:
        # Отправка в RabbitMQ
        channel.basic_publish(
            exchange='events_exchange',
            routing_key='event_key',
            body=formatted_message.encode('utf-8'),
            properties=pika.BasicProperties(
                delivery_mode = 2  # Персистентное сообщение
            )
        )
        print(formatted_message)
    except Exception as e:
        logging.error(f"Failed to send message to RabbitMQ: {e}")
        # Сбрасываем соединение для переподключения в следующий раз
        try:
            if channel:
                channel.close()
            if connection:
                connection.close()
        except:
            pass
        globals()['connection'] = None
        globals()['channel'] = None
        print(formatted_message)  # Выводим локально при ошибке

class Process:
    def __init__(self, event):
        # current
        self.pid          = event.pid

        self.comm = None
        try:
            self.comm         = event.comm.decode("ascii", errors="ignore")
        except:
            if not self.comm:
                self.comm = get_pid_realpath(self.pid)
            else:
                self.comm = "-"
        
        self.container_id = get_container_id(self.pid)

        # parent
        self.ppid = event.ppid
        if not self.ppid:
            self.ppid = get_ppid(self.pid)

        if self.ppid:
            self.parent_container_id = get_container_id(self.ppid)
            self.parent_comm         = get_pid_realpath(self.ppid)
        else:
            self.parent_container_id = "-"
            self.parent_comm         = "-"
    
    def in_container(self):
        if self.container_id != "-":
            return True
        else:
            return False
    
    def from_container(self):
        if self.parent_container_id != "-":
            return True
        else:
            return False
