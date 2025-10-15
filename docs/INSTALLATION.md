# Руководство по установке

## Системные требования

### Минимальные требования
- **ОС**: Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+)
- **CPU**: 2 ядра
- **RAM**: 4 GB
- **Диск**: 20 GB свободного места
- **Сеть**: 100 Mbps

### Рекомендуемые требования
- **ОС**: Ubuntu 22.04 LTS
- **CPU**: 4+ ядер
- **RAM**: 8+ GB
- **Диск**: 50+ GB SSD
- **Сеть**: 1 Gbps

## Предварительная подготовка

### 1. Обновление системы
```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Установка базовых зависимостей
```bash
# Основные пакеты
sudo apt install -y curl wget git build-essential

# Python и pip
sudo apt install -y python3 python3-pip python3-dev

# Go language
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### 3. Установка Docker
```bash
# Удаление старых версий
sudo apt remove -y docker docker-engine docker.io containerd runc

# Установка Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Добавление пользователя в группу docker
sudo usermod -aG docker $USER

# Перезагрузка для применения изменений
sudo reboot
```

### 4. Установка PostgreSQL/TimescaleDB
```bash
# Добавление репозитория TimescaleDB
wget --quiet -O - https://packagecloud.io/timescale/timescaledb/gpgkey | sudo apt-key add -
echo "deb https://packagecloud.io/timescale/timescaledb/ubuntu/ $(lsb_release -c -s) main" | sudo tee /etc/apt/sources.list.d/timescaledb.list

# Установка
sudo apt update
sudo apt install -y timescaledb-2-postgresql-14

# Настройка TimescaleDB
sudo timescaledb-tune --quiet --yes

# Перезапуск PostgreSQL
sudo systemctl restart postgresql
```

### 5. Установка RabbitMQ
```bash
# Установка Erlang
sudo apt install -y erlang-nox

# Установка RabbitMQ
sudo apt install -y rabbitmq-server

# Включение management plugin
sudo rabbitmq-plugins enable rabbitmq_management

# Запуск сервиса
sudo systemctl enable rabbitmq-server
sudo systemctl start rabbitmq-server
```

### 6. Установка eBPF зависимостей
```bash
# Kernel headers
sudo apt install -y linux-headers-$(uname -r)

# BCC dependencies
sudo apt install -y bpfcc-tools python3-bpfcc libbpfcc libbpfcc-dev

# Python BCC
pip3 install bcc psutil
```

## Настройка базы данных

### 1. Создание пользователя и базы данных
```bash
sudo -u postgres psql << EOF
CREATE USER monitoring WITH PASSWORD 'monitoring_password';
CREATE DATABASE monitoring OWNER monitoring;
GRANT ALL PRIVILEGES ON DATABASE monitoring TO monitoring;
\q
EOF
```

### 2. Включение TimescaleDB расширения
```bash
sudo -u postgres psql -d monitoring << EOF
CREATE EXTENSION IF NOT EXISTS timescaledb;
\q
EOF
```

### 3. Создание схемы данных
```bash
sudo -u postgres psql -d monitoring << EOF
CREATE TABLE events (
    time TIMESTAMPTZ NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    container_id TEXT,
    pid INTEGER,
    ppid INTEGER,
    comm TEXT,
    parent_comm TEXT,
    message TEXT,
    processed_at TIMESTAMPTZ,
    analysis_version TEXT,
    threat_score INTEGER,
    behavioral_severity TEXT,
    confidence DOUBLE PRECISION,
    recommendations JSONB
);

-- Создание hypertable
SELECT create_hypertable('events', 'time');

-- Создание индексов
CREATE INDEX idx_events_time ON events (time DESC);
CREATE INDEX idx_events_severity ON events (severity);
CREATE INDEX idx_events_container_id ON events (container_id);
CREATE INDEX idx_events_threat_score ON events (threat_score);
CREATE INDEX idx_events_type ON events (type);

-- Установка retention policy (удаление данных старше 30 дней)
SELECT add_retention_policy('events', INTERVAL '30 days');

\q
EOF
```

## Настройка RabbitMQ

### 1. Создание пользователя и виртуального хоста
```bash
# Создание пользователя
sudo rabbitmqctl add_user monitoring monitoring_password
sudo rabbitmqctl set_permissions -p / monitoring ".*" ".*" ".*"
sudo rabbitmqctl set_user_tags monitoring administrator

# Создание exchanges и queues
sudo rabbitmqctl eval '
application:ensure_all_started(rabbitmq_management),
rabbit_exchange:declare({resource, <<"/">>, exchange, <<"events">>}, topic, true, false, false, []),
rabbit_exchange:declare({resource, <<"/">>, exchange, <<"response_exchange">>}, direct, true, false, false, []),
rabbit_amqqueue:declare({resource, <<"/">>, queue, <<"security_events">>}, true, false, [], none),
rabbit_amqqueue:declare({resource, <<"/">>, queue, <<"response_queue">>}, true, false, [], none),
rabbit_binding:add({binding, {resource, <<"/">>, exchange, <<"events">>}, <<"events.#">>, {resource, <<"/">>, queue, <<"security_events">>}, []}),
rabbit_binding:add({binding, {resource, <<"/">>, exchange, <<"response_exchange">>}, <<"response_key">>, {resource, <<"/">>, queue, <<"response_queue">>}, []}).
'
```

### 2. Проверка настройки
```bash
# Проверка пользователей
sudo rabbitmqctl list_users

# Проверка exchanges
sudo rabbitmqctl list_exchanges

# Проверка queues
sudo rabbitmqctl list_queues
```

## Установка компонентов системы

### 1. Клонирование репозитория
```bash
cd /opt
sudo git clone <repository-url> container-security-monitoring
sudo chown -R $USER:$USER container-security-monitoring
cd container-security-monitoring
```

### 2. Установка eBPF Agent

```bash
cd ebpf/

# Создание конфигурации
cat > config.json << EOF
{
  "rabbitmq": {
    "host": "localhost",
    "port": 5672,
    "username": "monitoring",
    "password": "monitoring_password",
    "queue": "security_events",
    "exchange": "events"
  },
  "monitoring": {
    "syscalls": ["mknod", "mount", "unshare", "setns"],
    "containers_only": true,
    "log_level": "INFO"
  }
}
EOF

# Установка Python зависимостей
pip3 install -r requirements.txt

# Установка как systemd сервис
make install
```

### 3. Установка Analysis Server

```bash
cd ../analysis-server/

# Создание конфигурации
mkdir -p configs
cat > configs/analysis.json << EOF
{
  "rabbitmq": {
    "host": "localhost",
    "port": 5672,
    "username": "monitoring",
    "password": "monitoring_password",
    "queue": "security_events",
    "exchange": "events"
  },
  "database": {
    "host": "localhost",
    "port": 5432,
    "user": "monitoring",
    "password": "monitoring_password",
    "dbname": "monitoring"
  },
  "response_rabbitmq": {
    "host": "localhost",
    "port": 5672,
    "username": "monitoring",
    "password": "monitoring_password",
    "queue": "response_queue",
    "exchange": "response_exchange"
  },
  "analysis": {
    "batch_size": 100,
    "timeout": "30s",
    "version": "1.0"
  }
}
EOF

# Сборка и установка
make install
```

### 4. Установка Response Module

```bash
cd ../response-module/

# Создание конфигурации
cat > config.json << EOF
{
  "rabbitmq": {
    "host": "localhost",
    "port": 5672,
    "username": "monitoring",
    "password": "monitoring_password",
    "queue": "response_queue",
    "exchange": "response_exchange"
  },
  "email": {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "your-email@gmail.com",
    "password": "your-app-password",
    "to": "admin@company.com"
  },
  "docker": {
    "socket": "/var/run/docker.sock",
    "timeout": "30s"
  },
  "processing": {
    "batch_size": 10,
    "timeout": "5s"
  }
}
EOF

# Сборка и установка
make install
```

### 5. Установка Web Interface

```bash
cd ../web-interface/

# Сборка и установка
make install
```

## Настройка Email уведомлений

### 1. Настройка Gmail App Password

1. Войдите в Google Account
2. Перейдите в Security → 2-Step Verification
3. В разделе "App passwords" создайте новый пароль
4. Используйте этот пароль в конфигурации Response Module

### 2. Обновление конфигурации
```bash
sudo nano /etc/response-module/config.json

# Замените:
"username": "your-actual-email@gmail.com",
"password": "your-app-password-here",
"to": "admin@your-company.com"
```

### 3. Перезапуск сервиса
```bash
sudo systemctl restart response-module
```

## Запуск и проверка системы

### 1. Запуск всех сервисов
```bash
# Запуск в правильном порядке
sudo systemctl start rabbitmq-server
sudo systemctl start postgresql
sudo systemctl start ebpf-monitor
sudo systemctl start analysis-engine
sudo systemctl start response-module
sudo systemctl start web-interface

# Включение автозапуска
sudo systemctl enable rabbitmq-server
sudo systemctl enable postgresql
sudo systemctl enable ebpf-monitor
sudo systemctl enable analysis-engine
sudo systemctl enable response-module
sudo systemctl enable web-interface
```

### 2. Проверка статуса сервисов
```bash
# Проверка всех сервисов
sudo systemctl status ebpf-monitor analysis-engine response-module web-interface

# Подробная проверка
for service in ebpf-monitor analysis-engine response-module web-interface; do
    echo "=== $service ==="
    sudo systemctl is-active $service
    echo
done
```

### 3. Проверка логов
```bash
# Логи всех сервисов
sudo journalctl -u ebpf-monitor -u analysis-engine -u response-module -u web-interface -f

# Логи отдельных сервисов
sudo journalctl -u ebpf-monitor -n 50
sudo journalctl -u analysis-engine -n 50
sudo journalctl -u response-module -n 50
sudo journalctl -u web-interface -n 50
```

### 4. Проверка подключений
```bash
# Проверка портов
netstat -tlnp | grep -E "(5432|5672|8080)"

# Проверка RabbitMQ
sudo rabbitmqctl list_connections
sudo rabbitmqctl list_consumers

# Проверка базы данных
sudo -u postgres psql -d monitoring -c "SELECT COUNT(*) FROM events;"
```

### 5. Проверка веб-интерфейса
```bash
# Проверка HTTP ответа
curl -I http://localhost:8080

# Проверка API
curl http://localhost:8080/api/stats
curl http://localhost:8080/api/containers
```

## Тестирование системы

### 1. Создание тестового контейнера
```bash
# Запуск контейнера для тестирования
docker run -it --name test-container ubuntu:latest bash
```

### 2. Генерация тестовых событий
```bash
# В контейнере выполните:
# Создание device файла (должно вызвать CRITICAL событие)
mknod /tmp/test_device c 1 3

# Попытка монтирования (должно вызвать событие)
mount -t tmpfs tmpfs /tmp/test_mount 2>/dev/null || true

# Выход из контейнера
exit
```

### 3. Проверка обработки событий
```bash
# Проверка в базе данных
sudo -u postgres psql -d monitoring -c "
SELECT time, type, severity, container_id, threat_score 
FROM events 
ORDER BY time DESC 
LIMIT 10;
"

# Проверка в веб-интерфейсе
curl http://localhost:8080/api/events?limit=5
```

### 4. Тестирование Response Module
```bash
# Создание CRITICAL события должно остановить контейнер
docker ps -a | grep test-container

# Проверка email уведомлений в логах
sudo journalctl -u response-module | grep -i email
```

## Настройка мониторинга

### 1. Настройка logrotate
```bash
sudo cat > /etc/logrotate.d/container-security-monitoring << EOF
/var/log/container-security-monitoring/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF
```

### 2. Настройка cron для очистки
```bash
# Добавление задачи очистки старых данных
sudo crontab -e

# Добавьте строку:
0 2 * * * /usr/bin/sudo -u postgres psql -d monitoring -c "SELECT drop_chunks('events', INTERVAL '60 days');" >/dev/null 2>&1
```

### 3. Мониторинг дискового пространства
```bash
# Скрипт мониторинга
sudo cat > /usr/local/bin/monitor-disk-space.sh << EOF
#!/bin/bash
THRESHOLD=80
USAGE=\$(df /var/lib/postgresql | tail -1 | awk '{print \$5}' | sed 's/%//')
if [ \$USAGE -gt \$THRESHOLD ]; then
    echo "Database disk usage is \$USAGE%" | mail -s "Disk Space Warning" admin@company.com
fi
EOF

sudo chmod +x /usr/local/bin/monitor-disk-space.sh

# Добавление в cron
echo "0 */6 * * * /usr/local/bin/monitor-disk-space.sh" | sudo crontab -
```

## Настройка файрвола

### 1. UFW (Ubuntu Firewall)
```bash
# Включение UFW
sudo ufw enable

# Разрешение SSH
sudo ufw allow ssh

# Разрешение веб-интерфейса
sudo ufw allow 8080/tcp

# Разрешение RabbitMQ Management (опционально)
sudo ufw allow 15672/tcp

# Проверка правил
sudo ufw status
```

### 2. Iptables (альтернативный вариант)
```bash
# Разрешение входящих соединений
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 15672 -j ACCEPT

# Сохранение правил
sudo iptables-save > /etc/iptables/rules.v4
```

## Оптимизация производительности

### 1. Настройка PostgreSQL
```bash
sudo nano /etc/postgresql/14/main/postgresql.conf

# Добавьте или измените:
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200

# Перезапуск PostgreSQL
sudo systemctl restart postgresql
```

### 2. Настройка RabbitMQ
```bash
sudo nano /etc/rabbitmq/rabbitmq.conf

# Добавьте:
vm_memory_high_watermark.relative = 0.6
disk_free_limit.relative = 2.0
cluster_partition_handling = ignore

# Перезапуск RabbitMQ
sudo systemctl restart rabbitmq-server
```

### 3. Настройка системных лимитов
```bash
sudo nano /etc/security/limits.conf

# Добавьте:
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768

# Настройка systemd лимитов
sudo nano /etc/systemd/system.conf

# Раскомментируйте и измените:
DefaultLimitNOFILE=65536
DefaultLimitNPROC=32768

# Перезагрузка для применения
sudo reboot
```

## Резервное копирование

### 1. Скрипт резервного копирования базы данных
```bash
sudo cat > /usr/local/bin/backup-monitoring-db.sh << EOF
#!/bin/bash
BACKUP_DIR="/var/backups/monitoring"
DATE=\$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="monitoring_backup_\$DATE.sql"

# Создание директории
mkdir -p \$BACKUP_DIR

# Создание резервной копии
sudo -u postgres pg_dump monitoring > \$BACKUP_DIR/\$BACKUP_FILE

# Сжатие
gzip \$BACKUP_DIR/\$BACKUP_FILE

# Удаление старых копий (старше 7 дней)
find \$BACKUP_DIR -name "*.sql.gz" -mtime +7 -delete

echo "Backup completed: \$BACKUP_DIR/\$BACKUP_FILE.gz"
EOF

sudo chmod +x /usr/local/bin/backup-monitoring-db.sh

# Добавление в cron (ежедневно в 3:00)
echo "0 3 * * * /usr/local/bin/backup-monitoring-db.sh" | sudo crontab -
```

### 2. Резервное копирование конфигураций
```bash
sudo cat > /usr/local/bin/backup-configs.sh << EOF
#!/bin/bash
BACKUP_DIR="/var/backups/monitoring-configs"
DATE=\$(date +%Y%m%d_%H%M%S)

mkdir -p \$BACKUP_DIR

tar -czf \$BACKUP_DIR/configs_\$DATE.tar.gz \
    /etc/ebpf-monitor/ \
    /etc/analysis-engine/ \
    /etc/response-module/ \
    /etc/web-interface/ \
    /opt/container-security-monitoring/

# Удаление старых копий (старше 30 дней)
find \$BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete

echo "Config backup completed: \$BACKUP_DIR/configs_\$DATE.tar.gz"
EOF

sudo chmod +x /usr/local/bin/backup-configs.sh

# Добавление в cron (еженедельно)
echo "0 4 * * 0 /usr/local/bin/backup-configs.sh" | sudo crontab -
```

## Обновление системы

### 1. Обновление компонентов
```bash
# Остановка сервисов
sudo systemctl stop web-interface response-module analysis-engine ebpf-monitor

# Обновление кода
cd /opt/container-security-monitoring
git pull

# Пересборка компонентов
cd analysis-server && make build && sudo make install
cd ../response-module && make build && sudo make install
cd ../web-interface && make build && sudo make install

# Запуск сервисов
sudo systemctl start ebpf-monitor analysis-engine response-module web-interface
```

### 2. Проверка после обновления
```bash
# Проверка статуса
sudo systemctl status ebpf-monitor analysis-engine response-module web-interface

# Проверка логов
sudo journalctl -u analysis-engine -n 20

# Проверка веб-интерфейса
curl http://localhost:8080/api/stats
```

## Устранение неисправностей

### 1. eBPF Agent не запускается
```bash
# Проверка kernel headers
ls /lib/modules/$(uname -r)/build

# Установка headers если отсутствуют
sudo apt install linux-headers-$(uname -r)

# Проверка BCC
python3 -c "import bcc; print('BCC OK')"

# Проверка прав доступа
sudo usermod -aG docker ebpf-monitor
```

### 2. Analysis Server не подключается к RabbitMQ
```bash
# Проверка RabbitMQ
sudo systemctl status rabbitmq-server
sudo rabbitmqctl status

# Проверка пользователя
sudo rabbitmqctl list_users

# Проверка соединений
sudo rabbitmqctl list_connections
```

### 3. Web Interface недоступен
```bash
# Проверка порта
netstat -tlnp | grep 8080

# Проверка логов
sudo journalctl -u web-interface -f

# Проверка файрвола
sudo ufw status
```

### 4. База данных недоступна
```bash
# Проверка PostgreSQL
sudo systemctl status postgresql

# Проверка подключения
sudo -u postgres psql -d monitoring -c "SELECT 1;"

# Проверка дискового пространства
df -h /var/lib/postgresql
```

---

После выполнения всех шагов система Container Security Monitoring должна быть полностью установлена и готова к работе. Веб-интерфейс будет доступен по адресу http://localhost:8080, а все компоненты системы будут работать в автоматическом режиме. 