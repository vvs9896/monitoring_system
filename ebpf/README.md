# eBPF Container Security Monitor

Системный сервис для мониторинга контейнеров против атак container escape с использованием eBPF технологий.

## Обзор

eBPF Container Security Monitor - это высокопроизводительная система мониторинга безопасности контейнеров, которая использует eBPF (extended Berkeley Packet Filter) для отслеживания системных вызовов и обнаружения потенциальных атак типа container escape.

### Обнаруживаемые атаки

- **CVE-2022-0492**: Escape через cgroup release_agent
- **Docker Socket Access**: Доступ к Docker socket из контейнеров
- **Mount Operations**: Подозрительные операции монтирования
- **GDB Attach**: Отладка процессов и запись в память
- **Kernel Module Loading**: Загрузка модулей ядра из контейнеров
- **Block Device Creation**: Создание блочных устройств (mknod)
- **Proc/Sys Write**: Запись в критичные файлы /proc и /sys

## Архитектура

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│   eBPF Kernel   │───▶│   Python     │───▶│   RabbitMQ      │
│   Programs      │    │   Agent      │    │   Queue         │
└─────────────────┘    └──────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────┐
                       │   journald   │
                       │   Logging    │
                       └──────────────┘
```

## Требования

- Linux kernel 4.15+ с поддержкой eBPF
- Python 3.6+
- BCC (Berkeley Packet Filter Compiler Collection)
- RabbitMQ Server
- Root привилегии для загрузки eBPF программ

## Быстрая установка

```bash
# Клонирование репозитория
git clone <repository-url>
cd monitoring-system/ebpf

# Установка сервиса
sudo make install

# Запуск сервиса
sudo make start
```

## Установка зависимостей

### Ubuntu/Debian

```bash
# Обновление пакетов
sudo apt update

# Установка BCC
sudo apt install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)

# Установка Python зависимостей
pip3 install pika

# Установка RabbitMQ (если не установлен)
sudo apt install rabbitmq-server
sudo systemctl enable rabbitmq-server
sudo systemctl start rabbitmq-server
```

### Настройка RabbitMQ

```bash
# Создание пользователя
sudo rabbitmqctl add_user admin admin
sudo rabbitmqctl set_permissions -p / admin ".*" ".*" ".*"
sudo rabbitmqctl set_user_tags admin administrator

# Включение веб-интерфейса управления
sudo rabbitmq-plugins enable rabbitmq_management
sudo systemctl restart rabbitmq-server
```

## Конфигурация

Конфигурационный файл: `/etc/ebpf-monitor/config.json`

```json
{
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
  },
  "logging": {
    "level": "INFO"
  }
}
```

## Использование

### Управление сервисом

```bash
# Установка
make install

# Запуск
make start

# Остановка
make stop

# Перезапуск
make restart

# Статус
make status

# Просмотр логов
make logs

# Просмотр последних логов
make logs-recent

# Тестирование установки
make test

# Удаление
make uninstall
```

### Systemctl команды

```bash
# Запуск сервиса
sudo systemctl start ebpf-monitor

# Остановка сервиса
sudo systemctl stop ebpf-monitor

# Автозапуск
sudo systemctl enable ebpf-monitor

# Статус сервиса
sudo systemctl status ebpf-monitor

# Логи сервиса
sudo journalctl -u ebpf-monitor -f
```

### Просмотр логов

```bash
# В реальном времени
sudo journalctl -u ebpf-monitor -f

# За последний час
sudo journalctl -u ebpf-monitor --since "1 hour ago"

# С определенной даты
sudo journalctl -u ebpf-monitor --since "2024-01-01"

# Только критичные события
sudo journalctl -u ebpf-monitor -p crit
```

## Формат событий

События логируются в структурированном формате:

```
CONTAINER_ID PID    PCONTAINER_ID  PPID    PCOMM                                     ->  COMM             MESSAGE
a1b2c3d4e5f6 12345  g7h8i9j0k1l2   1234    /usr/bin/bash                         ->  curl             [DOCKER-SOCK] connecting to /var/run/docker.sock
```

Где:
- `CONTAINER_ID`: ID контейнера (первые 12 символов)
- `PID`: ID процесса
- `PCONTAINER_ID`: ID контейнера родительского процесса
- `PPID`: ID родительского процесса
- `PCOMM`: Команда родительского процесса
- `COMM`: Команда процесса
- `MESSAGE`: Описание события

## Уровни критичности

- **CRITICAL**: Критичные события требующие немедленного реагирования
  - GDB attach операции
  - Загрузка модулей ядра
  - Создание блочных устройств
  - Запись в /proc/sys
  - Создание привилегированных контейнеров

- **MEDIUM**: События средней критичности
  - Доступ к Docker socket
  - Подозрительные mount операции

- **INFO**: Информационные события
  - Обычные операции монтирования
  - Стандартные системные вызовы

## Мониторинг производительности

### Системные ресурсы

Сервис ограничен по ресурсам:
- Максимум 512MB памяти
- Максимум 50% CPU
- Максимум 65536 открытых файлов

### Метрики

Для мониторинга производительности используйте:

```bash
# Использование памяти
sudo systemctl show ebpf-monitor --property=MemoryCurrent

# Использование CPU
sudo systemctl show ebpf-monitor --property=CPUUsageNSec

# Статус процесса
sudo systemctl show ebpf-monitor --property=MainPID
```

## Отладка

### Проверка статуса

```bash
# Проверка установки
make test

# Детальный статус сервиса
sudo systemctl status ebpf-monitor -l --no-pager

# Проверка зависимостей
python3 -c "import bcc; print('BCC OK')"
python3 -c "import pika; print('Pika OK')"
```

### Общие проблемы

1. **BCC не установлен**
   ```bash
   sudo apt install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
   ```

2. **Нет прав root**
   ```bash
   sudo systemctl start ebpf-monitor
   ```

3. **RabbitMQ не запущен**
   ```bash
   sudo systemctl start rabbitmq-server
   ```

4. **Ошибки eBPF**
   - Проверьте версию ядра: `uname -r`
   - Убедитесь что CONFIG_BPF=y в конфигурации ядра

### Логи отладки

```bash
# Включение debug логирования
sudo systemctl edit ebpf-monitor

# Добавить:
[Service]
Environment=PYTHONUNBUFFERED=1
ExecStart=
ExecStart=/usr/bin/python3 /opt/ebpf-monitor/ebpf_monitor.py --config /etc/ebpf-monitor/config.json --debug
```

## Файловая структура

```
/opt/ebpf-monitor/
├── ebpf_monitor.py      # Основная программа
├── ebpf_agent.c         # eBPF программа
└── util.py              # Утилиты

/etc/ebpf-monitor/
└── config.json          # Конфигурация

/etc/systemd/system/
└── ebpf-monitor.service # Systemd unit файл

/var/log/
└── журналы в journald
```

## Безопасность

- Сервис запускается от root (требуется для eBPF)
- Использует systemd security features:
  - `PrivateTmp=true`
  - `ProtectHome=true`
  - `ProtectSystem=strict`
- Ограничения ресурсов через systemd
- Персистентные сообщения в RabbitMQ

## Лицензия

[Укажите лицензию]

## Поддержка

Для получения поддержки:
1. Проверьте логи: `sudo journalctl -u ebpf-monitor`
2. Запустите тесты: `make test`
3. Создайте issue в репозитории 