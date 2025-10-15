# Container Security Monitoring System

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Status](https://img.shields.io/badge/Status-Production%20Ready-green.svg)
![Version](https://img.shields.io/badge/Version-1.0.0-orange.svg)

Система мониторинга безопасности контейнеров против атак **Container Escape** с использованием eBPF, машинного обучения и автоматического реагирования.

## 🎯 Описание

Container Security Monitoring System - это комплексное решение для мониторинга и защиты Docker контейнеров от атак типа Container Escape. Система анализирует системные вызовы в реальном времени, выявляет подозрительную активность и автоматически реагирует на угрозы.

## ✨ Основные возможности

### 🔍 Мониторинг в реальном времени
- **eBPF агент** для мониторинга системных вызовов
- **Анализ событий** с определением уровня критичности
- **WebSocket обновления** интерфейса в реальном времени
- **События каждую секунду** на timeline графике

### 🧠 Интеллектуальный анализ
- **Сигнатурный анализ** известных техник атак
- **Поведенческий анализ** (готов к ML интеграции)
- **MITRE ATT&CK** база знаний техник Container Escape
- **Автоматическое определение критичности** событий

### ⚡ Автоматическое реагирование
- **Критичные события**: автоматическая остановка контейнера + email уведомление
- **Средние события**: email уведомление администратору
- **Информационные события**: логирование без действий
- **Настраиваемые правила** реагирования

### 🌐 Современный веб-интерфейс
- **Real-time dashboard** с графиками и статистикой
- **Events Timeline** - график событий по секундам
- **Severity Distribution** - круговая диаграмма критичности
- **Управление контейнерами** прямо из интерфейса
- **MITRE ATT&CK** справочник техник атак

## 🏗️ Архитектура системы

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   eBPF Agent    │───▶│     RabbitMQ     │───▶│ Analysis Server │
│  (Python/BCC)  │    │   (Message Bus)  │    │   (Go/Golang)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                        │
┌─────────────────┐    ┌──────────────────┐            ▼
│ Web Interface   │◄───│   TimescaleDB    │◄───────────────────────┐
│ (Go/Gin + JS)   │    │  (Time Series)   │                        │
└─────────────────┘    └──────────────────┘                        │
         ▲                                                          ▼
         │              ┌──────────────────┐              ┌─────────────────┐
         └──────────────│    WebSocket     │              │ Response Module │
                        │   (Real-time)    │              │   (Go/Docker)   │
                        └──────────────────┘              └─────────────────┘
```

### Компоненты системы

#### 1. **eBPF Agent** (`ebpf/`)
- Мониторинг системных вызовов на уровне ядра
- Детекция подозрительной активности контейнеров
- Отправка событий в RabbitMQ
- Работает как systemd сервис

#### 2. **Analysis Server** (`analysis-server/`)
- Получение событий из RabbitMQ
- Сигнатурный анализ событий
- Определение уровня критичности
- Сохранение в TimescaleDB
- Отправка в Response Module

#### 3. **Response Module** (`response-module/`)
- Автоматическое реагирование на критичные события
- Остановка подозрительных контейнеров
- Email уведомления администратору
- Логирование всех действий

#### 4. **Web Interface** (`web-interface/`)
- Real-time dashboard
- Управление системой
- Просмотр событий и статистики
- Интеграция с другими компонентами

#### 5. **TimescaleDB**
- Хранение временных рядов событий
- Быстрые запросы по времени
- Аналитика и отчетность

#### 6. **RabbitMQ**
- Асинхронная обработка сообщений
- Надежная доставка событий
- Масштабируемость системы

## 🚀 Быстрый старт

### Предварительные требования

- **OS**: Linux (Ubuntu 20.04+ / Debian 11+ / CentOS 8+)
- **Docker**: версия 20.04+
- **Go**: версия 1.21+
- **Python**: версия 3.8+
- **PostgreSQL**: версия 13+
- **RabbitMQ**: версия 3.8+

### Установка системы

#### 1. Установка eBPF Agent
```bash
cd ebpf/
make install
make start
```

#### 2. Установка Analysis Server
```bash
cd analysis-server/
make install
make start
```

#### 3. Установка Response Module
```bash
cd response-module/
make install
make start
```

#### 4. Установка Web Interface
```bash
cd web-interface/
make install
make start
```

### Проверка установки

```bash
# Проверка статуса всех сервисов
systemctl status ebpf-monitor
systemctl status analysis-engine
systemctl status response-module
systemctl status web-interface

# Проверка логов
journalctl -u ebpf-monitor -f
journalctl -u analysis-engine -f
journalctl -u response-module -f
journalctl -u web-interface -f
```

## 🔧 Конфигурация

### eBPF Agent (`ebpf/config.json`)
```json
{
  "rabbitmq": {
    "host": "localhost",
    "port": 5672,
    "username": "guest",
    "password": "guest",
    "queue": "security_events",
    "exchange": "events"
  },
  "monitoring": {
    "syscalls": ["mknod", "mount", "unshare", "setns"],
    "containers_only": true,
    "log_level": "INFO"
  }
}
```

### Analysis Server (`analysis-server/configs/analysis.json`)
```json
{
  "rabbitmq": {
    "host": "localhost",
    "port": 5672,
    "username": "guest",
    "password": "guest"
  },
  "database": {
    "host": "localhost",
    "port": 5432,
    "user": "postgres",
    "password": "postgres",
    "dbname": "monitoring"
  },
  "response_rabbitmq": {
    "host": "localhost",
    "port": 5672,
    "queue": "response_queue",
    "exchange": "response_exchange"
  }
}
```

### Response Module (`response-module/config.json`)
```json
{
  "rabbitmq": {
    "host": "localhost",
    "port": 5672,
    "username": "guest",
    "password": "guest",
    "queue": "response_queue"
  },
  "email": {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "your-email@gmail.com",
    "password": "your-app-password",
    "to": "admin@company.com"
  },
  "docker": {
    "socket": "/var/run/docker.sock"
  }
}
```

## 📊 Использование

### Веб-интерфейс

Откройте в браузере:
- **http://localhost:8080** - основной интерфейс
- **http://your-server-ip:8080** - удаленный доступ

#### Основные разделы:

1. **Dashboard** - обзор системы в реальном времени
   - Статистика событий (Critical/Medium/Info)
   - Events Timeline - график событий по секундам
   - Severity Distribution - круговая диаграмма
   - Последние события

2. **Events** - детальный просмотр событий
   - Фильтрация по критичности
   - Фильтрация по времени
   - Полная информация о событиях

3. **Containers** - управление контейнерами
   - Список всех контейнеров
   - Информация о состоянии
   - Кнопки управления (остановка)

4. **MITRE ATT&CK** - база знаний
   - Техники Container Escape
   - Описание атак
   - Методы защиты

5. **Services** - ссылки на сервисы
   - RabbitMQ Management
   - Другие веб-интерфейсы

6. **System Status** - статус системы
   - Состояние всех сервисов
   - Использование ресурсов
   - Время работы

### Мониторинг событий

#### Типы событий:
- **DEVICE_CREATION** - создание блочных устройств (mknod)
- **MOUNT_OPERATION** - монтирование файловых систем
- **DOCKER_SOCKET_ACCESS** - доступ к Docker socket
- **NAMESPACE_MANIPULATION** - манипуляции с namespaces

#### Уровни критичности:
- 🔴 **CRITICAL** (90-100 баллов) - немедленная остановка контейнера
- 🟡 **MEDIUM** (50-89 баллов) - email уведомление
- ⚪ **INFO** (0-49 баллов) - только логирование

### API Endpoints

```bash
# Статистика событий
GET /api/stats

# Список событий
GET /api/events?limit=100&severity=CRITICAL

# Список контейнеров
GET /api/containers

# Остановка контейнера
POST /api/containers/{id}/stop

# Данные для графиков
GET /api/timeseries?hours=24

# Техники MITRE ATT&CK
GET /api/mitre

# Статус системы
GET /api/system
```

## 🔐 Безопасность

### Обнаруживаемые атаки

#### Container Escape техники:
1. **Privileged Container Abuse**
   - Доступ к /dev/
   - Монтирование host файловых систем

2. **Docker Socket Exposure**
   - Доступ к /var/run/docker.sock
   - Создание привилегированных контейнеров

3. **Kernel Exploits**
   - CVE-2022-0492 (cgroups v1)
   - Другие kernel vulnerabilities

4. **Resource Abuse**
   - Несанкционированное монтирование
   - Создание device файлов

### Методы защиты

#### Превентивные меры:
- Использование непривилегированных контейнеров
- Ограничение capabilities
- Применение AppArmor/SELinux профилей
- Сокрытие Docker socket

#### Реактивные меры:
- Автоматическая остановка подозрительных контейнеров
- Немедленное уведомление администратора
- Детальное логирование всех действий

## 🔍 Диагностика и отладка

### Проверка работы компонентов

```bash
# Статус сервисов
systemctl status ebpf-monitor analysis-engine response-module web-interface

# Логи в реальном времени
journalctl -u ebpf-monitor -f
journalctl -u analysis-engine -f

# Проверка RabbitMQ
rabbitmqctl list_queues
rabbitmqctl list_exchanges

# Проверка базы данных
sudo -u postgres psql monitoring -c "SELECT COUNT(*) FROM events;"

# Проверка Docker
docker ps -a
```

### Частые проблемы

#### eBPF Agent не запускается
```bash
# Проверка kernel headers
uname -r
ls /lib/modules/$(uname -r)/build

# Установка headers
sudo apt install linux-headers-$(uname -r)
```

#### RabbitMQ connection failed
```bash
# Проверка статуса RabbitMQ
systemctl status rabbitmq-server

# Проверка портов
netstat -tlnp | grep 5672

# Проверка пользователей
sudo rabbitmqctl list_users
```

#### База данных недоступна
```bash
# Проверка PostgreSQL
systemctl status postgresql

# Подключение к БД
sudo -u postgres psql -d monitoring

# Проверка таблиц
\dt
```

## 📈 Производительность

### Системные требования

#### Минимальные:
- **CPU**: 2 cores
- **RAM**: 4 GB
- **Disk**: 20 GB
- **Network**: 100 Mbps

#### Рекомендуемые:
- **CPU**: 4+ cores
- **RAM**: 8+ GB
- **Disk**: 50+ GB SSD
- **Network**: 1 Gbps

### Оптимизация

#### eBPF Agent:
- Фильтрация событий по контейнерам
- Batch отправка в RabbitMQ
- Настройка log_level

#### Analysis Server:
- Batch обработка событий
- Connection pooling для БД
- Кэширование правил анализа

#### TimescaleDB:
- Настройка retention policy
- Индексы по времени и severity
- Партицирование таблиц

## 🚢 Развертывание

### Docker Compose (рекомендуется)
```yaml
version: '3.8'
services:
  rabbitmq:
    image: rabbitmq:3-management
    ports:
      - "5672:5672"
      - "15672:15672"
    environment:
      RABBITMQ_DEFAULT_USER: guest
      RABBITMQ_DEFAULT_PASS: guest

  timescaledb:
    image: timescale/timescaledb:latest-pg13
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: monitoring
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    volumes:
      - timescaledb_data:/var/lib/postgresql/data

  web-interface:
    build: ./web-interface
    ports:
      - "8080:8080"
    depends_on:
      - rabbitmq
      - timescaledb

volumes:
  timescaledb_data:
```

### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: container-security-monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: security-monitoring
  template:
    metadata:
      labels:
        app: security-monitoring
    spec:
      containers:
      - name: web-interface
        image: security-monitoring/web-interface:latest
        ports:
        - containerPort: 8080
        env:
        - name: DB_HOST
          value: "timescaledb-service"
        - name: RABBITMQ_HOST
          value: "rabbitmq-service"
```

## 🤝 Разработка

### Структура проекта
```
Monitoring_System/
├── ebpf/                 # eBPF агент мониторинга
│   ├── ebpf_monitor.py   # Основной скрипт
│   ├── util.py           # Утилиты
│   ├── config.json       # Конфигурация
│   └── Makefile          # Сборка и установка
├── analysis-server/      # Сервер анализа
│   ├── main.go           # Основной код
│   ├── signature/        # Сигнатурный анализ
│   ├── behavioral/       # Поведенческий анализ
│   └── configs/          # Конфигурации
├── response-module/      # Модуль реагирования
│   ├── main.go           # Основной код
│   ├── config.json       # Конфигурация
│   └── Makefile          # Сборка
├── web-interface/        # Веб-интерфейс
│   ├── cmd/server/       # HTTP сервер
│   ├── internal/         # Внутренняя логика
│   ├── static/           # CSS/JS файлы
│   └── templates/        # HTML шаблоны
└── docs/                 # Документация
    └── README.md         # Этот файл
```

### Добавление новых правил анализа

1. Откройте `analysis-server/signature/analyzer.go`
2. Добавьте новое правило в `classifyEventType()`
3. Обновите `calculateThreatScore()`
4. Пересоберите: `make build && make install`

### Добавление новых типов событий

1. Обновите eBPF программу в `ebpf/ebpf_monitor.py`
2. Добавьте обработку в Analysis Server
3. Обновите веб-интерфейс для отображения

## 📞 Поддержка

### Логи системы
```bash
# Все логи системы мониторинга
journalctl -u ebpf-monitor -u analysis-engine -u response-module -u web-interface -f

# Логи с определенного времени
journalctl -u ebpf-monitor --since "2024-01-01 10:00:00"

# Логи с ошибками
journalctl -u analysis-engine -p err
```

### Мониторинг производительности
```bash
# Использование ресурсов сервисами
systemctl show ebpf-monitor --property=MemoryCurrent
systemctl show analysis-engine --property=CPUUsageNSec

# Статистика базы данных
sudo -u postgres psql monitoring -c "
SELECT schemaname, tablename, n_tup_ins, n_tup_upd, n_tup_del 
FROM pg_stat_user_tables WHERE tablename='events';
"
```

### Резервное копирование
```bash
# Резервная копия конфигураций
tar -czf monitoring-configs-$(date +%Y%m%d).tar.gz \
    ebpf/config.json \
    analysis-server/configs/ \
    response-module/config.json

# Резервная копия базы данных
sudo -u postgres pg_dump monitoring > monitoring-backup-$(date +%Y%m%d).sql
```

## 📄 Лицензия

MIT License - см. файл [LICENSE](../LICENSE)

## 🙏 Благодарности

- **BCC (BPF Compiler Collection)** - для eBPF функциональности
- **Go Gin Framework** - для веб-интерфейса
- **Chart.js** - для графиков в реальном времени
- **RabbitMQ** - для надежной обработки сообщений
- **TimescaleDB** - для эффективного хранения временных рядов

---

**Container Security Monitoring System** - Защита ваших контейнеров 24/7 🛡️

Для получения поддержки: 
1. Проверьте логи: `sudo journalctl -u <service-name>`
2. Запустите тесты: `make test`
3. Создайте issue в репозитории 