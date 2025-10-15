# API Documentation

Container Security Monitoring System предоставляет REST API для интеграции с внешними системами и автоматизации.

## Base URL

```
http://localhost:8080/api
```

## Аутентификация

В текущей версии API не требует аутентификации. В production среде рекомендуется добавить HTTP Basic Auth или JWT токены.

## Общие параметры

### Формат времени
Все временные метки используют RFC3339 format:
```
2024-01-01T12:00:00Z
```

### Коды ответов
- `200 OK` - Успешный запрос
- `400 Bad Request` - Некорректные параметры
- `404 Not Found` - Ресурс не найден
- `500 Internal Server Error` - Внутренняя ошибка сервера

### Формат ошибок
```json
{
  "error": "Описание ошибки",
  "code": "ERROR_CODE",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## Endpoints

### Dashboard

#### GET /api/dashboard
Получение данных для главной страницы dashboard.

**Параметры:** Нет

**Ответ:**
```json
{
  "stats": {
    "critical": 15,
    "medium": 45,
    "info": 120,
    "total": 180
  },
  "recent_events": [
    {
      "id": 123,
      "time": "2024-01-01T12:00:00Z",
      "type": "DEVICE_CREATION",
      "severity": "CRITICAL",
      "container_id": "abc123456789",
      "process_id": 1234,
      "parent_process_id": 1,
      "command": "mknod",
      "parent_command": "/bin/bash",
      "message": "mknod creating block device /dev/sda from container",
      "processed_at": "2024-01-01T12:00:01Z",
      "analysis_version": "1.0",
      "threat_score": 95,
      "behavioral_severity": "",
      "confidence": 0.95,
      "recommendations": [
        "Immediate investigation required",
        "Consider isolating the container",
        "Check device creation permissions"
      ]
    }
  ],
  "container_count": 5,
  "system_status": {
    "ebpf_agent": {
      "name": "ebpf-monitor",
      "status": "active",
      "uptime": "2024-01-01T10:00:00Z",
      "memory": "45MB",
      "cpu": "2.5%",
      "healthy": true
    },
    "analysis_engine": {
      "name": "analysis-engine",
      "status": "active",
      "uptime": "2024-01-01T10:00:00Z",
      "memory": "128MB",
      "cpu": "5.2%",
      "healthy": true
    }
  },
  "time_series": [
    {
      "timestamp": "2024-01-01T11:00:00Z",
      "critical": 2,
      "medium": 8,
      "info": 15
    }
  ]
}
```

### События (Events)

#### GET /api/events
Получение списка событий безопасности.

**Параметры:**
- `limit` (int, optional) - Количество событий (по умолчанию: 100, максимум: 1000)
- `offset` (int, optional) - Смещение для пагинации (по умолчанию: 0)
- `severity` (string, optional) - Фильтр по критичности: `CRITICAL`, `MEDIUM`, `INFO`
- `from` (string, optional) - Начальная дата в формате RFC3339
- `to` (string, optional) - Конечная дата в формате RFC3339
- `container_id` (string, optional) - Фильтр по ID контейнера
- `type` (string, optional) - Фильтр по типу события

**Примеры запросов:**
```bash
# Последние 50 событий
GET /api/events?limit=50

# Только критичные события
GET /api/events?severity=CRITICAL

# События за последний час
GET /api/events?from=2024-01-01T11:00:00Z&to=2024-01-01T12:00:00Z

# События конкретного контейнера
GET /api/events?container_id=abc123456789
```

**Ответ:**
```json
[
  {
    "id": 123,
    "time": "2024-01-01T12:00:00Z",
    "type": "DEVICE_CREATION",
    "severity": "CRITICAL",
    "container_id": "abc123456789",
    "process_id": 1234,
    "parent_process_id": 1,
    "command": "mknod",
    "parent_command": "/bin/bash",
    "message": "mknod creating block device /dev/sda from container",
    "processed_at": "2024-01-01T12:00:01Z",
    "analysis_version": "1.0",
    "threat_score": 95,
    "behavioral_severity": "",
    "confidence": 0.95,
    "recommendations": [
      "Immediate investigation required",
      "Consider isolating the container",
      "Check device creation permissions"
    ]
  }
]
```

### Статистика

#### GET /api/stats
Получение статистики событий.

**Параметры:**
- `hours` (int, optional) - Период для статистики в часах (по умолчанию: 24)

**Примеры:**
```bash
# Статистика за последние 24 часа
GET /api/stats

# Статистика за последнюю неделю
GET /api/stats?hours=168
```

**Ответ:**
```json
{
  "critical": 15,
  "medium": 45,
  "info": 120,
  "total": 180
}
```

#### GET /api/timeseries
Получение данных временных рядов для графиков.

**Параметры:**
- `hours` (int, optional) - Период в часах (по умолчанию: 24)
- `interval` (string, optional) - Интервал группировки: `minute`, `hour`, `day` (по умолчанию: `hour`)

**Ответ:**
```json
[
  {
    "timestamp": "2024-01-01T11:00:00Z",
    "critical": 2,
    "medium": 8,
    "info": 15
  },
  {
    "timestamp": "2024-01-01T12:00:00Z",
    "critical": 3,
    "medium": 12,
    "info": 20
  }
]
```

### Контейнеры

#### GET /api/containers
Получение списка Docker контейнеров.

**Параметры:**
- `status` (string, optional) - Фильтр по статусу: `running`, `exited`, `all` (по умолчанию: `all`)

**Ответ:**
```json
[
  {
    "Id": "abc123456789",
    "Names": ["/web-server"],
    "Image": "nginx:latest",
    "Command": "nginx -g 'daemon off;'",
    "Created": 1704067200,
    "Ports": [
      {
        "IP": "0.0.0.0",
        "PrivatePort": 80,
        "PublicPort": 8080,
        "Type": "tcp"
      }
    ],
    "Labels": {
      "com.docker.compose.service": "web"
    },
    "State": "running",
    "Status": "Up 2 hours"
  }
]
```

#### POST /api/containers/{id}/stop
Остановка контейнера по ID.

**Параметры пути:**
- `id` (string, required) - ID контейнера

**Ответ при успехе:**
```json
{
  "message": "Container stopped successfully",
  "id": "abc123456789"
}
```

**Ответ при ошибке:**
```json
{
  "error": "Failed to stop container",
  "output": "Error response from daemon: No such container: abc123456789"
}
```

### MITRE ATT&CK

#### GET /api/mitre
Получение информации о техниках MITRE ATT&CK для Container Escape.

**Параметры:** Нет

**Ответ:**
```json
[
  {
    "id": "T1611",
    "name": "Escape to Host",
    "description": "Adversaries may break out of a container to gain access to the underlying host.",
    "tactics": ["Privilege Escalation"],
    "techniques": [
      "Container Escape",
      "Privileged Container",
      "Host Network"
    ],
    "mitigation": "Use security profiles like AppArmor or SELinux, avoid privileged containers, implement proper container isolation."
  }
]
```

### Статус системы

#### GET /api/system
Получение статуса всех компонентов системы.

**Параметры:** Нет

**Ответ:**
```json
{
  "ebpf_agent": {
    "name": "ebpf-monitor",
    "status": "active",
    "uptime": "2024-01-01T10:00:00Z",
    "memory": "45MB",
    "cpu": "2.5%",
    "healthy": true
  },
  "analysis_engine": {
    "name": "analysis-engine", 
    "status": "active",
    "uptime": "2024-01-01T10:00:00Z",
    "memory": "128MB",
    "cpu": "5.2%",
    "healthy": true
  },
  "response_module": {
    "name": "response-module",
    "status": "active", 
    "uptime": "2024-01-01T10:00:00Z",
    "memory": "32MB",
    "cpu": "1.8%",
    "healthy": true
  },
  "rabbitmq": {
    "name": "rabbitmq-server",
    "status": "active",
    "uptime": "2024-01-01T09:00:00Z", 
    "memory": "256MB",
    "cpu": "3.2%",
    "healthy": true
  },
  "database": {
    "name": "postgresql",
    "status": "active",
    "uptime": "2024-01-01T09:00:00Z",
    "memory": "512MB", 
    "cpu": "4.5%",
    "healthy": true
  }
}
```

### Сервисы

#### GET /api/services
Получение ссылок на веб-интерфейсы других сервисов.

**Параметры:** Нет

**Ответ:**
```json
{
  "rabbitmq": "http://localhost:15672",
  "timescaledb": "http://localhost:5432",
  "portainer": "http://localhost:9000",
  "grafana": "http://localhost:3000"
}
```

## WebSocket API

### Подключение
```javascript
const ws = new WebSocket('ws://localhost:8080/ws');
```

### Типы сообщений

#### new_event
Новое событие безопасности:
```json
{
  "type": "new_event",
  "data": {
    "id": 123,
    "time": "2024-01-01T12:00:00Z",
    "type": "DEVICE_CREATION",
    "severity": "CRITICAL",
    "container_id": "abc123456789",
    "message": "mknod creating block device /dev/sda from container"
  }
}
```

#### stats_update
Обновление статистики:
```json
{
  "type": "stats_update",
  "data": {
    "critical": 16,
    "medium": 45,
    "info": 120,
    "total": 181
  }
}
```

#### system_status
Обновление статуса системы:
```json
{
  "type": "system_status",
  "data": {
    "ebpf_agent": {
      "name": "ebpf-monitor",
      "status": "active",
      "healthy": true
    }
  }
}
```

## Примеры использования

### Python Client
```python
import requests
import json

# Получение статистики
response = requests.get('http://localhost:8080/api/stats')
stats = response.json()
print(f"Critical events: {stats['critical']}")

# Получение событий
events = requests.get('http://localhost:8080/api/events?severity=CRITICAL&limit=10')
for event in events.json():
    print(f"Event: {event['type']} - {event['message']}")

# Остановка контейнера
container_id = "abc123456789"
response = requests.post(f'http://localhost:8080/api/containers/{container_id}/stop')
if response.status_code == 200:
    print("Container stopped successfully")
```

### JavaScript Client
```javascript
// Получение данных dashboard
async function getDashboardData() {
    const response = await fetch('/api/dashboard');
    const data = await response.json();
    
    console.log('Critical events:', data.stats.critical);
    console.log('Container count:', data.container_count);
    
    return data;
}

// WebSocket подключение
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onmessage = function(event) {
    const message = JSON.parse(event.data);
    
    switch(message.type) {
        case 'new_event':
            console.log('New security event:', message.data);
            break;
        case 'stats_update':
            console.log('Stats updated:', message.data);
            break;
    }
};

// Остановка контейнера
async function stopContainer(containerId) {
    const response = await fetch(`/api/containers/${containerId}/stop`, {
        method: 'POST'
    });
    
    const result = await response.json();
    
    if (response.ok) {
        console.log('Container stopped:', result.message);
    } else {
        console.error('Error stopping container:', result.error);
    }
}
```

### Bash/cURL Examples
```bash
#!/bin/bash

# Получение статистики за последнюю неделю
curl -s "http://localhost:8080/api/stats?hours=168" | jq .

# Получение критичных событий
curl -s "http://localhost:8080/api/events?severity=CRITICAL&limit=5" | jq '.[].message'

# Получение списка контейнеров
curl -s "http://localhost:8080/api/containers" | jq '.[].Names[0]'

# Остановка контейнера
CONTAINER_ID="abc123456789"
curl -X POST "http://localhost:8080/api/containers/$CONTAINER_ID/stop" | jq .

# Мониторинг новых событий (с использованием websocat)
websocat ws://localhost:8080/ws
```

## Rate Limiting

В текущей версии rate limiting не реализован. Рекомендации для production:

- Максимум 100 запросов в минуту на IP
- Максимум 1000 событий в одном запросе
- WebSocket соединения: максимум 10 на IP

## Кэширование

API использует следующую стратегию кэширования:

- **Статистика** (`/api/stats`): кэш 30 секунд
- **Система статус** (`/api/system`): кэш 60 секунд  
- **MITRE данные** (`/api/mitre`): кэш 24 часа
- **События** (`/api/events`): без кэша (real-time)

## Мониторинг API

### Метрики
- Количество запросов в секунду
- Время ответа API
- Количество ошибок
- Активные WebSocket соединения

### Health Check
```bash
# Проверка доступности API
curl -f http://localhost:8080/api/stats > /dev/null

# Проверка WebSocket
websocat --ping-interval 10 ws://localhost:8080/ws
```

## Версионирование

Текущая версия API: **v1**

В будущих версиях планируется:
- **v2**: Добавление аутентификации и авторизации
- **v3**: GraphQL поддержка
- **v4**: gRPC API для высокопроизводительных интеграций

## Ограничения

- Максимум 1000 событий в одном запросе
- Максимальный период для временных рядов: 30 дней
- WebSocket сообщения: максимум 1MB
- Timeout для всех запросов: 30 секунд

---

Для получения поддержки по API:
1. Проверьте логи: `sudo journalctl -u web-interface`
2. Проверьте статус: `curl -I http://localhost:8080/api/stats`
3. Создайте issue в репозитории с примером запроса 