# Container Security Analysis Services

Модульная система анализа событий безопасности контейнеров с поддержкой сигнатурного и поведенческого анализа.

## Архитектура

Система разделена на **2 независимых сервиса**:

### 1. **Analysis Engine Service** 
Основной сервис анализа событий:
- **RabbitMQ Consumer** - получает события от eBPF монитора
- **Event Parser** - парсит события в структуры данных
- **Signature Analyzer** - выполняет сигнатурный анализ на основе правил
- **Behavioral Analyzer** - интерфейс для ML-анализа (готов к расширению)
- **Event Enrichment** - обогащает события дополнительными данными
- **Result Publisher** - отправляет обработанные события дальше

### 2. **Data Persistence Service**
Сервис сохранения и управления данными:
- **Batch Processing** - группировка событий для эффективной записи
- **TimescaleDB Writer** - запись в базу данных временных рядов
- **Data Archival** - архивирование старых данных
- **Performance Optimization** - оптимизация запросов и индексов

## Преимущества модульной архитектуры

### ✅ **Разделение ответственности**
- Анализ и сохранение данных независимы
- Легко масштабировать каждый компонент отдельно
- Упрощенная отладка и мониторинг

### ✅ **Готовность к ML интеграции**
- Интерфейс `BehavioralAnalyzer` готов к подключению ML моделей
- Система хранения контекста для поведенческого анализа
- Комбинирование результатов сигнатурного и поведенческого анализа

### ✅ **Производительность**
- Batch processing для эффективной записи в БД
- Асинхронная обработка событий
- Connection pooling для базы данных

### ✅ **Надежность**
- Graceful shutdown с сохранением данных
- Retry механизмы для отказоустойчивости
- Manual acknowledgment в RabbitMQ

## Требования

- Go 1.19+
- RabbitMQ Server
- PostgreSQL/TimescaleDB
- Системные привилегии для установки systemd сервисов

## Быстрая установка

```bash
# Перейти в директорию
cd analysis-server

# Собрать сервисы
make build

# Установить как systemd сервисы
sudo make install

# Запустить сервисы
sudo make start
```

## Конфигурация

### Analysis Engine (`/etc/analysis-engine/config.json`)
```json
{
  "rabbitmq": {
    "host": "localhost",
    "port": 5672,
    "username": "admin",
    "password": "admin",
    "input_queue": "events_queue",
    "output_queue": "analyzed_events_queue"
  },
  "analysis": {
    "enable_signature_analysis": true,
    "enable_behavioral_analysis": false,
    "batch_size": 1,
    "processing_timeout_seconds": 30
  }
}
```

### Data Persistence (`/etc/data-persistence/config.json`)
```json
{
  "database": {
    "host": "localhost",
    "port": 5432,
    "username": "postgres",
    "password": "postgres",
    "database": "monitoring"
  },
  "processing": {
    "batch_size": 10,
    "flush_interval_seconds": 5,
    "retry_attempts": 3
  }
}
```

## Управление сервисами

### Основные команды
```bash
# Сборка
make build              # Собрать оба сервиса
make build-ae           # Собрать только Analysis Engine
make build-dp           # Собрать только Data Persistence

# Установка
make install            # Установить оба сервиса
make install-ae         # Установить только Analysis Engine
make install-dp         # Установить только Data Persistence

# Управление
make start              # Запустить оба сервиса
make stop               # Остановить оба сервиса
make restart            # Перезапустить оба сервиса
make status             # Показать статус сервисов

# Логи
make logs               # Логи обоих сервисов в реальном времени
make logs-ae            # Логи Analysis Engine
make logs-dp            # Логи Data Persistence
make logs-recent        # Недавние логи

# Тестирование
make test               # Проверить установку
make dev-test           # Тесты разработки
```

### Systemctl команды
```bash
# Analysis Engine
sudo systemctl start analysis-engine
sudo systemctl stop analysis-engine
sudo systemctl status analysis-engine
sudo journalctl -u analysis-engine -f

# Data Persistence
sudo systemctl start data-persistence
sudo systemctl stop data-persistence
sudo systemctl status data-persistence
sudo journalctl -u data-persistence -f
```

## Структура обогащенных событий

События после анализа содержат:

```json
{
  "type": "DOCKER_SOCKET_ACCESS",
  "message": {
    "container_id": "a1b2c3d4e5f6",
    "pid": 12345,
    "parent_container_id": "g7h8i9j0k1l2",
    "ppid": 1234,
    "parent_comm": "/usr/bin/bash",
    "comm": "curl",
    "message": "[DOCKER-SOCK] connecting to /var/run/docker.sock"
  },
  "severity": "MEDIUM",
  "timestamp": "Mon, 02 Jan 2006 15:04:05 MST",
  "behavioral_severity": "MEDIUM",
  "confidence": 0.85,
  "processed_at": "2024-01-02T15:04:05Z",
  "analysis_version": "1.0.0",
  "threat_score": 70,
  "recommendations": [
    "Monitor container activity closely",
    "Audit Docker socket access permissions"
  ]
}
```

## База данных

### Схема таблицы событий
```sql
CREATE TABLE events (
    time TIMESTAMPTZ NOT NULL,
    type TEXT NOT NULL,
    container_id TEXT,
    pid INT,
    parent_container_id TEXT,
    ppid INT,
    parent_comm TEXT,
    comm TEXT,
    message TEXT,
    severity TEXT NOT NULL,
    behavioral_severity TEXT,
    confidence FLOAT,
    processed_at TIMESTAMPTZ,
    analysis_version TEXT,
    threat_score INT,
    recommendations JSONB
);

-- TimescaleDB hypertable
SELECT create_hypertable('events', 'time');
```

### Индексы для производительности
- `idx_events_severity` - по уровню критичности
- `idx_events_container_id` - по ID контейнера
- `idx_events_type` - по типу события
- `idx_events_threat_score` - по уровню угрозы

## Интеграция ML компонента

Для добавления поведенческого анализа:

1. **Реализуйте интерфейс `BehavioralAnalyzer`**:
```go
type BehavioralAnalyzer interface {
    AnalyzeEvent(event analysis.Event, context []analysis.Event) (severity string, confidence float64, err error)
    UpdateModel(events []analysis.Event) error
    IsEnabled() bool
}
```

2. **Замените `MockBehavioralAnalyzer`** на реальную реализацию
3. **Включите в конфигурации**: `"enable_behavioral_analysis": true`

### Пример ML интеграции
```go
type IsolationForestAnalyzer struct {
    model *isolation.Forest
    enabled bool
}

func (ifa *IsolationForestAnalyzer) AnalyzeEvent(event analysis.Event, context []analysis.Event) (string, float64, error) {
    // Извлечение признаков из события и контекста
    features := extractFeatures(event, context)
    
    // Предсказание аномальности
    score := ifa.model.Predict(features)
    
    // Определение критичности на основе аномальности
    if score > 0.8 {
        return "CRITICAL", score, nil
    } else if score > 0.6 {
        return "MEDIUM", score, nil
    }
    
    return event.Severity, score, nil
}
```

## Мониторинг и метрики

### Системные ресурсы
- **Analysis Engine**: до 1GB RAM, до 80% CPU
- **Data Persistence**: до 512MB RAM, до 50% CPU

### Ключевые метрики
```bash
# Производительность
sudo systemctl show analysis-engine --property=MemoryCurrent
sudo systemctl show data-persistence --property=CPUUsageNSec

# Статистика обработки
sudo journalctl -u analysis-engine | grep "processed successfully"
sudo journalctl -u data-persistence | grep "Successfully inserted"
```

## Отладка

### Общие проблемы

1. **Сервисы не запускаются**
   ```bash
   # Проверить зависимости
   sudo systemctl status rabbitmq-server postgresql
   
   # Проверить права доступа
   sudo ls -la /opt/analysis-engine /opt/data-persistence
   
   # Проверить конфигурацию
   sudo journalctl -u analysis-engine -u data-persistence --since "5 minutes ago"
   ```

2. **События не обрабатываются**
   ```bash
   # Проверить очереди RabbitMQ
   sudo rabbitmqctl list_queues name messages
   
   # Проверить подключение к БД
   sudo -u postgres psql -d monitoring -c "SELECT COUNT(*) FROM events;"
   ```

3. **Высокое потребление ресурсов**
   ```bash
   # Настроить batch_size в конфигурации
   # Уменьшить flush_interval_seconds
   # Проверить индексы в БД
   ```

## Файловая структура

```
/opt/analysis-engine/          # Бинарный файл Analysis Engine
/opt/data-persistence/         # Бинарный файл Data Persistence
/etc/analysis-engine/          # Конфигурация Analysis Engine
/etc/data-persistence/         # Конфигурация Data Persistence
/var/log/analysis-engine/      # Логи Analysis Engine
/var/log/data-persistence/     # Логи Data Persistence
/var/lib/analysis/             # Рабочие данные
```

## Безопасность

- Сервисы запускаются от пользователя `analysis` (не root)
- systemd security features включены
- Ограничения ресурсов через systemd
- Защищенные директории и файлы конфигурации

## Roadmap

- [ ] **Поведенческий анализ**: Интеграция Isolation Forest модели
- [ ] **Response Service**: Автоматическое реагирование на угрозы
- [ ] **Web Dashboard**: Веб-интерфейс для мониторинга
- [ ] **API Gateway**: REST API для внешних интеграций
- [ ] **Metrics Export**: Prometheus метрики
- [ ] **Distributed Processing**: Поддержка кластеризации

## Лицензия

[Укажите лицензию]

## Поддержка

Для получения поддержки:
1. Проверьте логи: `sudo make logs`
2. Запустите тесты: `make test`
3. Создайте issue в репозитории 