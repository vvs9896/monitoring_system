# Архитектура системы

## Обзор архитектуры

Container Security Monitoring System построена по микросервисной архитектуре с асинхронной обработкой событий.

```
┌─────────────────────────────────────────────────────────────────┐
│                        HOST SYSTEM                              │
│  ┌─────────────────┐    ┌──────────────────┐                   │
│  │   eBPF Agent    │    │     Docker       │                   │
│  │  (Kernel Space) │    │   Containers     │                   │
│  │                 │    │                  │                   │
│  │ ┌─────────────┐ │    │ ┌──────────────┐ │                   │
│  │ │ eBPF Program│ │    │ │ Container 1  │ │                   │
│  │ │ (BCC/Python)│ │    │ │ Container 2  │ │                   │
│  │ │             │ │    │ │ Container N  │ │                   │
│  │ └─────────────┘ │    │ └──────────────┘ │                   │
│  └─────────────────┘    └──────────────────┘                   │
│           │                       │                            │
│           └───────────┬───────────┘                            │
│                       │                                        │
│                       ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                MESSAGE BUS                              │   │
│  │                                                         │   │
│  │ ┌─────────────────┐    ┌──────────────────┐             │   │
│  │ │    RabbitMQ     │    │     Queues       │             │   │
│  │ │                 │    │ ┌──────────────┐ │             │   │
│  │ │   Exchanges:    │    │ │security_events│ │             │   │
│  │ │   - events      │    │ │response_queue │ │             │   │
│  │ │   - response    │    │ └──────────────┘ │             │   │
│  │ └─────────────────┘    └──────────────────┘             │   │
│  └─────────────────────────────────────────────────────────┘   │
│           │                       │                            │
│           ▼                       ▼                            │
│  ┌─────────────────┐    ┌──────────────────┐                   │
│  │ Analysis Server │    │ Response Module  │                   │
│  │                 │    │                  │                   │
│  │ ┌─────────────┐ │    │ ┌──────────────┐ │                   │
│  │ │ Signature   │ │    │ │ Docker API   │ │                   │
│  │ │ Analysis    │ │    │ │ Integration  │ │                   │
│  │ │             │ │    │ │              │ │                   │
│  │ ├─────────────┤ │    │ ├──────────────┤ │                   │
│  │ │ Behavioral  │ │    │ │ Email        │ │                   │
│  │ │ Analysis    │ │    │ │ Notifications│ │                   │
│  │ │ (ML Ready)  │ │    │ │              │ │                   │
│  │ └─────────────┘ │    │ └──────────────┘ │                   │
│  └─────────────────┘    └──────────────────┘                   │
│           │                                                    │
│           ▼                                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  STORAGE                                │   │
│  │                                                         │   │
│  │ ┌─────────────────┐    ┌──────────────────┐             │   │
│  │ │   TimescaleDB   │    │   Web Interface  │             │   │
│  │ │                 │    │                  │             │   │
│  │ │ ┌─────────────┐ │    │ ┌──────────────┐ │             │   │
│  │ │ │ Events      │ │    │ │ HTTP Server  │ │             │   │
│  │ │ │ Time Series │ │    │ │ (Go/Gin)     │ │             │   │
│  │ │ │             │ │    │ │              │ │             │   │
│  │ │ ├─────────────┤ │    │ ├──────────────┤ │             │   │
│  │ │ │ Indexes     │ │    │ │ WebSocket    │ │             │   │
│  │ │ │ Partitions  │ │    │ │ Real-time    │ │             │   │
│  │ │ │             │ │    │ │              │ │             │   │
│  │ │ └─────────────┘ │    │ └──────────────┘ │             │   │
│  │ └─────────────────┘    └──────────────────┘             │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Компоненты системы

### 1. eBPF Agent

**Назначение**: Мониторинг системных вызовов на уровне ядра Linux

**Технологии**:
- Python 3.8+
- BCC (BPF Compiler Collection)
- eBPF программы на C

**Основные функции**:
- Перехват системных вызовов: `mknod`, `mount`, `unshare`, `setns`
- Фильтрация событий по контейнерам
- Обогащение событий метаданными процессов
- Отправка событий в RabbitMQ

**Архитектурные особенности**:
- Работает в kernel space для минимальной задержки
- Использует eBPF maps для передачи данных в userspace
- Асинхронная отправка событий
- Автоматическое переподключение к RabbitMQ

### 2. Analysis Server

**Назначение**: Анализ событий безопасности и определение угроз

**Технологии**:
- Go 1.21+
- PostgreSQL driver
- RabbitMQ AMQP client

**Модульная архитектура**:

#### Main Package
- Получение событий из RabbitMQ
- Координация между модулями анализа
- Сохранение в базу данных
- Отправка в Response Module

#### Signature Package
- Анализ на основе известных паттернов
- Классификация типов событий
- Расчет threat score (0-100)
- Генерация рекомендаций

#### Behavioral Package (готов к ML)
- Интерфейс для ML моделей
- Поведенческий анализ
- Детекция аномалий
- Корреляция событий

**Алгоритм анализа**:
```go
Event → Parse → Signature Analysis → Behavioral Analysis → 
Score Calculation → Severity Assignment → Database → Response Module
```

### 3. Response Module

**Назначение**: Автоматическое реагирование на угрозы

**Технологии**:
- Go 1.21+
- Docker API client
- SMTP client для email

**Логика реагирования**:
- **CRITICAL** (90-100): Остановка контейнера + Email
- **MEDIUM** (50-89): Только Email уведомление
- **INFO** (0-49): Только логирование

**Компоненты**:
- RabbitMQ consumer
- Docker API интеграция
- Email notification service
- Action logging

### 4. Web Interface

**Назначение**: Веб-интерфейс для мониторинга и управления

**Технологии**:
- Go 1.21+ (Backend)
- Gin HTTP framework
- JavaScript ES6+ (Frontend)
- Chart.js для графиков
- WebSocket для real-time

**Архитектура**:
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend      │    │   HTTP Server    │    │   Database      │
│   (HTML/CSS/JS) │◄──►│   (Go/Gin)       │◄──►│   (TimescaleDB) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         ▲                       ▲                       ▲
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   WebSocket     │    │   API Routes     │    │   Docker API    │
│   Real-time     │    │   REST/JSON      │    │   Integration   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### 5. TimescaleDB

**Назначение**: Хранение временных рядов событий

**Особенности**:
- Расширение PostgreSQL для временных рядов
- Автоматическое партицирование по времени
- Сжатие старых данных
- Быстрые аналитические запросы

**Схема данных**:
```sql
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

-- Hypertable для временных рядов
SELECT create_hypertable('events', 'time');
```

### 6. RabbitMQ

**Назначение**: Асинхронная обработка сообщений

**Топология**:
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   eBPF Agent    │───▶│     Exchange     │───▶│ Analysis Server │
│                 │    │     "events"     │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌──────────────────┐    ┌──────────────────┐
                       │      Queue       │    │     Exchange     │
                       │ "security_events"│    │   "response"     │
                       └──────────────────┘    └──────────────────┘
                                                        │
                                                        ▼
                                               ┌──────────────────┐
                                               │ Response Module  │
                                               │                  │
                                               └──────────────────┘
```

## Потоки данных

### 1. Поток событий безопасности

```
Container Syscall → eBPF Program → eBPF Agent → RabbitMQ → 
Analysis Server → TimescaleDB → Web Interface
```

### 2. Поток реагирования

```
Analysis Server → RabbitMQ → Response Module → Docker API → 
Container Stop + Email Notification
```

### 3. Поток веб-интерфейса

```
User Request → HTTP Server → Database Query → JSON Response → 
Frontend Rendering → WebSocket Updates
```

## Масштабирование

### Горизонтальное масштабирование

**Analysis Server**:
- Множественные инстансы с RabbitMQ load balancing
- Статeless обработка событий
- Shared database для консистентности

**Response Module**:
- Множественные инстансы для отказоустойчивости
- Idempotent операции
- Distributed locking для критических действий

**Web Interface**:
- Load balancer перед HTTP серверами
- Shared session storage (Redis)
- CDN для статических ресурсов

### Вертикальное масштабирование

**eBPF Agent**:
- CPU-bound: больше cores для обработки событий
- Memory: буферы для batch отправки

**TimescaleDB**:
- Memory: кэширование индексов и данных
- Storage: SSD для быстрых запросов
- CPU: параллельные запросы

## Безопасность

### Network Security

**Изоляция компонентов**:
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   DMZ Network   │    │ Internal Network │    │ Database Network│
│                 │    │                  │    │                 │
│ ┌─────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │Web Interface│ │    │ │ Analysis     │ │    │ │ TimescaleDB │ │
│ │   (8080)    │ │    │ │ Server       │ │    │ │   (5432)    │ │
│ └─────────────┘ │    │ │ Response     │ │    │ └─────────────┘ │
│                 │    │ │ Module       │ │    │                 │
│                 │    │ └──────────────┘ │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────┬───────────┘                       │
                     │                                   │
                     ▼                                   │
            ┌──────────────────┐                        │
            │ Message Network  │                        │
            │                  │                        │
            │ ┌──────────────┐ │◄───────────────────────┘
            │ │   RabbitMQ   │ │
            │ │   (5672)     │ │
            │ └──────────────┘ │
            └──────────────────┘
```

### Authentication & Authorization

**Service-to-Service**:
- RabbitMQ: username/password authentication
- Database: role-based access control
- Docker API: socket permissions

**Web Interface**:
- HTTP Basic Auth (расширяемо до OAuth2/JWT)
- RBAC для различных операций
- CSRF protection

### Data Protection

**In Transit**:
- TLS для всех HTTP соединений
- RabbitMQ SSL/TLS encryption
- Database SSL connections

**At Rest**:
- Database encryption
- Log file encryption
- Configuration secrets management

## Мониторинг и наблюдаемость

### Метрики

**System Metrics**:
- CPU, Memory, Disk usage per service
- Network I/O
- Container resource consumption

**Application Metrics**:
- Events processed per second
- Analysis latency
- Response time
- Error rates

**Business Metrics**:
- Security events by severity
- Container escape attempts
- Response effectiveness
- False positive rate

### Логирование

**Structured Logging**:
```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "service": "analysis-server",
  "level": "INFO",
  "event_id": "evt-123",
  "container_id": "abc123",
  "severity": "CRITICAL",
  "threat_score": 95,
  "action": "analysis_completed"
}
```

**Log Aggregation**:
- Centralized logging via syslog
- Log rotation and retention
- Structured search and alerting

### Трассировка

**Distributed Tracing**:
- Request ID propagation через все компоненты
- Performance bottleneck identification
- Error root cause analysis

## Развертывание

### Production Environment

**Infrastructure Requirements**:
- Load Balancer (nginx/HAProxy)
- Container Orchestration (Docker Compose/Kubernetes)
- Service Discovery (Consul/etcd)
- Secret Management (Vault/Kubernetes Secrets)

**High Availability Setup**:
```yaml
services:
  web-interface:
    replicas: 3
    deploy:
      placement:
        constraints: [node.role == worker]
  
  analysis-server:
    replicas: 2
    deploy:
      placement:
        constraints: [node.role == worker]
  
  timescaledb:
    replicas: 1
    deploy:
      placement:
        constraints: [node.role == manager]
      resources:
        reservations:
          memory: 4G
```

### CI/CD Pipeline

**Build Stage**:
1. Code compilation and testing
2. Docker image creation
3. Security scanning
4. Artifact storage

**Deploy Stage**:
1. Infrastructure provisioning
2. Service deployment
3. Health checks
4. Rollback capabilities

### Backup and Recovery

**Database Backup**:
- Continuous WAL archiving
- Point-in-time recovery
- Cross-region replication

**Configuration Backup**:
- Version controlled configurations
- Automated backup verification
- Disaster recovery procedures

## Производительность

### Оптимизация eBPF Agent

**Event Filtering**:
- Kernel-space filtering для снижения overhead
- Container-specific monitoring
- Syscall whitelist/blacklist

**Batch Processing**:
- Агрегация событий перед отправкой
- Compression для network efficiency
- Adaptive batching на основе load

### Оптимизация Analysis Server

**Concurrent Processing**:
- Goroutine pools для параллельной обработки
- Channel-based communication
- Non-blocking I/O operations

**Caching Strategy**:
- In-memory rule cache
- Database query result caching
- Redis для shared cache

### Database Optimization

**Indexing Strategy**:
```sql
-- Time-based queries
CREATE INDEX idx_events_time ON events (time DESC);

-- Severity filtering
CREATE INDEX idx_events_severity ON events (severity);

-- Container-specific queries
CREATE INDEX idx_events_container_id ON events (container_id);

-- Composite index для complex queries
CREATE INDEX idx_events_time_severity ON events (time DESC, severity);
```

**Partitioning**:
- Automatic time-based partitioning
- Partition pruning для query optimization
- Old partition cleanup

**Query Optimization**:
- Prepared statements
- Connection pooling
- Query plan analysis

## Расширяемость

### Plugin Architecture

**Analysis Plugins**:
```go
type AnalysisPlugin interface {
    Name() string
    Analyze(event Event) (AnalysisResult, error)
    Configure(config map[string]interface{}) error
}
```

**Notification Plugins**:
```go
type NotificationPlugin interface {
    Name() string
    Send(notification Notification) error
    Configure(config map[string]interface{}) error
}
```

### API Extensions

**REST API**:
- Versioned endpoints
- OpenAPI specification
- SDK generation

**GraphQL API** (будущее расширение):
- Flexible data querying
- Real-time subscriptions
- Schema evolution

### Integration Points

**External SIEM Integration**:
- Syslog forwarding
- REST API webhooks
- Standard formats (CEF, STIX)

**Threat Intelligence Integration**:
- IOC feeds integration
- Threat score enrichment
- Attribution information

---

Эта архитектура обеспечивает:
- **Масштабируемость**: горизонтальное и вертикальное масштабирование
- **Отказоустойчивость**: graceful degradation и автоматическое восстановление
- **Безопасность**: defense in depth и least privilege
- **Наблюдаемость**: comprehensive monitoring и debugging
- **Расширяемость**: plugin architecture и API-first подход 