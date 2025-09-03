package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/rabbitmq/amqp091-go"
)

// Configuration структура для конфигурации сервиса
type Configuration struct {
	RabbitMQ struct {
		Host       string `json:"host"`
		Port       int    `json:"port"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		Queue      string `json:"queue"`
		Exchange   string `json:"exchange"`
		RoutingKey string `json:"routing_key"`
	} `json:"rabbitmq"`

	Database struct {
		Host            string `json:"host"`
		Port            int    `json:"port"`
		Username        string `json:"username"`
		Password        string `json:"password"`
		Database        string `json:"database"`
		SSLMode         string `json:"ssl_mode"`
		MaxConnections  int    `json:"max_connections"`
		ConnMaxLifetime int    `json:"conn_max_lifetime_minutes"`
	} `json:"database"`

	Processing struct {
		BatchSize     int `json:"batch_size"`
		FlushInterval int `json:"flush_interval_seconds"`
		RetryAttempts int `json:"retry_attempts"`
		RetryDelay    int `json:"retry_delay_seconds"`
	} `json:"processing"`

	Logging struct {
		Level string `json:"level"`
	} `json:"logging"`
}

// EnrichedEvent структура обогащенного события (должна совпадать с analysis-engine)
type EnrichedEvent struct {
	Type      string  `json:"type"`
	Message   Message `json:"message"`
	Severity  string  `json:"severity"`
	Timestamp string  `json:"timestamp"`

	BehavioralSeverity string    `json:"behavioral_severity,omitempty"`
	Confidence         float64   `json:"confidence,omitempty"`
	ProcessedAt        time.Time `json:"processed_at"`
	AnalysisVersion    string    `json:"analysis_version"`
	ThreatScore        int       `json:"threat_score"`
	Recommendations    []string  `json:"recommendations,omitempty"`
}

type Message struct {
	ContainerID       string `json:"container_id"`
	PID               int    `json:"pid"`
	ParentContainerID string `json:"parent_container_id"`
	PPID              int    `json:"ppid"`
	ParentComm        string `json:"parent_comm"`
	Comm              string `json:"comm"`
	Message           string `json:"message"`
}

// DataPersistenceService сервис для сохранения данных
type DataPersistenceService struct {
	config        Configuration
	rabbitConn    *amqp091.Connection
	rabbitChannel *amqp091.Channel
	db            *sql.DB
	eventBatch    []EnrichedEvent
	batchMutex    sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

// NewDataPersistenceService создает новый экземпляр сервиса
func NewDataPersistenceService(configPath string) (*DataPersistenceService, error) {
	config, err := loadConfiguration(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	service := &DataPersistenceService{
		config:     config,
		eventBatch: make([]EnrichedEvent, 0, config.Processing.BatchSize),
		ctx:        ctx,
		cancel:     cancel,
	}

	return service, nil
}

func loadConfiguration(configPath string) (Configuration, error) {
	var config Configuration

	// Значения по умолчанию
	config.RabbitMQ.Host = "localhost"
	config.RabbitMQ.Port = 5672
	config.RabbitMQ.Username = "admin"
	config.RabbitMQ.Password = "admin"
	config.RabbitMQ.Queue = "analyzed_events_queue"
	config.RabbitMQ.Exchange = "events_exchange"
	config.RabbitMQ.RoutingKey = "analyzed_event_key"

	config.Database.Host = "localhost"
	config.Database.Port = 5432
	config.Database.Username = "postgres"
	config.Database.Password = "postgres"
	config.Database.Database = "monitoring"
	config.Database.SSLMode = "disable"
	config.Database.MaxConnections = 10
	config.Database.ConnMaxLifetime = 60

	config.Processing.BatchSize = 10
	config.Processing.FlushInterval = 5
	config.Processing.RetryAttempts = 3
	config.Processing.RetryDelay = 1

	config.Logging.Level = "INFO"

	if configPath != "" && fileExists(configPath) {
		file, err := os.Open(configPath)
		if err != nil {
			return config, err
		}
		defer file.Close()

		decoder := json.NewDecoder(file)
		if err := decoder.Decode(&config); err != nil {
			return config, err
		}
		log.Printf("Loaded configuration from %s", configPath)
	} else {
		log.Printf("Using default configuration")
	}

	return config, nil
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

// Start запускает сервис
func (dps *DataPersistenceService) Start() error {
	log.Printf("Starting Data Persistence Service...")

	// Подключение к базе данных
	if err := dps.connectDatabase(); err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Подключение к RabbitMQ
	if err := dps.connectRabbitMQ(); err != nil {
		return fmt.Errorf("failed to connect to RabbitMQ: %w", err)
	}

	// Создание таблиц если не существуют
	if err := dps.createTables(); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Настройка обработчиков сигналов
	dps.setupSignalHandlers()

	// Запуск обработчиков
	dps.wg.Add(2)
	go dps.processEvents()
	go dps.flushBatchPeriodically()

	log.Printf("Data Persistence Service started successfully")
	log.Printf("Configuration:")
	log.Printf("  - Database: %s@%s:%d/%s", dps.config.Database.Username, dps.config.Database.Host, dps.config.Database.Port, dps.config.Database.Database)
	log.Printf("  - Batch Size: %d", dps.config.Processing.BatchSize)
	log.Printf("  - Flush Interval: %ds", dps.config.Processing.FlushInterval)

	// Ожидание завершения
	dps.wg.Wait()
	return nil
}

func (dps *DataPersistenceService) connectDatabase() error {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		dps.config.Database.Host,
		dps.config.Database.Port,
		dps.config.Database.Username,
		dps.config.Database.Password,
		dps.config.Database.Database,
		dps.config.Database.SSLMode)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return err
	}

	// Настройка пула подключений
	db.SetMaxOpenConns(dps.config.Database.MaxConnections)
	db.SetMaxIdleConns(dps.config.Database.MaxConnections / 2)
	db.SetConnMaxLifetime(time.Duration(dps.config.Database.ConnMaxLifetime) * time.Minute)

	// Проверка подключения
	if err := db.Ping(); err != nil {
		db.Close()
		return err
	}

	dps.db = db
	log.Printf("Connected to TimescaleDB at %s:%d", dps.config.Database.Host, dps.config.Database.Port)
	return nil
}

func (dps *DataPersistenceService) connectRabbitMQ() error {
	connStr := fmt.Sprintf("amqp://%s:%s@%s:%d/",
		dps.config.RabbitMQ.Username,
		dps.config.RabbitMQ.Password,
		dps.config.RabbitMQ.Host,
		dps.config.RabbitMQ.Port)

	conn, err := amqp091.Dial(connStr)
	if err != nil {
		return err
	}

	channel, err := conn.Channel()
	if err != nil {
		conn.Close()
		return err
	}

	dps.rabbitConn = conn
	dps.rabbitChannel = channel

	// Объявляем очередь
	_, err = channel.QueueDeclare(
		dps.config.RabbitMQ.Queue,
		true,  // durable
		false, // delete when unused
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)

	log.Printf("Connected to RabbitMQ at %s:%d", dps.config.RabbitMQ.Host, dps.config.RabbitMQ.Port)
	return err
}

func (dps *DataPersistenceService) createTables() error {
	// Создаем расширенную таблицу событий
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS events (
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
	`

	if _, err := dps.db.Exec(createTableQuery); err != nil {
		return err
	}

	// Создаем hypertable если это TimescaleDB
	hypertableQuery := `
	SELECT create_hypertable('events', 'time', if_not_exists => TRUE);
	`

	if _, err := dps.db.Exec(hypertableQuery); err != nil {
		log.Printf("Warning: Failed to create hypertable (not TimescaleDB?): %v", err)
	}

	// Создаем индексы для производительности
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);`,
		`CREATE INDEX IF NOT EXISTS idx_events_container_id ON events(container_id);`,
		`CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);`,
		`CREATE INDEX IF NOT EXISTS idx_events_threat_score ON events(threat_score);`,
	}

	for _, indexQuery := range indexes {
		if _, err := dps.db.Exec(indexQuery); err != nil {
			log.Printf("Warning: Failed to create index: %v", err)
		}
	}

	log.Printf("Database tables and indexes created successfully")
	return nil
}

func (dps *DataPersistenceService) processEvents() {
	defer dps.wg.Done()

	msgs, err := dps.rabbitChannel.Consume(
		dps.config.RabbitMQ.Queue,
		"",    // consumer
		false, // auto-ack (используем manual ack)
		false, // exclusive
		false, // no local
		false, // no wait
		nil,   // args
	)
	if err != nil {
		log.Printf("Failed to register consumer: %v", err)
		return
	}

	log.Printf("Waiting for analyzed events...")

	for {
		select {
		case <-dps.ctx.Done():
			log.Printf("Stopping event processing...")
			dps.flushBatch() // Сохраняем оставшиеся события
			return
		case msg, ok := <-msgs:
			if !ok {
				log.Printf("Message channel closed")
				return
			}

			if err := dps.handleEvent(msg); err != nil {
				log.Printf("Error handling event: %v", err)
				msg.Nack(false, true) // Nack и возвращаем в очередь
			} else {
				msg.Ack(false)
			}
		}
	}
}

func (dps *DataPersistenceService) handleEvent(msg amqp091.Delivery) error {
	var event EnrichedEvent
	if err := json.Unmarshal(msg.Body, &event); err != nil {
		return fmt.Errorf("failed to unmarshal event: %w", err)
	}

	// Добавляем событие в батч
	dps.batchMutex.Lock()
	dps.eventBatch = append(dps.eventBatch, event)
	shouldFlush := len(dps.eventBatch) >= dps.config.Processing.BatchSize
	dps.batchMutex.Unlock()

	// Сбрасываем батч если он полный
	if shouldFlush {
		if err := dps.flushBatch(); err != nil {
			return fmt.Errorf("failed to flush batch: %w", err)
		}
	}

	return nil
}

func (dps *DataPersistenceService) flushBatchPeriodically() {
	defer dps.wg.Done()

	ticker := time.NewTicker(time.Duration(dps.config.Processing.FlushInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-dps.ctx.Done():
			return
		case <-ticker.C:
			if err := dps.flushBatch(); err != nil {
				log.Printf("Error flushing batch: %v", err)
			}
		}
	}
}

func (dps *DataPersistenceService) flushBatch() error {
	dps.batchMutex.Lock()
	if len(dps.eventBatch) == 0 {
		dps.batchMutex.Unlock()
		return nil
	}

	events := make([]EnrichedEvent, len(dps.eventBatch))
	copy(events, dps.eventBatch)
	dps.eventBatch = dps.eventBatch[:0] // Очищаем батч
	dps.batchMutex.Unlock()

	return dps.insertEventsBatch(events)
}

func (dps *DataPersistenceService) insertEventsBatch(events []EnrichedEvent) error {
	if len(events) == 0 {
		return nil
	}

	// Начинаем транзакцию
	tx, err := dps.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Подготавливаем запрос
	query := `
	INSERT INTO events(
		time, type, container_id, pid, parent_container_id, ppid, parent_comm, comm, message, severity,
		behavioral_severity, confidence, processed_at, analysis_version, threat_score, recommendations
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
	`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Вставляем события
	for _, event := range events {
		ts, err := time.Parse(time.RFC1123, event.Timestamp)
		if err != nil {
			log.Printf("Warning: Failed to parse timestamp %s, using current time", event.Timestamp)
			ts = time.Now()
		}

		recommendationsJSON, _ := json.Marshal(event.Recommendations)

		_, err = stmt.Exec(
			ts,
			event.Type,
			event.Message.ContainerID,
			event.Message.PID,
			event.Message.ParentContainerID,
			event.Message.PPID,
			event.Message.ParentComm,
			event.Message.Comm,
			event.Message.Message,
			event.Severity,
			nullableString(event.BehavioralSeverity),
			nullableFloat64(event.Confidence),
			event.ProcessedAt,
			event.AnalysisVersion,
			event.ThreatScore,
			string(recommendationsJSON),
		)
		if err != nil {
			return err
		}
	}

	// Коммитим транзакцию
	if err := tx.Commit(); err != nil {
		return err
	}

	log.Printf("Successfully inserted %d events into database", len(events))
	return nil
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func nullableFloat64(f float64) interface{} {
	if f == 0 {
		return nil
	}
	return f
}

func (dps *DataPersistenceService) setupSignalHandlers() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal %s, shutting down gracefully...", sig)
		dps.Stop()
	}()
}

// Stop останавливает сервис
func (dps *DataPersistenceService) Stop() {
	dps.cancel()

	// Сохраняем оставшиеся события
	if err := dps.flushBatch(); err != nil {
		log.Printf("Error flushing final batch: %v", err)
	}

	if dps.rabbitChannel != nil {
		dps.rabbitChannel.Close()
	}
	if dps.rabbitConn != nil {
		dps.rabbitConn.Close()
	}
	if dps.db != nil {
		dps.db.Close()
	}

	log.Printf("Data Persistence Service stopped")
}

func main() {
	configPath := "/etc/data-persistence/config.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	service, err := NewDataPersistenceService(configPath)
	if err != nil {
		log.Fatalf("Failed to create data persistence service: %v", err)
	}

	if err := service.Start(); err != nil {
		log.Fatalf("Failed to start data persistence service: %v", err)
	}
}
