package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"container-security-monitoring/behavioral"
	"container-security-monitoring/signature"

	_ "github.com/lib/pq"
	"github.com/rabbitmq/amqp091-go"
)

type Config struct {
	RabbitMQ struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
		Queue    string `json:"queue"`
		Exchange string `json:"exchange"`
	} `json:"rabbitmq"`
	Database struct {
		Host         string `json:"host"`
		Port         int    `json:"port"`
		Username     string `json:"username"`
		Password     string `json:"password"`
		Database     string `json:"database"`
		SSLMode      string `json:"ssl_mode"`
		MaxConns     int    `json:"max_connections"`
		ConnLifetime int    `json:"conn_max_lifetime_minutes"`
	} `json:"database"`
	Analysis struct {
		EnableSignatureAnalysis  bool `json:"enable_signature_analysis"`
		EnableBehavioralAnalysis bool `json:"enable_behavioral_analysis"`
	} `json:"analysis"`
	Processing struct {
		BatchSize     int `json:"batch_size"`
		FlushInterval int `json:"flush_interval_seconds"`
		RetryAttempts int `json:"retry_attempts"`
		RetryDelay    int `json:"retry_delay_seconds"`
	} `json:"processing"`
}

type AnalysisEngine struct {
	config             Config
	db                 *sql.DB
	rabbitConn         *amqp091.Connection
	rabbitCh           *amqp091.Channel
	signatureAnalyzer  *signature.Analyzer
	behavioralAnalyzer behavioral.Analyzer
	eventBatch         []EnrichedEvent
	batchMutex         sync.Mutex
	shutdown           chan struct{}
	wg                 sync.WaitGroup
}

type ParsedMessage struct {
	ContainerID       string
	PID               int
	ParentContainerID string
	PPID              int
	ParentComm        string
	Comm              string
	Message           string
}

type EnrichedEvent struct {
	Time               time.Time `json:"time"`
	Type               string    `json:"type"`
	Severity           string    `json:"severity"`
	ContainerID        string    `json:"container_id"`
	ProcessID          int       `json:"process_id"`
	ParentProcessID    int       `json:"parent_process_id"`
	Command            string    `json:"command"`
	ParentCommand      string    `json:"parent_command"`
	Message            string    `json:"message"`
	ProcessedAt        time.Time `json:"processed_at"`
	AnalysisVersion    string    `json:"analysis_version"`
	ThreatScore        int       `json:"threat_score"`
	BehavioralSeverity string    `json:"behavioral_severity"`
	Confidence         float64   `json:"confidence"`
	Recommendations    []string  `json:"recommendations"`
}

func NewAnalysisEngine(configPath string) (*AnalysisEngine, error) {
	var config Config

	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &AnalysisEngine{
		config:             config,
		signatureAnalyzer:  signature.NewAnalyzer(),
		behavioralAnalyzer: behavioral.NewMockAnalyzer(),
		eventBatch:         make([]EnrichedEvent, 0, config.Processing.BatchSize),
		shutdown:           make(chan struct{}),
	}, nil
}

func (ae *AnalysisEngine) connectDatabase() error {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		ae.config.Database.Host,
		ae.config.Database.Port,
		ae.config.Database.Username,
		ae.config.Database.Password,
		ae.config.Database.Database,
		ae.config.Database.SSLMode)

	for {
		db, err := sql.Open("postgres", connStr)
		if err != nil {
			log.Printf("Failed to open database: %v, retrying in 5 seconds...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if err := db.Ping(); err != nil {
			db.Close()
			log.Printf("Failed to ping database: %v, retrying in 5 seconds...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		db.SetMaxOpenConns(ae.config.Database.MaxConns)
		db.SetConnMaxLifetime(time.Duration(ae.config.Database.ConnLifetime) * time.Minute)

		ae.db = db
		log.Printf("Connected to database at %s:%d", ae.config.Database.Host, ae.config.Database.Port)
		return nil
	}
}

func (ae *AnalysisEngine) connectRabbitMQ() error {
	connStr := fmt.Sprintf("amqp://%s:%s@%s:%d/",
		ae.config.RabbitMQ.Username,
		ae.config.RabbitMQ.Password,
		ae.config.RabbitMQ.Host,
		ae.config.RabbitMQ.Port)

	for {
		conn, err := amqp091.Dial(connStr)
		if err != nil {
			log.Printf("Failed to connect to RabbitMQ: %v, retrying in 5 seconds...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		ch, err := conn.Channel()
		if err != nil {
			conn.Close()
			log.Printf("Failed to create channel: %v, retrying in 5 seconds...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		ae.rabbitConn = conn
		ae.rabbitCh = ch

		// Объявляем exchange и очередь
		err = ch.ExchangeDeclare(
			ae.config.RabbitMQ.Exchange,
			"direct", true, false, false, false, nil,
		)
		if err != nil {
			ch.Close()
			conn.Close()
			log.Printf("Failed to declare exchange: %v, retrying in 5 seconds...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		_, err = ch.QueueDeclare(
			ae.config.RabbitMQ.Queue,
			true, false, false, false, nil,
		)
		if err != nil {
			ch.Close()
			conn.Close()
			log.Printf("Failed to declare queue: %v, retrying in 5 seconds...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		log.Printf("Connected to RabbitMQ at %s:%d", ae.config.RabbitMQ.Host, ae.config.RabbitMQ.Port)
		return nil
	}
}

func (ae *AnalysisEngine) parseMessage(rawMessage string) (ParsedMessage, error) {
	// Разделяем по стрелке
	parts := strings.Split(rawMessage, " -> ")
	if len(parts) != 2 {
		return ParsedMessage{}, fmt.Errorf("arrow separator not found")
	}

	leftPart := parts[0]
	rightPart := strings.TrimSpace(parts[1])

	// Парсим левую часть по фиксированным позициям
	var msg ParsedMessage
	var err error

	if len(leftPart) < 59 {
		return ParsedMessage{}, fmt.Errorf("message too short")
	}

	// Container ID (12 символов)
	msg.ContainerID = strings.TrimSpace(leftPart[0:12])

	// PID (7 символов, начиная с позиции 12)
	pidStr := strings.TrimSpace(leftPart[12:19])
	if pidStr == "" {
		return ParsedMessage{}, fmt.Errorf("PID is required")
	}
	msg.PID, err = strconv.Atoi(pidStr)
	if err != nil {
		return ParsedMessage{}, fmt.Errorf("invalid PID: %v", err)
	}

	// Parent Container ID (14 символов, начиная с позиции 19)
	msg.ParentContainerID = strings.TrimSpace(leftPart[19:33])

	// PPID (7 символов, начиная с позиции 33)
	ppidStr := strings.TrimSpace(leftPart[33:40])
	if ppidStr != "" {
		msg.PPID, err = strconv.Atoi(ppidStr)
		if err != nil {
			return ParsedMessage{}, fmt.Errorf("invalid PPID: %v", err)
		}
	}

	// Parent Command (40 символов, начиная с позиции 40)
	msg.ParentComm = strings.TrimSpace(leftPart[40:80])

	// Command - это правая часть (до первого пробела)
	commandParts := strings.Fields(rightPart)
	if len(commandParts) > 0 {
		msg.Comm = commandParts[0]
	}

	// Message - вся правая часть
	msg.Message = rightPart

	return msg, nil
}

func (ae *AnalysisEngine) processEvent(rawEvent string) (EnrichedEvent, error) {
	// Парсим сырое событие
	msg, err := ae.parseMessage(rawEvent)
	if err != nil {
		return EnrichedEvent{}, fmt.Errorf("failed to parse message: %w", err)
	}

	// Сигнатурный анализ
	eventType, severity, threatScore := ae.signatureAnalyzer.AnalyzeMessage(
		msg.ContainerID, msg.Comm, msg.Message)

	// Поведенческий анализ (если включен)
	var behavioralSeverity string
	var confidence float64
	if ae.config.Analysis.EnableBehavioralAnalysis {
		behavioralSeverity, confidence, _ = ae.behavioralAnalyzer.AnalyzeEvent(
			eventType, msg.ContainerID, msg.Comm, msg.Message)
		// Комбинируем результаты анализов
		severity = behavioral.CombineSeverities(severity, behavioralSeverity, confidence)
	}

	// Генерируем рекомендации
	recommendations := ae.signatureAnalyzer.GenerateRecommendations(eventType, severity)

	// Создаем обогащенное событие
	enrichedEvent := EnrichedEvent{
		Time:               time.Now(),
		Type:               eventType,
		Severity:           severity,
		ContainerID:        msg.ContainerID,
		ProcessID:          msg.PID,
		ParentProcessID:    msg.PPID,
		Command:            msg.Comm,
		ParentCommand:      msg.ParentComm,
		Message:            msg.Message,
		ProcessedAt:        time.Now(),
		AnalysisVersion:    "1.0",
		ThreatScore:        threatScore,
		BehavioralSeverity: behavioralSeverity,
		Confidence:         confidence,
		Recommendations:    recommendations,
	}

	log.Printf("Event processed successfully: Type=%s, Severity=%s, ThreatScore=%d",
		enrichedEvent.Type, enrichedEvent.Severity, enrichedEvent.ThreatScore)

	return enrichedEvent, nil
}

func (ae *AnalysisEngine) addToBatch(event EnrichedEvent) {
	ae.batchMutex.Lock()
	defer ae.batchMutex.Unlock()

	ae.eventBatch = append(ae.eventBatch, event)

	if len(ae.eventBatch) >= ae.config.Processing.BatchSize {
		go ae.flushBatch()
	}
}

func (ae *AnalysisEngine) flushBatch() {
	ae.batchMutex.Lock()
	if len(ae.eventBatch) == 0 {
		ae.batchMutex.Unlock()
		return
	}

	batch := make([]EnrichedEvent, len(ae.eventBatch))
	copy(batch, ae.eventBatch)
	ae.eventBatch = ae.eventBatch[:0]
	ae.batchMutex.Unlock()

	// Сохраняем в БД с повторными попытками
	for attempt := 0; attempt < ae.config.Processing.RetryAttempts; attempt++ {
		if err := ae.insertBatch(batch); err != nil {
			log.Printf("Failed to insert batch (attempt %d/%d): %v",
				attempt+1, ae.config.Processing.RetryAttempts, err)
			if attempt < ae.config.Processing.RetryAttempts-1 {
				time.Sleep(time.Duration(ae.config.Processing.RetryDelay) * time.Second)
			}
		} else {
			log.Printf("Successfully inserted %d events into database", len(batch))
			return
		}
	}

	log.Printf("Failed to insert batch after %d attempts", ae.config.Processing.RetryAttempts)
}

func (ae *AnalysisEngine) insertBatch(events []EnrichedEvent) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := ae.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO events (
			time, type, severity, container_id, pid, ppid,
			comm, parent_comm, message, processed_at, analysis_version,
			threat_score, behavioral_severity, confidence, recommendations
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, event := range events {
		recommendationsJSON, _ := json.Marshal(event.Recommendations)

		_, err = stmt.Exec(
			event.Time,
			event.Type,
			event.Severity,
			event.ContainerID,
			event.ProcessID,
			event.ParentProcessID,
			event.Command,
			event.ParentCommand,
			event.Message,
			event.ProcessedAt,
			event.AnalysisVersion,
			event.ThreatScore,
			event.BehavioralSeverity,
			event.Confidence,
			string(recommendationsJSON),
		)
		if err != nil {
			return fmt.Errorf("failed to execute statement: %w", err)
		}
	}

	return tx.Commit()
}

func (ae *AnalysisEngine) processEvents() {
	defer ae.wg.Done()

	msgs, err := ae.rabbitCh.Consume(
		ae.config.RabbitMQ.Queue,
		"",    // consumer
		false, // auto-ack
		false, // exclusive
		false, // no-local
		false, // no-wait
		nil,   // args
	)
	if err != nil {
		log.Printf("Failed to register consumer: %v", err)
		return
	}

	flushTicker := time.NewTicker(time.Duration(ae.config.Processing.FlushInterval) * time.Second)
	defer flushTicker.Stop()

	for {
		select {
		case <-ae.shutdown:
			ae.flushBatch()
			return

		case <-flushTicker.C:
			ae.flushBatch()

		case msg, ok := <-msgs:
			if !ok {
				log.Println("RabbitMQ channel closed, attempting to reconnect...")
				if err := ae.connectRabbitMQ(); err != nil {
					log.Printf("Failed to reconnect to RabbitMQ: %v", err)
					return
				}
				// Перезапускаем consumer
				msgs, err = ae.rabbitCh.Consume(
					ae.config.RabbitMQ.Queue,
					"", false, false, false, false, nil,
				)
				if err != nil {
					log.Printf("Failed to restart consumer: %v", err)
					return
				}
				continue
			}

			// Обрабатываем событие
			enrichedEvent, err := ae.processEvent(string(msg.Body))
			if err != nil {
				log.Printf("Failed to process event: %v", err)
				msg.Nack(false, false)
				continue
			}

			// Добавляем в батч
			ae.addToBatch(enrichedEvent)

			// Подтверждаем обработку
			msg.Ack(false)
		}
	}
}

func (ae *AnalysisEngine) setupSignalHandlers() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, shutting down gracefully...", sig)
		close(ae.shutdown)
	}()
}

func (ae *AnalysisEngine) Start() error {
	log.Printf("Starting Container Security Analysis Engine...")

	// Подключение к базе данных
	if err := ae.connectDatabase(); err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Подключение к RabbitMQ
	if err := ae.connectRabbitMQ(); err != nil {
		return fmt.Errorf("failed to connect to RabbitMQ: %w", err)
	}

	// Настройка обработчиков сигналов
	ae.setupSignalHandlers()

	// Запуск обработки событий
	ae.wg.Add(1)
	go ae.processEvents()

	log.Printf("Analysis Engine started successfully")
	log.Printf("Configuration:")
	log.Printf("  - Signature Analysis: %v", ae.config.Analysis.EnableSignatureAnalysis)
	log.Printf("  - Behavioral Analysis: %v", ae.config.Analysis.EnableBehavioralAnalysis)
	log.Printf("  - Input Queue: %s", ae.config.RabbitMQ.Queue)
	log.Printf("  - Batch Size: %d", ae.config.Processing.BatchSize)
	log.Printf("  - Flush Interval: %ds", ae.config.Processing.FlushInterval)

	// Ожидание завершения
	ae.wg.Wait()

	// Закрытие соединений
	if ae.rabbitCh != nil {
		ae.rabbitCh.Close()
	}
	if ae.rabbitConn != nil {
		ae.rabbitConn.Close()
	}
	if ae.db != nil {
		ae.db.Close()
	}

	log.Printf("Analysis Engine stopped")
	return nil
}

func main() {
	configPath := "/etc/analysis-engine/config.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	engine, err := NewAnalysisEngine(configPath)
	if err != nil {
		log.Fatalf("Failed to create analysis engine: %v", err)
	}

	if err := engine.Start(); err != nil {
		log.Fatalf("Failed to start analysis engine: %v", err)
	}
}
