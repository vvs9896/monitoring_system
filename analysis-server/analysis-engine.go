package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"container-security-monitoring/analysis"

	"github.com/rabbitmq/amqp091-go"
)

// Configuration структура для конфигурации сервиса
type Configuration struct {
	RabbitMQ struct {
		Host        string `json:"host"`
		Port        int    `json:"port"`
		Username    string `json:"username"`
		Password    string `json:"password"`
		InputQueue  string `json:"input_queue"`
		OutputQueue string `json:"output_queue"`
		Exchange    string `json:"exchange"`
		RoutingKey  string `json:"routing_key"`
		ResponseKey string `json:"response_key"`
	} `json:"rabbitmq"`

	Analysis struct {
		EnableSignatureAnalysis  bool `json:"enable_signature_analysis"`
		EnableBehavioralAnalysis bool `json:"enable_behavioral_analysis"`
		BatchSize                int  `json:"batch_size"`
		ProcessingTimeout        int  `json:"processing_timeout_seconds"`
	} `json:"analysis"`

	Logging struct {
		Level string `json:"level"`
	} `json:"logging"`
}

// AnalysisEngine основная структура сервиса анализа
type AnalysisEngine struct {
	config             Configuration
	rabbitConn         *amqp091.Connection
	rabbitChannel      *amqp091.Channel
	signatureAnalyzer  *analysis.SignatureAnalyzer
	behavioralAnalyzer BehavioralAnalyzer // Интерфейс для будущего ML компонента
	eventProcessor     *EventProcessor
	ctx                context.Context
	cancel             context.CancelFunc
	wg                 sync.WaitGroup
}

// BehavioralAnalyzer интерфейс для поведенческого анализа
type BehavioralAnalyzer interface {
	AnalyzeEvent(event analysis.Event, context []analysis.Event) (severity string, confidence float64, err error)
	UpdateModel(events []analysis.Event) error
	IsEnabled() bool
}

// MockBehavioralAnalyzer заглушка для будущего ML анализатора
type MockBehavioralAnalyzer struct {
	enabled bool
}

func (mba *MockBehavioralAnalyzer) AnalyzeEvent(event analysis.Event, context []analysis.Event) (string, float64, error) {
	// Пока возвращаем исходную критичность
	return event.Severity, 1.0, nil
}

func (mba *MockBehavioralAnalyzer) UpdateModel(events []analysis.Event) error {
	return nil
}

func (mba *MockBehavioralAnalyzer) IsEnabled() bool {
	return mba.enabled
}

// EventProcessor обработчик событий
type EventProcessor struct {
	signatureAnalyzer  *analysis.SignatureAnalyzer
	behavioralAnalyzer BehavioralAnalyzer
	eventHistory       []analysis.Event
	historyMutex       sync.RWMutex
	maxHistorySize     int
}

// EnrichedEvent расширенное событие с результатами анализа
type EnrichedEvent struct {
	analysis.Event
	BehavioralSeverity string    `json:"behavioral_severity,omitempty"`
	Confidence         float64   `json:"confidence,omitempty"`
	ProcessedAt        time.Time `json:"processed_at"`
	AnalysisVersion    string    `json:"analysis_version"`
	ThreatScore        int       `json:"threat_score"`
	Recommendations    []string  `json:"recommendations,omitempty"`
}

// NewAnalysisEngine создает новый экземпляр сервиса анализа
func NewAnalysisEngine(configPath string) (*AnalysisEngine, error) {
	config, err := loadConfiguration(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	engine := &AnalysisEngine{
		config:             config,
		signatureAnalyzer:  analysis.NewSignatureAnalyzer(),
		behavioralAnalyzer: &MockBehavioralAnalyzer{enabled: config.Analysis.EnableBehavioralAnalysis},
		ctx:                ctx,
		cancel:             cancel,
	}

	engine.eventProcessor = &EventProcessor{
		signatureAnalyzer:  engine.signatureAnalyzer,
		behavioralAnalyzer: engine.behavioralAnalyzer,
		eventHistory:       make([]analysis.Event, 0),
		maxHistorySize:     1000, // Храним последние 1000 событий для контекста
	}

	return engine, nil
}

func loadConfiguration(configPath string) (Configuration, error) {
	var config Configuration

	// Значения по умолчанию
	config.RabbitMQ.Host = "localhost"
	config.RabbitMQ.Port = 5672
	config.RabbitMQ.Username = "admin"
	config.RabbitMQ.Password = "admin"
	config.RabbitMQ.InputQueue = "events_queue"
	config.RabbitMQ.OutputQueue = "analyzed_events_queue"
	config.RabbitMQ.Exchange = "events_exchange"
	config.RabbitMQ.RoutingKey = "event_key"
	config.RabbitMQ.ResponseKey = "analyzed_event_key"
	config.Analysis.EnableSignatureAnalysis = true
	config.Analysis.EnableBehavioralAnalysis = false
	config.Analysis.BatchSize = 1
	config.Analysis.ProcessingTimeout = 30
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

// Start запускает сервис анализа
func (ae *AnalysisEngine) Start() error {
	log.Printf("Starting Analysis Engine...")

	// Подключение к RabbitMQ
	if err := ae.connectRabbitMQ(); err != nil {
		return fmt.Errorf("failed to connect to RabbitMQ: %w", err)
	}

	// Настройка обработчиков сигналов
	ae.setupSignalHandlers()

	// Запуск обработчиков
	ae.wg.Add(1)
	go ae.processEvents()

	log.Printf("Analysis Engine started successfully")
	log.Printf("Configuration:")
	log.Printf("  - Signature Analysis: %v", ae.config.Analysis.EnableSignatureAnalysis)
	log.Printf("  - Behavioral Analysis: %v", ae.config.Analysis.EnableBehavioralAnalysis)
	log.Printf("  - Input Queue: %s", ae.config.RabbitMQ.InputQueue)
	log.Printf("  - Output Queue: %s", ae.config.RabbitMQ.OutputQueue)

	// Ожидание завершения
	ae.wg.Wait()
	return nil
}

func (ae *AnalysisEngine) connectRabbitMQ() error {
	connStr := fmt.Sprintf("amqp://%s:%s@%s:%d/",
		ae.config.RabbitMQ.Username,
		ae.config.RabbitMQ.Password,
		ae.config.RabbitMQ.Host,
		ae.config.RabbitMQ.Port)

	conn, err := amqp091.Dial(connStr)
	if err != nil {
		return err
	}

	channel, err := conn.Channel()
	if err != nil {
		conn.Close()
		return err
	}

	ae.rabbitConn = conn
	ae.rabbitChannel = channel

	// Объявляем exchange
	err = channel.ExchangeDeclare(
		ae.config.RabbitMQ.Exchange,
		"direct",
		true,  // durable
		false, // auto-deleted
		false, // internal
		false, // no-wait
		nil,   // arguments
	)
	if err != nil {
		return err
	}

	// Объявляем входную очередь
	_, err = channel.QueueDeclare(
		ae.config.RabbitMQ.InputQueue,
		true,  // durable
		false, // delete when unused
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)
	if err != nil {
		return err
	}

	// Объявляем выходную очередь
	_, err = channel.QueueDeclare(
		ae.config.RabbitMQ.OutputQueue,
		true,  // durable
		false, // delete when unused
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)
	if err != nil {
		return err
	}

	// Привязываем очереди
	err = channel.QueueBind(
		ae.config.RabbitMQ.InputQueue,
		ae.config.RabbitMQ.RoutingKey,
		ae.config.RabbitMQ.Exchange,
		false,
		nil,
	)
	if err != nil {
		return err
	}

	err = channel.QueueBind(
		ae.config.RabbitMQ.OutputQueue,
		ae.config.RabbitMQ.ResponseKey,
		ae.config.RabbitMQ.Exchange,
		false,
		nil,
	)

	log.Printf("Connected to RabbitMQ at %s:%d", ae.config.RabbitMQ.Host, ae.config.RabbitMQ.Port)
	return err
}

func (ae *AnalysisEngine) processEvents() {
	defer ae.wg.Done()

	msgs, err := ae.rabbitChannel.Consume(
		ae.config.RabbitMQ.InputQueue,
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

	log.Printf("Waiting for events. To exit press CTRL+C")

	for {
		select {
		case <-ae.ctx.Done():
			log.Printf("Stopping event processing...")
			return
		case msg, ok := <-msgs:
			if !ok {
				log.Printf("Message channel closed")
				return
			}

			if err := ae.handleEvent(msg); err != nil {
				log.Printf("Error handling event: %v", err)
				msg.Nack(false, true) // Nack и возвращаем в очередь
			} else {
				msg.Ack(false)
			}
		}
	}
}

func (ae *AnalysisEngine) handleEvent(msg amqp091.Delivery) error {
	log.Printf("Received event: %s", string(msg.Body))

	// Парсим событие
	parsedMsg, err := analysis.ParseManually(string(msg.Body))
	if err != nil {
		return fmt.Errorf("failed to parse event: %w", err)
	}

	// Обрабатываем событие
	enrichedEvent, err := ae.eventProcessor.ProcessEvent(parsedMsg)
	if err != nil {
		return fmt.Errorf("failed to process event: %w", err)
	}

	// Отправляем обработанное событие
	if err := ae.publishEnrichedEvent(enrichedEvent); err != nil {
		return fmt.Errorf("failed to publish enriched event: %w", err)
	}

	log.Printf("Event processed successfully: Type=%s, Severity=%s, ThreatScore=%d",
		enrichedEvent.Type, enrichedEvent.Severity, enrichedEvent.ThreatScore)

	return nil
}

func (ep *EventProcessor) ProcessEvent(msg analysis.Message) (EnrichedEvent, error) {
	// Выполняем сигнатурный анализ
	event := ep.signatureAnalyzer.AnalyzeEvent(msg)

	// Создаем обогащенное событие
	enrichedEvent := EnrichedEvent{
		Event:           event,
		ProcessedAt:     time.Now(),
		AnalysisVersion: "1.0.0",
		ThreatScore:     ep.calculateThreatScore(event),
		Recommendations: ep.generateRecommendations(event),
	}

	// Поведенческий анализ (если включен)
	if ep.behavioralAnalyzer.IsEnabled() {
		ep.historyMutex.RLock()
		context := make([]analysis.Event, len(ep.eventHistory))
		copy(context, ep.eventHistory)
		ep.historyMutex.RUnlock()

		behavioralSeverity, confidence, err := ep.behavioralAnalyzer.AnalyzeEvent(event, context)
		if err != nil {
			log.Printf("Behavioral analysis failed: %v", err)
		} else {
			enrichedEvent.BehavioralSeverity = behavioralSeverity
			enrichedEvent.Confidence = confidence

			// Комбинируем результаты анализов
			enrichedEvent.Severity = ep.combineSeverities(event.Severity, behavioralSeverity, confidence)
			enrichedEvent.ThreatScore = ep.adjustThreatScore(enrichedEvent.ThreatScore, confidence)
		}
	}

	// Обновляем историю событий
	ep.updateEventHistory(event)

	return enrichedEvent, nil
}

func (ep *EventProcessor) calculateThreatScore(event analysis.Event) int {
	score := 0
	switch event.Severity {
	case analysis.CriticalSeverity:
		score = 90
	case analysis.MediumSeverity:
		score = 50
	case analysis.InfoSeverity:
		score = 10
	}

	// Дополнительные очки за тип события
	switch event.Type {
	case "DOCKER_SOCKET_ACCESS":
		score += 20
	case "KERNEL_MODULE_LOAD":
		score += 30
	case "PROCESS_DEBUG":
		score += 25
	case "DEVICE_CREATION":
		score += 20
	}

	if score > 100 {
		score = 100
	}

	return score
}

func (ep *EventProcessor) generateRecommendations(event analysis.Event) []string {
	recommendations := []string{}

	switch event.Severity {
	case analysis.CriticalSeverity:
		recommendations = append(recommendations, "Immediate investigation required")
		recommendations = append(recommendations, "Consider isolating the container")
	case analysis.MediumSeverity:
		recommendations = append(recommendations, "Monitor container activity closely")
		recommendations = append(recommendations, "Review container security policies")
	}

	switch event.Type {
	case "DOCKER_SOCKET_ACCESS":
		recommendations = append(recommendations, "Audit Docker socket access permissions")
	case "KERNEL_MODULE_LOAD":
		recommendations = append(recommendations, "Verify kernel module legitimacy")
	}

	return recommendations
}

func (ep *EventProcessor) combineSeverities(signature, behavioral string, confidence float64) string {
	if confidence < 0.7 {
		return signature // Низкая уверенность - используем сигнатурный анализ
	}

	severityOrder := map[string]int{
		analysis.InfoSeverity:     1,
		analysis.MediumSeverity:   2,
		analysis.CriticalSeverity: 3,
	}

	// Возвращаем более высокий уровень критичности
	if severityOrder[behavioral] > severityOrder[signature] {
		return behavioral
	}
	return signature
}

func (ep *EventProcessor) adjustThreatScore(baseScore int, confidence float64) int {
	if confidence > 0.8 {
		return int(float64(baseScore) * 1.2) // Увеличиваем на 20% при высокой уверенности
	}
	return baseScore
}

func (ep *EventProcessor) updateEventHistory(event analysis.Event) {
	ep.historyMutex.Lock()
	defer ep.historyMutex.Unlock()

	ep.eventHistory = append(ep.eventHistory, event)
	if len(ep.eventHistory) > ep.maxHistorySize {
		ep.eventHistory = ep.eventHistory[1:] // Удаляем самое старое событие
	}
}

func (ae *AnalysisEngine) publishEnrichedEvent(event EnrichedEvent) error {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return err
	}

	return ae.rabbitChannel.Publish(
		ae.config.RabbitMQ.Exchange,
		ae.config.RabbitMQ.ResponseKey,
		false, // mandatory
		false, // immediate
		amqp091.Publishing{
			ContentType:  "application/json",
			Body:         eventJSON,
			DeliveryMode: amqp091.Persistent,
			Timestamp:    time.Now(),
		},
	)
}

func (ae *AnalysisEngine) setupSignalHandlers() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal %s, shutting down gracefully...", sig)
		ae.Stop()
	}()
}

// Stop останавливает сервис
func (ae *AnalysisEngine) Stop() {
	ae.cancel()

	if ae.rabbitChannel != nil {
		ae.rabbitChannel.Close()
	}
	if ae.rabbitConn != nil {
		ae.rabbitConn.Close()
	}

	log.Printf("Analysis Engine stopped")
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
