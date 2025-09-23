package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/smtp"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/streadway/amqp"
)

// ResponseEvent представляет событие для обработки
type ResponseEvent struct {
	Time            time.Time `json:"time"`
	Type            string    `json:"type"`
	Severity        string    `json:"severity"`
	ContainerID     string    `json:"container_id"`
	ProcessID       int       `json:"process_id"`
	ParentProcessID int       `json:"parent_process_id"`
	Command         string    `json:"command"`
	ParentCommand   string    `json:"parent_command"`
	Message         string    `json:"message"`
	ProcessedAt     time.Time `json:"processed_at"`
	AnalysisVersion string    `json:"analysis_version"`
	ThreatScore     int       `json:"threat_score"`
	Recommendations []string  `json:"recommendations"`
}

// Config конфигурация модуля реагирования
type Config struct {
	RabbitMQ struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
		Queue    string `json:"queue"`
		Exchange string `json:"exchange"`
	} `json:"rabbitmq"`
	Email struct {
		SMTPHost   string `json:"smtp_host"`
		SMTPPort   int    `json:"smtp_port"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		AdminEmail string `json:"admin_email"`
		FromEmail  string `json:"from_email"`
		FromName   string `json:"from_name"`
	} `json:"email"`
	Docker struct {
		SocketPath string `json:"socket_path"`
	} `json:"docker"`
	Processing struct {
		RetryAttempts int `json:"retry_attempts"`
		RetryDelay    int `json:"retry_delay_seconds"`
	} `json:"processing"`
}

// ResponseModule основной модуль реагирования
type ResponseModule struct {
	config     Config
	rabbitConn *amqp.Connection
	rabbitCh   *amqp.Channel
	shutdown   chan struct{}
	wg         sync.WaitGroup
}

func NewResponseModule(configFile string) (*ResponseModule, error) {
	config, err := loadConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	rm := &ResponseModule{
		config:   config,
		shutdown: make(chan struct{}),
	}

	return rm, nil
}

func loadConfig(configFile string) (Config, error) {
	var config Config

	file, err := os.Open(configFile)
	if err != nil {
		return config, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	return config, err
}

func (rm *ResponseModule) connectRabbitMQ() error {
	url := fmt.Sprintf("amqp://%s:%s@%s:%d/",
		rm.config.RabbitMQ.Username,
		rm.config.RabbitMQ.Password,
		rm.config.RabbitMQ.Host,
		rm.config.RabbitMQ.Port)

	conn, err := amqp.Dial(url)
	if err != nil {
		return fmt.Errorf("failed to connect to RabbitMQ: %w", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to open channel: %w", err)
	}

	// Объявляем очередь для получения событий от analysis-server
	_, err = ch.QueueDeclare(
		rm.config.RabbitMQ.Queue, // name
		true,                     // durable
		false,                    // delete when unused
		false,                    // exclusive
		false,                    // no-wait
		nil,                      // arguments
	)
	if err != nil {
		ch.Close()
		conn.Close()
		return fmt.Errorf("failed to declare queue: %w", err)
	}

	rm.rabbitConn = conn
	rm.rabbitCh = ch

	log.Printf("Connected to RabbitMQ at %s:%d", rm.config.RabbitMQ.Host, rm.config.RabbitMQ.Port)
	return nil
}

func (rm *ResponseModule) stopContainer(containerID string) error {
	log.Printf("CRITICAL RESPONSE: Stopping container %s", containerID)

	// Используем docker stop для остановки контейнера
	cmd := exec.Command("docker", "stop", containerID)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop container %s: %w, output: %s", containerID, err, string(output))
	}

	log.Printf("Successfully stopped container %s", containerID)
	return nil
}

func (rm *ResponseModule) sendEmailNotification(event ResponseEvent, action string) error {
	subject := fmt.Sprintf("[CONTAINER SECURITY] %s Alert - %s", event.Severity, event.Type)

	body := fmt.Sprintf(`
CONTAINER SECURITY ALERT

Severity: %s
Action Taken: %s
Time: %s
Container ID: %s
Process: %s (PID: %d)
Parent Process: %s (PPID: %d)
Threat Score: %d
Event Type: %s

Message:
%s

Recommendations:
%s

Analysis Details:
- Analysis Version: %s
- Processed At: %s
- Event Time: %s

This is an automated alert from the Container Security Monitoring System.
Please investigate this incident immediately.
`,
		event.Severity,
		action,
		time.Now().Format("2006-01-02 15:04:05"),
		event.ContainerID,
		event.Command,
		event.ProcessID,
		event.ParentCommand,
		event.ParentProcessID,
		event.ThreatScore,
		event.Type,
		event.Message,
		formatRecommendations(event.Recommendations),
		event.AnalysisVersion,
		event.ProcessedAt.Format("2006-01-02 15:04:05"),
		event.Time.Format("2006-01-02 15:04:05"),
	)

	return rm.sendEmail(subject, body)
}

func formatRecommendations(recommendations []string) string {
	if len(recommendations) == 0 {
		return "No specific recommendations available"
	}

	var lines []string
	for _, rec := range recommendations {
		lines = append(lines, fmt.Sprintf("- %s", rec))
	}
	return strings.Join(lines, "\n")
}

func (rm *ResponseModule) sendEmail(subject, body string) error {
	auth := smtp.PlainAuth("",
		rm.config.Email.Username,
		rm.config.Email.Password,
		rm.config.Email.SMTPHost)

	to := []string{rm.config.Email.AdminEmail}

	msg := fmt.Sprintf("From: %s <%s>\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"\r\n%s",
		rm.config.Email.FromName,
		rm.config.Email.FromEmail,
		rm.config.Email.AdminEmail,
		subject,
		body)

	addr := fmt.Sprintf("%s:%d", rm.config.Email.SMTPHost, rm.config.Email.SMTPPort)

	err := smtp.SendMail(addr, auth, rm.config.Email.FromEmail, to, []byte(msg))
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Printf("Email notification sent to %s", rm.config.Email.AdminEmail)
	return nil
}

func (rm *ResponseModule) processEvent(event ResponseEvent) error {
	log.Printf("Processing event: Type=%s, Severity=%s, Container=%s, ThreatScore=%d",
		event.Type, event.Severity, event.ContainerID, event.ThreatScore)

	switch strings.ToUpper(event.Severity) {
	case "CRITICAL":
		// Критичное событие: останавливаем контейнер и отправляем уведомление
		var action string

		// Останавливаем контейнер
		if err := rm.stopContainer(event.ContainerID); err != nil {
			log.Printf("Failed to stop container: %v", err)
			action = fmt.Sprintf("FAILED to stop container: %v", err)
		} else {
			action = "Container stopped successfully"
		}

		// Отправляем уведомление (не блокируем выполнение при ошибке email)
		if err := rm.sendEmailNotification(event, action); err != nil {
			log.Printf("Failed to send email notification: %v", err)
			// Не возвращаем ошибку, чтобы событие считалось успешно обработанным
		}

	case "MEDIUM":
		// Среднее событие: только уведомление
		action := "Email notification sent"
		if err := rm.sendEmailNotification(event, action); err != nil {
			log.Printf("Failed to send email notification: %v", err)
			// Не возвращаем ошибку, чтобы событие считалось успешно обработанным
		}

	case "INFO":
		// Информационное событие: ничего не делаем
		log.Printf("INFO event logged: %s", event.Type)

	default:
		log.Printf("Unknown severity level: %s", event.Severity)
	}

	return nil
}

func (rm *ResponseModule) processEvents() {
	defer rm.wg.Done()

	msgs, err := rm.rabbitCh.Consume(
		rm.config.RabbitMQ.Queue,
		"response-module", // consumer
		false,             // auto-ack
		false,             // exclusive
		false,             // no-local
		false,             // no-wait
		nil,               // args
	)
	if err != nil {
		log.Printf("Failed to register consumer: %v", err)
		return
	}

	for {
		select {
		case <-rm.shutdown:
			return

		case msg, ok := <-msgs:
			if !ok {
				log.Println("RabbitMQ channel closed, attempting to reconnect...")
				if err := rm.connectRabbitMQ(); err != nil {
					log.Printf("Failed to reconnect to RabbitMQ: %v", err)
					return
				}
				// Перезапускаем consumer
				msgs, err = rm.rabbitCh.Consume(
					rm.config.RabbitMQ.Queue,
					"response-module", false, false, false, false, nil,
				)
				if err != nil {
					log.Printf("Failed to restart consumer: %v", err)
					return
				}
				continue
			}

			// Парсим событие
			var event ResponseEvent
			if err := json.Unmarshal(msg.Body, &event); err != nil {
				log.Printf("Failed to parse event: %v", err)
				msg.Nack(false, false)
				continue
			}

			// Обрабатываем событие с повторными попытками
			var lastErr error
			for attempt := 0; attempt < rm.config.Processing.RetryAttempts; attempt++ {
				if err := rm.processEvent(event); err != nil {
					lastErr = err
					log.Printf("Failed to process event (attempt %d/%d): %v",
						attempt+1, rm.config.Processing.RetryAttempts, err)
					if attempt < rm.config.Processing.RetryAttempts-1 {
						time.Sleep(time.Duration(rm.config.Processing.RetryDelay) * time.Second)
					}
				} else {
					lastErr = nil
					break
				}
			}

			if lastErr != nil {
				log.Printf("Failed to process event after %d attempts: %v",
					rm.config.Processing.RetryAttempts, lastErr)
				msg.Nack(false, false)
			} else {
				msg.Ack(false)
			}
		}
	}
}

func (rm *ResponseModule) setupSignalHandlers() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, shutting down gracefully...", sig)
		close(rm.shutdown)
	}()
}

func (rm *ResponseModule) Start() error {
	log.Println("Starting Container Security Response Module...")

	// Подключаемся к RabbitMQ
	if err := rm.connectRabbitMQ(); err != nil {
		return fmt.Errorf("failed to connect to RabbitMQ: %w", err)
	}
	defer rm.rabbitConn.Close()
	defer rm.rabbitCh.Close()

	// Настраиваем обработчики сигналов
	rm.setupSignalHandlers()

	// Запускаем обработку событий
	rm.wg.Add(1)
	go rm.processEvents()

	log.Println("Response Module started successfully")
	log.Printf("Listening for events on queue: %s", rm.config.RabbitMQ.Queue)
	log.Printf("Admin email configured: %s", rm.config.Email.AdminEmail)

	// Ждем завершения
	rm.wg.Wait()
	log.Println("Response Module stopped")

	return nil
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: response-module <config-file>")
	}

	configFile := os.Args[1]

	rm, err := NewResponseModule(configFile)
	if err != nil {
		log.Fatalf("Failed to create response module: %v", err)
	}

	if err := rm.Start(); err != nil {
		log.Fatalf("Response module error: %v", err)
	}
}
