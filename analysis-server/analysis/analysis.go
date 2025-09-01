package analysis

import (
	"strings"
	"time"
)

// Уровни критичности
const (
	CriticalSeverity = "CRITICAL"
	MediumSeverity   = "MEDIUM"
	InfoSeverity     = "INFO"
)

type Event struct {
	Type      string
	Message   Message
	Severity  string
	Timestamp string
}

// SignatureAnalyzer структура для анализа сигнатур
type SignatureAnalyzer struct {
	criticalCommands map[string]bool

	mediumCommands map[string]bool
}

// NewSignatureAnalyzer создает новый анализатор сигнатур
func NewSignatureAnalyzer() *SignatureAnalyzer {
	return &SignatureAnalyzer{
		criticalCommands: map[string]bool{
			"mknod":         true,
			"/usr/bin/gdb":  true,
			"/usr/bin/kmod": true,
			"mount":         true,
			"curl":          true,
			"/usr/bin/curl": true,
		},
		mediumCommands: map[string]bool{
			"/usr/bin/docker": true,
		},
	}
}

// AnalyzeEvent выполняет сигнатурный анализ события
func (sa *SignatureAnalyzer) AnalyzeEvent(msg Message) Event {
	event := Event{
		Type:      sa.classifyEventType(msg),
		Message:   msg,
		Severity:  InfoSeverity,
		Timestamp: getCurrentTimestamp(),
	}

	// Определяем критичность
	event.Severity = sa.determineSeverity(msg)

	return event
}

// determineSeverity определяет уровень критичности события
func (sa *SignatureAnalyzer) determineSeverity(msg Message) string {
	pcomm := strings.TrimSpace(msg.ParentComm)
	comm := strings.TrimSpace(msg.Comm)

	// Критичные события:
	// 1. Команды из bash в контейнере (потенциальный container escape)
	if pcomm == "/usr/bin/bash" && sa.criticalCommands[comm] {
		return CriticalSeverity
	}

	// 2. Запуск bash из containerd-shim (возможное выполнение команд в контейнере)
	if pcomm == "/usr/bin/containerd-shim-runc-v2" && comm == "/usr/bin/bash" {
		return CriticalSeverity
	}

	// 3. Дополнительные критичные паттерны из сообщений
	if sa.isCriticalByMessage(msg.Message) {
		return CriticalSeverity
	}

	// Средне-критичные события:
	// Использование sudo с docker
	if pcomm == "/usr/bin/sudo" && sa.mediumCommands[comm] {
		return MediumSeverity
	}

	// Дополнительные средне-критичные паттерны
	if sa.isMediumByMessage(msg.Message) {
		return MediumSeverity
	}

	return InfoSeverity
}

// classifyEventType классифицирует тип события по сообщению
func (sa *SignatureAnalyzer) classifyEventType(msg Message) string {
	message := strings.ToUpper(msg.Message)

	switch {
	case strings.Contains(message, "[DOCKER-SOCK]"):
		return "DOCKER_SOCKET_ACCESS"
	case strings.Contains(message, "[MOUNT]"):
		return "MOUNT_OPERATION"
	case strings.Contains(message, "[GDB-ATTACH]"):
		return "PROCESS_DEBUG"
	case strings.Contains(message, "[LOAD-MODULE]"):
		return "KERNEL_MODULE_LOAD"
	case strings.Contains(message, "[MKNOD]"):
		return "DEVICE_CREATION"
	case strings.Contains(message, "[PROC-SYS-WRITE]"):
		return "PROC_SYS_WRITE"
	default:
		return "UNKNOWN"
	}
}

// isCriticalByMessage проверяет критичность по содержимому сообщения
func (sa *SignatureAnalyzer) isCriticalByMessage(message string) bool {
	criticalPatterns := []string{
		"[GDB-ATTACH]",                      // Отладка процессов
		"[LOAD-MODULE]",                     // Загрузка модулей ядра
		"[MKNOD]",                           // Создание блочных устройств
		"[PROC-SYS-WRITE]",                  // Запись в /proc/sys
		"creating container with \"binds\"", // Создание контейнера с bind mount
		"core_pattern",                      // Изменение core_pattern (потенциальный CVE-2022-0492)
	}

	msgUpper := strings.ToUpper(message)
	for _, pattern := range criticalPatterns {
		if strings.Contains(msgUpper, strings.ToUpper(pattern)) {
			return true
		}
	}

	return false
}

// isMediumByMessage проверяет средне-критичность по содержимому сообщения
func (sa *SignatureAnalyzer) isMediumByMessage(message string) bool {
	mediumPatterns := []string{
		"[DOCKER-SOCK]",                      // Доступ к Docker socket
		"connecting to /var/run/docker.sock", // Подключение к Docker socket
	}

	msgUpper := strings.ToUpper(message)
	for _, pattern := range mediumPatterns {
		if strings.Contains(msgUpper, strings.ToUpper(pattern)) {
			return true
		}
	}

	return false
}

// getCurrentTimestamp возвращает текущую временную метку
func getCurrentTimestamp() string {
	return time.Now().Format(time.RFC1123)
}

// AnalyzeBatch анализирует батч сообщений
func (sa *SignatureAnalyzer) AnalyzeBatch(messages []Message) []Event {
	events := make([]Event, 0, len(messages))

	for _, msg := range messages {
		event := sa.AnalyzeEvent(msg)
		events = append(events, event)
	}

	return events
}

// GetSeverityStats возвращает статистику по уровням критичности
func (sa *SignatureAnalyzer) GetSeverityStats(events []Event) map[string]int {
	stats := map[string]int{
		CriticalSeverity: 0,
		MediumSeverity:   0,
		InfoSeverity:     0,
	}

	for _, event := range events {
		stats[event.Severity]++
	}

	return stats
}
