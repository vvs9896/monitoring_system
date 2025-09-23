package signature

import (
	"strings"
)

// Уровни критичности
const (
	CriticalSeverity = "CRITICAL"
	MediumSeverity   = "MEDIUM"
	InfoSeverity     = "INFO"
)

// Analyzer структура для сигнатурного анализа
type Analyzer struct {
	criticalCommands map[string]bool
	mediumCommands   map[string]bool
}

// NewAnalyzer создает новый анализатор сигнатур
func NewAnalyzer() *Analyzer {
	return &Analyzer{
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

// AnalyzeMessage выполняет сигнатурный анализ сообщения
func (sa *Analyzer) AnalyzeMessage(containerID string, command, message string) (eventType, severity string, threatScore int) {
	// Определяем тип события
	eventType = sa.classifyEventType(message)

	// Определяем критичность на основе команды
	severity = sa.analyzeSeverity(command)

	// Вычисляем threat score
	threatScore = sa.calculateThreatScore(eventType, severity)

	return eventType, severity, threatScore
}

func (sa *Analyzer) classifyEventType(message string) string {
	message = strings.ToUpper(message)

	if strings.Contains(message, "[MOUNT]") {
		return "MOUNT_OPERATION"
	}
	if strings.Contains(message, "[MKNOD]") {
		return "DEVICE_CREATION"
	}
	if strings.Contains(message, "GDB") || strings.Contains(message, "DEBUG") {
		return "PROCESS_DEBUG"
	}
	if strings.Contains(message, "DOCKER") {
		return "DOCKER_SOCKET_ACCESS"
	}
	if strings.Contains(message, "KMOD") || strings.Contains(message, "MODULE") {
		return "KERNEL_MODULE_LOAD"
	}
	if strings.Contains(message, "CURL") || strings.Contains(message, "WGET") {
		return "NETWORK_REQUEST"
	}

	return "UNKNOWN_OPERATION"
}

func (sa *Analyzer) analyzeSeverity(command string) string {
	if sa.criticalCommands[command] {
		return CriticalSeverity
	}
	if sa.mediumCommands[command] {
		return MediumSeverity
	}
	return InfoSeverity
}

func (sa *Analyzer) calculateThreatScore(eventType, severity string) int {
	score := 10 // Базовый счет

	// Очки за уровень критичности
	switch severity {
	case CriticalSeverity:
		score += 70
	case MediumSeverity:
		score += 40
	}

	// Дополнительные очки за тип события
	switch eventType {
	case "DOCKER_SOCKET_ACCESS":
		score += 20
	case "KERNEL_MODULE_LOAD":
		score += 30
	case "PROCESS_DEBUG":
		score += 25
	case "DEVICE_CREATION":
		score += 20
	case "MOUNT_OPERATION":
		score += 10
	}

	if score > 100 {
		score = 100
	}

	return score
}

// GenerateRecommendations генерирует рекомендации на основе анализа
func (sa *Analyzer) GenerateRecommendations(eventType, severity string) []string {
	recommendations := []string{}

	switch severity {
	case CriticalSeverity:
		recommendations = append(recommendations, "Immediate investigation required")
		recommendations = append(recommendations, "Consider isolating the container")
	case MediumSeverity:
		recommendations = append(recommendations, "Monitor container activity closely")
		recommendations = append(recommendations, "Review container security policies")
	}

	switch eventType {
	case "DOCKER_SOCKET_ACCESS":
		recommendations = append(recommendations, "Audit Docker socket access permissions")
	case "KERNEL_MODULE_LOAD":
		recommendations = append(recommendations, "Verify kernel module legitimacy")
	case "DEVICE_CREATION":
		recommendations = append(recommendations, "Check device creation permissions")
	case "MOUNT_OPERATION":
		recommendations = append(recommendations, "Verify mount operation legitimacy")
	}

	return recommendations
}
