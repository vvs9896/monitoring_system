package behavioral

// Analyzer интерфейс для поведенческого анализа
type Analyzer interface {
	AnalyzeEvent(eventType, containerID, command, message string) (behavioralSeverity string, confidence float64, err error)
}

// MockAnalyzer заглушка для поведенческого анализа
type MockAnalyzer struct{}

// NewMockAnalyzer создает заглушку анализатора
func NewMockAnalyzer() *MockAnalyzer {
	return &MockAnalyzer{}
}

// AnalyzeEvent выполняет поведенческий анализ (заглушка)
func (m *MockAnalyzer) AnalyzeEvent(eventType, containerID, command, message string) (string, float64, error) {
	// В будущем здесь будет ML модель (например, Isolation Forest)
	// Пока возвращаем нейтральные значения
	return "INFO", 0.5, nil
}

// CombineSeverities комбинирует результаты сигнатурного и поведенческого анализа
func CombineSeverities(signature, behavioral string, confidence float64) string {
	if confidence < 0.7 {
		return signature // Низкая уверенность - используем сигнатурный анализ
	}

	severityOrder := map[string]int{
		"INFO":     1,
		"MEDIUM":   2,
		"CRITICAL": 3,
	}

	if severityOrder[behavioral] > severityOrder[signature] {
		return behavioral
	}
	return signature
}
