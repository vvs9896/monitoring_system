package models

import (
	"time"
)

// Event представляет событие безопасности
type Event struct {
	ID                 int64     `json:"id" db:"id"`
	Time               time.Time `json:"time" db:"time"`
	Type               string    `json:"type" db:"type"`
	Severity           string    `json:"severity" db:"severity"`
	ContainerID        string    `json:"container_id" db:"container_id"`
	ProcessID          int       `json:"process_id" db:"pid"`
	ParentProcessID    int       `json:"parent_process_id" db:"ppid"`
	Command            string    `json:"command" db:"comm"`
	ParentCommand      string    `json:"parent_command" db:"parent_comm"`
	Message            string    `json:"message" db:"message"`
	ProcessedAt        time.Time `json:"processed_at" db:"processed_at"`
	AnalysisVersion    string    `json:"analysis_version" db:"analysis_version"`
	ThreatScore        int       `json:"threat_score" db:"threat_score"`
	BehavioralSeverity string    `json:"behavioral_severity" db:"behavioral_severity"`
	Confidence         float64   `json:"confidence" db:"confidence"`
	Recommendations    []string  `json:"recommendations" db:"recommendations"`
}

// Container представляет Docker контейнер
type Container struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	Command string            `json:"Command"`
	Created int64             `json:"Created"`
	Ports   []ContainerPort   `json:"Ports"`
	Labels  map[string]string `json:"Labels"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
}

// ContainerPort представляет порт контейнера
type ContainerPort struct {
	IP          string `json:"IP"`
	PrivatePort uint16 `json:"PrivatePort"`
	PublicPort  uint16 `json:"PublicPort"`
	Type        string `json:"Type"`
}

// EventStats статистика событий
type EventStats struct {
	Critical int `json:"critical"`
	Medium   int `json:"medium"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// TimeSeriesData данные для графиков
type TimeSeriesData struct {
	Timestamp time.Time `json:"timestamp"`
	Critical  int       `json:"critical"`
	Medium    int       `json:"medium"`
	Info      int       `json:"info"`
}

// MITREAttack техника MITRE ATT&CK
type MITREAttack struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tactics     []string `json:"tactics"`
	Techniques  []string `json:"techniques"`
	Mitigation  string   `json:"mitigation"`
}

// SystemStatus статус системы
type SystemStatus struct {
	EBPFAgent      ServiceStatus `json:"ebpf_agent"`
	AnalysisEngine ServiceStatus `json:"analysis_engine"`
	ResponseModule ServiceStatus `json:"response_module"`
	RabbitMQ       ServiceStatus `json:"rabbitmq"`
	Database       ServiceStatus `json:"database"`
}

// ServiceStatus статус сервиса
type ServiceStatus struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Uptime  string `json:"uptime"`
	Memory  string `json:"memory"`
	CPU     string `json:"cpu"`
	Healthy bool   `json:"healthy"`
}

// WebSocketMessage сообщение для WebSocket
type WebSocketMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// DashboardData данные для дашборда
type DashboardData struct {
	Stats          EventStats       `json:"stats"`
	RecentEvents   []Event          `json:"recent_events"`
	ContainerCount int              `json:"container_count"`
	SystemStatus   SystemStatus     `json:"system_status"`
	TimeSeries     []TimeSeriesData `json:"time_series"`
}
