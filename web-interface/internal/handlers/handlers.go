package handlers

import (
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"web-interface/internal/database"
	"web-interface/internal/models"
	"web-interface/internal/websocket"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	db  *database.DB
	hub *websocket.Hub
}

func NewHandler(db *database.DB, hub *websocket.Hub) *Handler {
	return &Handler{db: db, hub: hub}
}

// GetDashboard возвращает данные для главной страницы
func (h *Handler) GetDashboard(c *gin.Context) {
	// Получаем статистику за последние 24 часа
	since := time.Now().Add(-24 * time.Hour)
	stats, err := h.db.GetEventStats(since)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Получаем последние события
	recentEvents, err := h.db.GetRecentEvents(50)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Получаем данные временных рядов
	timeSeries, err := h.db.GetTimeSeriesData(since, "hour")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Получаем количество контейнеров
	containerCount := h.getContainerCount()

	// Получаем статус системы
	systemStatus := h.getSystemStatus()

	dashboardData := models.DashboardData{
		Stats:          *stats,
		RecentEvents:   recentEvents,
		ContainerCount: containerCount,
		SystemStatus:   systemStatus,
		TimeSeries:     timeSeries,
	}

	c.JSON(http.StatusOK, dashboardData)
}

// GetEvents возвращает события с фильтрацией и пагинацией
func (h *Handler) GetEvents(c *gin.Context) {
	// Параметры запроса
	limitStr := c.DefaultQuery("limit", "100")
	offsetStr := c.DefaultQuery("offset", "0")
	severity := c.Query("severity")
	fromStr := c.Query("from")
	toStr := c.Query("to")

	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	var events []models.Event
	var err error

	if severity != "" {
		events, err = h.db.GetEventsBySeverity(severity, limit)
	} else if fromStr != "" && toStr != "" {
		from, _ := time.Parse(time.RFC3339, fromStr)
		to, _ := time.Parse(time.RFC3339, toStr)
		events, err = h.db.GetEventsByTimeRange(from, to, limit, offset)
	} else {
		events, err = h.db.GetRecentEvents(limit)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, events)
}

// GetContainers возвращает список Docker контейнеров
func (h *Handler) GetContainers(c *gin.Context) {
	containers := h.getDockerContainers()
	c.JSON(http.StatusOK, containers)
}

// GetStats возвращает статистику событий
func (h *Handler) GetStats(c *gin.Context) {
	hoursStr := c.DefaultQuery("hours", "24")
	hours, _ := strconv.Atoi(hoursStr)

	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	stats, err := h.db.GetEventStats(since)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// GetTimeSeries возвращает данные временных рядов для графиков
func (h *Handler) GetTimeSeries(c *gin.Context) {
	hoursStr := c.DefaultQuery("hours", "24")
	interval := c.DefaultQuery("interval", "hour")

	hours, _ := strconv.Atoi(hoursStr)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	data, err := h.db.GetTimeSeriesData(since, interval)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, data)
}

// GetMITREAttacks возвращает информацию о техниках MITRE ATT&CK
func (h *Handler) GetMITREAttacks(c *gin.Context) {
	attacks := []models.MITREAttack{
		{
			ID:          "T1611",
			Name:        "Escape to Host",
			Description: "Adversaries may break out of a container to gain access to the underlying host.",
			Tactics:     []string{"Privilege Escalation"},
			Techniques:  []string{"Container Escape", "Privileged Container", "Host Network"},
			Mitigation:  "Use security profiles like AppArmor or SELinux, avoid privileged containers, implement proper container isolation.",
		},
		{
			ID:          "T1610",
			Name:        "Deploy Container",
			Description: "Adversaries may deploy a container into an environment to facilitate execution or evade defenses.",
			Tactics:     []string{"Defense Evasion", "Execution"},
			Techniques:  []string{"Container Deployment", "Resource Hijacking"},
			Mitigation:  "Monitor container deployment activities, implement proper access controls, use admission controllers.",
		},
		{
			ID:          "T1609",
			Name:        "Container Administration Command",
			Description: "Adversaries may abuse a container administration service to execute commands within a container.",
			Tactics:     []string{"Execution"},
			Techniques:  []string{"Docker API", "Container Runtime", "Remote Access"},
			Mitigation:  "Secure container APIs, implement proper authentication and authorization, monitor API usage.",
		},
		{
			ID:          "T1613",
			Name:        "Container and Resource Discovery",
			Description: "Adversaries may attempt to discover containers and other resources that are available within a containers environment.",
			Tactics:     []string{"Discovery"},
			Techniques:  []string{"Container Enumeration", "Resource Discovery"},
			Mitigation:  "Limit container visibility, implement network segmentation, monitor discovery activities.",
		},
	}

	c.JSON(http.StatusOK, attacks)
}

// GetSystemStatus возвращает статус системы
func (h *Handler) GetSystemStatus(c *gin.Context) {
	status := h.getSystemStatus()
	c.JSON(http.StatusOK, status)
}

// GetServiceLinks возвращает ссылки на веб-интерфейсы сервисов
func (h *Handler) GetServiceLinks(c *gin.Context) {
	links := map[string]string{
		"rabbitmq":    "http://localhost:15672",
		"timescaledb": "http://localhost:5432", // Обычно нет веб-интерфейса
		"portainer":   "http://localhost:9000", // Если установлен
		"grafana":     "http://localhost:3000", // Если установлен
	}

	c.JSON(http.StatusOK, links)
}

// WebSocket endpoint
func (h *Handler) HandleWebSocket(c *gin.Context) {
	h.hub.HandleWebSocket(c.Writer, c.Request)
}

// StopContainer останавливает контейнер
func (h *Handler) StopContainer(c *gin.Context) {
	containerID := c.Param("id")
	if containerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Container ID is required"})
		return
	}

	cmd := exec.Command("docker", "stop", containerID)
	output, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":  "Failed to stop container",
			"output": string(output),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Container stopped successfully",
		"id":      containerID,
	})
}

// Вспомогательные функции

func (h *Handler) getDockerContainers() []models.Container {
	// Используем простой формат без таблицы
	cmd := exec.Command("docker", "ps", "-a", "--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.Command}}|{{.Status}}|{{.CreatedAt}}")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Error getting containers: %v", err)
		return []models.Container{}
	}

	var containers []models.Container
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		fields := strings.Split(line, "|")
		if len(fields) >= 5 {
			container := models.Container{
				ID:      fields[0][:12], // Короткий ID
				Names:   []string{fields[1]},
				Image:   fields[2],
				Command: truncateString(fields[3], 30),
				Status:  fields[4],
				State:   getContainerState(fields[4]),
			}

			// Простая обработка времени создания
			container.Created = time.Now().Unix() - 3600 // Примерно час назад, можно улучшить

			containers = append(containers, container)
		}
	}

	return containers
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func getContainerState(status string) string {
	if strings.Contains(strings.ToLower(status), "up") {
		return "running"
	}
	return "exited"
}

func (h *Handler) getContainerCount() int {
	containers := h.getDockerContainers()
	return len(containers)
}

func (h *Handler) getSystemStatus() models.SystemStatus {
	return models.SystemStatus{
		EBPFAgent:      h.getServiceStatus("ebpf-monitor"),
		AnalysisEngine: h.getServiceStatus("analysis-engine"),
		ResponseModule: h.getServiceStatus("response-module"),
		RabbitMQ:       h.getServiceStatus("rabbitmq-server"),
		Database:       h.getServiceStatus("postgresql"),
	}
}

func (h *Handler) getServiceStatus(serviceName string) models.ServiceStatus {
	// Проверяем статус сервиса
	cmd := exec.Command("systemctl", "is-active", serviceName)
	output, err := cmd.Output()
	status := strings.TrimSpace(string(output))
	healthy := err == nil && status == "active"

	// Получаем uptime
	uptimeCmd := exec.Command("systemctl", "show", serviceName, "--property=ActiveEnterTimestamp", "--value")
	uptimeOutput, _ := uptimeCmd.Output()
	uptime := strings.TrimSpace(string(uptimeOutput))

	// Получаем использование памяти
	memoryCmd := exec.Command("systemctl", "show", serviceName, "--property=MemoryCurrent", "--value")
	memoryOutput, _ := memoryCmd.Output()
	memory := strings.TrimSpace(string(memoryOutput))

	return models.ServiceStatus{
		Name:    serviceName,
		Status:  status,
		Uptime:  uptime,
		Memory:  memory,
		CPU:     "N/A", // Можно добавить позже
		Healthy: healthy,
	}
}
