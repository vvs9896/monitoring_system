package analysis

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Message struct {
	ContainerID       string
	PID               int
	ParentContainerID string
	PPID              int
	ParentComm        string
	Comm              string
	Message           string
}

func ParseManually(input string) (Message, error) {
	// Разделяем по стрелке
	parts := strings.Split(input, " -> ")
	if len(parts) != 2 {
		return Message{}, fmt.Errorf("arrow separator not found")
	}

	leftPart := parts[0] // не убираем пробелы, чтобы сохранить форматирование
	rightPart := strings.TrimSpace(parts[1])

	// Парсим левую часть по фиксированным позициям
	// %-12s %-7d %-14s %-7d %-40s

	var event Message
	var err error

	// Container ID (12 символов)
	containerID := strings.TrimSpace(leftPart[0:12])
	if containerID != "" {
		event.ContainerID = containerID
	}

	// PID (7 символов, начиная с позиции 12)
	pidStr := strings.TrimSpace(leftPart[12:19])
	if pidStr == "" {
		return Message{}, fmt.Errorf("PID is required")
	}
	event.PID, err = strconv.Atoi(pidStr)
	if err != nil {
		return Message{}, fmt.Errorf("invalid PID: %v", err)
	}

	// Parent Container ID (14 символов, начиная с позиции 19)
	parentContainerID := strings.TrimSpace(leftPart[19:33])
	if parentContainerID != "" {
		event.ParentContainerID = parentContainerID
	}

	// PPID (7 символов, начиная с позиции 33)
	ppidStr := strings.TrimSpace(leftPart[33:40])
	if ppidStr == "" {
		return Message{}, fmt.Errorf("PPID is required")
	}
	event.PPID, err = strconv.Atoi(ppidStr)
	if err != nil {
		return Message{}, fmt.Errorf("invalid PPID: %v", err)
	}

	// Parent Command (40 символов, начиная с позиции 40)
	parentComm := strings.TrimSpace(leftPart[40:80])
	if parentComm != "" {
		event.ParentComm = parentComm
	}

	// Парсим правую часть (после стрелки)
	rightFields := strings.Fields(rightPart)
	if len(rightFields) < 1 {
		return Message{}, fmt.Errorf("insufficient fields in right part")
	}

	event.Comm = rightFields[0]

	if len(rightFields) > 1 {
		event.Message = strings.Join(rightFields[1:], " ")
	}

	return event, nil
}

func InsertEvent(db *sql.DB, event Event) error {
	// Парсим Timestamp в time.Time
	ts, err := time.Parse(time.RFC1123, event.Timestamp)
	if err != nil {
		return fmt.Errorf("failed to parse timestamp: %w", err)
	}

	query := `
    INSERT INTO events(
        time, type, container_id, pid, parent_container_id, ppid, parent_comm, comm, message, severity
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    `

	_, err = db.Exec(query,
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
	)
	if err != nil {
		return fmt.Errorf("failed to insert event: %w", err)
	}

	return nil
}
