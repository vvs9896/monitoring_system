package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"web-interface/internal/models"

	_ "github.com/lib/pq"
)

type DB struct {
	conn *sql.DB
}

func NewDB(host, port, user, password, dbname string) (*DB, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{conn: conn}, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

// GetRecentEvents получает последние события
func (db *DB) GetRecentEvents(limit int) ([]models.Event, error) {
	query := `
		SELECT time, type, severity, container_id, pid, ppid, comm, parent_comm, 
		       message, processed_at, analysis_version, threat_score, 
		       behavioral_severity, confidence, recommendations
		FROM events 
		ORDER BY time DESC 
		LIMIT $1`

	rows, err := db.conn.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []models.Event
	for rows.Next() {
		var event models.Event
		var recommendationsJSON string

		err := rows.Scan(
			&event.Time, &event.Type, &event.Severity, &event.ContainerID,
			&event.ProcessID, &event.ParentProcessID, &event.Command, &event.ParentCommand,
			&event.Message, &event.ProcessedAt, &event.AnalysisVersion, &event.ThreatScore,
			&event.BehavioralSeverity, &event.Confidence, &recommendationsJSON,
		)
		if err != nil {
			log.Printf("Error scanning event: %v", err)
			continue
		}

		// Парсим JSON рекомендаций
		if recommendationsJSON != "" {
			if err := json.Unmarshal([]byte(recommendationsJSON), &event.Recommendations); err != nil {
				log.Printf("Error parsing recommendations: %v", err)
				event.Recommendations = []string{}
			}
		}

		events = append(events, event)
	}

	return events, nil
}

// GetEventStats получает статистику событий
func (db *DB) GetEventStats(since time.Time) (*models.EventStats, error) {
	query := `
		SELECT 
			COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical,
			COUNT(CASE WHEN severity = 'MEDIUM' THEN 1 END) as medium,
			COUNT(CASE WHEN severity = 'INFO' THEN 1 END) as info,
			COUNT(*) as total
		FROM events 
		WHERE time >= $1`

	var stats models.EventStats
	err := db.conn.QueryRow(query, since).Scan(
		&stats.Critical, &stats.Medium, &stats.Info, &stats.Total)
	if err != nil {
		return nil, err
	}

	return &stats, nil
}

// GetTimeSeriesData получает данные временных рядов для графиков
func (db *DB) GetTimeSeriesData(since time.Time, interval string) ([]models.TimeSeriesData, error) {
	query := `
		SELECT 
			date_trunc($1, time) as timestamp,
			COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical,
			COUNT(CASE WHEN severity = 'MEDIUM' THEN 1 END) as medium,
			COUNT(CASE WHEN severity = 'INFO' THEN 1 END) as info
		FROM events 
		WHERE time >= $2
		GROUP BY date_trunc($1, time)
		ORDER BY timestamp`

	rows, err := db.conn.Query(query, interval, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var data []models.TimeSeriesData
	for rows.Next() {
		var item models.TimeSeriesData
		err := rows.Scan(&item.Timestamp, &item.Critical, &item.Medium, &item.Info)
		if err != nil {
			log.Printf("Error scanning time series data: %v", err)
			continue
		}
		data = append(data, item)
	}

	return data, nil
}

// GetEventsByTimeRange получает события за определенный период
func (db *DB) GetEventsByTimeRange(from, to time.Time, limit, offset int) ([]models.Event, error) {
	query := `
		SELECT time, type, severity, container_id, pid, ppid, comm, parent_comm, 
		       message, processed_at, analysis_version, threat_score, 
		       behavioral_severity, confidence, recommendations
		FROM events 
		WHERE time BETWEEN $1 AND $2
		ORDER BY time DESC 
		LIMIT $3 OFFSET $4`

	rows, err := db.conn.Query(query, from, to, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []models.Event
	for rows.Next() {
		var event models.Event
		var recommendationsJSON string

		err := rows.Scan(
			&event.Time, &event.Type, &event.Severity, &event.ContainerID,
			&event.ProcessID, &event.ParentProcessID, &event.Command, &event.ParentCommand,
			&event.Message, &event.ProcessedAt, &event.AnalysisVersion, &event.ThreatScore,
			&event.BehavioralSeverity, &event.Confidence, &recommendationsJSON,
		)
		if err != nil {
			log.Printf("Error scanning event: %v", err)
			continue
		}

		// Парсим JSON рекомендаций
		if recommendationsJSON != "" {
			if err := json.Unmarshal([]byte(recommendationsJSON), &event.Recommendations); err != nil {
				log.Printf("Error parsing recommendations: %v", err)
				event.Recommendations = []string{}
			}
		}

		events = append(events, event)
	}

	return events, nil
}

// GetEventsBySeverity получает события по уровню критичности
func (db *DB) GetEventsBySeverity(severity string, limit int) ([]models.Event, error) {
	query := `
		SELECT time, type, severity, container_id, pid, ppid, comm, parent_comm, 
		       message, processed_at, analysis_version, threat_score, 
		       behavioral_severity, confidence, recommendations
		FROM events 
		WHERE severity = $1
		ORDER BY time DESC 
		LIMIT $2`

	rows, err := db.conn.Query(query, severity, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []models.Event
	for rows.Next() {
		var event models.Event
		var recommendationsJSON string

		err := rows.Scan(
			&event.Time, &event.Type, &event.Severity, &event.ContainerID,
			&event.ProcessID, &event.ParentProcessID, &event.Command, &event.ParentCommand,
			&event.Message, &event.ProcessedAt, &event.AnalysisVersion, &event.ThreatScore,
			&event.BehavioralSeverity, &event.Confidence, &recommendationsJSON,
		)
		if err != nil {
			log.Printf("Error scanning event: %v", err)
			continue
		}

		// Парсим JSON рекомендаций
		if recommendationsJSON != "" {
			if err := json.Unmarshal([]byte(recommendationsJSON), &event.Recommendations); err != nil {
				log.Printf("Error parsing recommendations: %v", err)
				event.Recommendations = []string{}
			}
		}

		events = append(events, event)
	}

	return events, nil
}
