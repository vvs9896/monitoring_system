package websocket

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"web-interface/internal/models"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Разрешаем все origins для разработки
	},
}

// Hub управляет WebSocket соединениями
type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
}

// Client представляет WebSocket клиента
type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
}

// NewHub создает новый WebSocket hub
func NewHub() *Hub {
	hub := &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}

	// Start periodic stats broadcaster
	go hub.startPeriodicUpdates()

	return hub
}

// Start periodic updates
func (h *Hub) startPeriodicUpdates() {
	// This will be called from the handler with actual data
	// Just a placeholder for now
}

// Run запускает hub
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			log.Printf("WebSocket client connected, total: %d", len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			log.Printf("WebSocket client disconnected, total: %d", len(h.clients))

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					delete(h.clients, client)
					close(client.send)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// BroadcastEvent отправляет событие всем подключенным клиентам
func (h *Hub) BroadcastEvent(event models.Event) {
	message := models.WebSocketMessage{
		Type: "new_event",
		Data: event,
	}

	data, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error marshaling event: %v", err)
		return
	}

	h.broadcast <- data
}

// BroadcastStats отправляет статистику всем подключенным клиентам
func (h *Hub) BroadcastStats(stats models.EventStats) {
	message := models.WebSocketMessage{
		Type: "stats_update",
		Data: stats,
	}

	data, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error marshaling stats: %v", err)
		return
	}

	h.broadcast <- data
}

// BroadcastSystemStatus отправляет статус системы
func (h *Hub) BroadcastSystemStatus(status models.SystemStatus) {
	message := models.WebSocketMessage{
		Type: "system_status",
		Data: status,
	}

	data, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error marshaling system status: %v", err)
		return
	}

	h.broadcast <- data
}

// HandleWebSocket обрабатывает WebSocket соединения
func (h *Hub) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	client := &Client{
		hub:  h,
		conn: conn,
		send: make(chan []byte, 256),
	}

	client.hub.register <- client

	// Запускаем горутины для чтения и записи
	go client.writePump()
	go client.readPump()
}

// readPump читает сообщения от WebSocket клиента
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}
	}
}

// writePump отправляет сообщения WebSocket клиенту
func (c *Client) writePump() {
	defer c.conn.Close()

	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				log.Printf("WebSocket write error: %v", err)
				return
			}
		}
	}
}
