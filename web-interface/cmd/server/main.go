package main

import (
	"flag"
	"log"
	"net/http"

	"web-interface/internal/database"
	"web-interface/internal/handlers"
	"web-interface/internal/websocket"

	"github.com/gin-gonic/gin"
)

func main() {
	var (
		addr   = flag.String("addr", ":8080", "HTTP server address")
		dbHost = flag.String("db-host", "localhost", "Database host")
		dbPort = flag.String("db-port", "5432", "Database port")
		dbUser = flag.String("db-user", "postgres", "Database user")
		dbPass = flag.String("db-pass", "postgres", "Database password")
		dbName = flag.String("db-name", "monitoring", "Database name")
	)
	flag.Parse()

	// Initialize database
	db, err := database.NewDB(*dbHost, *dbPort, *dbUser, *dbPass, *dbName)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize WebSocket hub
	hub := websocket.NewHub()
	go hub.Run()

	// Initialize handlers
	handler := handlers.NewHandler(db, hub)

	// Setup Gin router
	r := gin.Default()

	// Load HTML templates
	r.LoadHTMLGlob("templates/*")

	// Serve static files
	r.Static("/static", "./static")

	// Routes
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"title": "Container Security Monitoring System",
		})
	})

	// API routes
	api := r.Group("/api")
	{
		api.GET("/dashboard", handler.GetDashboard)
		api.GET("/events", handler.GetEvents)
		api.GET("/containers", handler.GetContainers)
		api.GET("/stats", handler.GetStats)
		api.GET("/timeseries", handler.GetTimeSeries)
		api.GET("/mitre", handler.GetMITREAttacks)
		api.GET("/system", handler.GetSystemStatus)
		api.GET("/services", handler.GetServiceLinks)
	}

	// WebSocket endpoint
	r.GET("/ws", handler.HandleWebSocket)

	log.Printf("Starting Container Security Monitoring Web Interface on %s", *addr)
	log.Printf("Database: %s@%s:%s/%s", *dbUser, *dbHost, *dbPort, *dbName)
	log.Printf("Access the interface at: http://localhost%s", *addr)

	if err := r.Run(*addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
