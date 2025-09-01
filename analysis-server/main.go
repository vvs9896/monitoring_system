package main

import (
	"database/sql"
	"fmt"
	"log"

	"container-security-monitoring/analysis"

	"github.com/rabbitmq/amqp091-go"

	_ "github.com/lib/pq"
)

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func main() {
	conn, err := amqp091.Dial("amqp://admin:admin@localhost:5672/")
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	// Объявляем exchange (должен совпадать с отправителем)
	err = ch.ExchangeDeclare(
		"events_exchange", // name
		"direct",          // type
		true,              // durable
		false,             // auto-deleted
		false,             // internal
		false,             // no-wait
		nil,               // arguments
	)
	failOnError(err, "Failed to declare an exchange")

	q, err := ch.QueueDeclare(
		"events_queue", // имя очереди
		true,           // durable
		false,          // delete when unused
		false,          // exclusive
		false,          // no-wait
		nil,            // arguments
	)
	failOnError(err, "Failed to declare a queue")

	// Привязываем очередь к exchange
	err = ch.QueueBind(
		q.Name,            // queue name
		"event_key",       // routing key (должен совпадать с отправителем)
		"events_exchange", // exchange
		false,
		nil,
	)
	failOnError(err, "Failed to bind a queue")

	msgs, err := ch.Consume(
		q.Name, // queue
		"",     // consumer
		true,   // auto-ack
		false,  // exclusive
		false,  // no local
		false,  // no wait
		nil,    // args
	)
	failOnError(err, "Failed to register a consumer")

	forever := make(chan bool)

	go func() {
		for d := range msgs {
			log.Printf("Received a message: %s", d.Body)

			messg, err := analysis.ParseManually(string(d.Body))
			if err != nil {
				failOnError(err, "Failed to parse an event")
			}

			var event analysis.Event = analysis.NewSignatureAnalyzer().AnalyzeEvent(messg)

			connStr := "host=localhost port=5432 user=postgres password=postgres dbname=monitoring sslmode=disable"

			db, err := sql.Open("postgres", connStr)
			if err != nil {
				log.Fatalf("failed to open connection: %v", err)
			}

			if err := analysis.InsertEvent(db, event); err != nil {
				log.Fatalf("Error inserting event: %v", err)
			}
			db.Close()

			fmt.Println("Event inserted successfully")
		}
	}()

	log.Printf(" [*] Waiting for messages. To exit press CTRL+C")
	<-forever
}
