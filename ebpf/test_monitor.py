#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import json
import pika
from threading import Thread

def test_rabbitmq_connection():
    """Тест подключения к RabbitMQ"""
    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='localhost', credentials=pika.PlainCredentials('admin', 'admin'))
        )
        channel = connection.channel()
        
        # Проверяем существование exchange и queue
        channel.exchange_declare(exchange='events_exchange', exchange_type='direct', durable=True, passive=True)
        channel.queue_declare(queue='events_queue', durable=True, passive=True)
        
        connection.close()
        print("✓ RabbitMQ connection test passed")
        return True
    except Exception as e:
        print(f"✗ RabbitMQ connection test failed: {e}")
        return False

def test_config_file():
    """Тест конфигурационного файла"""
    config_path = "/etc/ebpf-monitor/config.json"
    try:
        if not os.path.exists(config_path):
            print(f"✗ Config file not found: {config_path}")
            return False
            
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        required_keys = ['rabbitmq', 'ebpf']
        for key in required_keys:
            if key not in config:
                print(f"✗ Missing required config key: {key}")
                return False
        
        print("✓ Configuration file test passed")
        return True
    except Exception as e:
        print(f"✗ Configuration file test failed: {e}")
        return False

def test_ebpf_program():
    """Тест eBPF программы"""
    program_path = "/opt/ebpf-monitor/ebpf_agent.c"
    try:
        if not os.path.exists(program_path):
            print(f"✗ eBPF program not found: {program_path}")
            return False
        
        # Проверяем, что файл содержит eBPF код
        with open(program_path, 'r') as f:
            content = f.read()
        
        if 'BPF_PERF_OUTPUT' not in content:
            print("✗ eBPF program appears to be invalid")
            return False
        
        print("✓ eBPF program file test passed")
        return True
    except Exception as e:
        print(f"✗ eBPF program test failed: {e}")
        return False

def test_service_status():
    """Тест статуса сервиса"""
    try:
        # Проверяем, что сервис установлен
        result = subprocess.run(['systemctl', 'is-enabled', 'ebpf-monitor'], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            print("✗ Service is not enabled")
            return False
        
        # Проверяем, что сервис запущен
        result = subprocess.run(['systemctl', 'is-active', 'ebpf-monitor'], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            print("! Service is not running (this is OK for testing)")
        else:
            print("✓ Service is running")
        
        print("✓ Service status test passed")
        return True
    except Exception as e:
        print(f"✗ Service status test failed: {e}")
        return False

def test_dependencies():
    """Тест зависимостей"""
    dependencies = [
        ('bcc', 'BCC library'),
        ('pika', 'RabbitMQ client'),
    ]
    
    all_passed = True
    for module, description in dependencies:
        try:
            __import__(module)
            print(f"✓ {description} available")
        except ImportError:
            print(f"✗ {description} not available")
            all_passed = False
    
    return all_passed

def test_permissions():
    """Тест прав доступа"""
    try:
        if os.geteuid() != 0:
            print("! Not running as root - some tests may fail")
        
        # Проверяем доступ к /proc
        if not os.access('/proc', os.R_OK):
            print("✗ Cannot access /proc")
            return False
        
        # Проверяем доступ к /sys
        if not os.access('/sys', os.R_OK):
            print("✗ Cannot access /sys")
            return False
        
        print("✓ Permissions test passed")
        return True
    except Exception as e:
        print(f"✗ Permissions test failed: {e}")
        return False

def listen_to_events(duration=10):
    """Прослушивание событий из RabbitMQ"""
    print(f"Listening for events for {duration} seconds...")
    
    events_received = []
    
    def callback(ch, method, properties, body):
        event = body.decode('utf-8')
        events_received.append(event)
        print(f"Received event: {event}")
        ch.basic_ack(delivery_tag=method.delivery_tag)
    
    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='localhost', credentials=pika.PlainCredentials('admin', 'admin'))
        )
        channel = connection.channel()
        
        channel.basic_consume(queue='events_queue', on_message_callback=callback)
        
        # Запускаем прослушивание в отдельном потоке
        def consume():
            channel.start_consuming()
        
        consumer_thread = Thread(target=consume)
        consumer_thread.daemon = True
        consumer_thread.start()
        
        # Ждем указанное время
        time.sleep(duration)
        
        channel.stop_consuming()
        connection.close()
        
        print(f"✓ Event listening test completed. Received {len(events_received)} events")
        return True
        
    except Exception as e:
        print(f"✗ Event listening test failed: {e}")
        return False

def generate_test_activity():
    """Генерация тестовой активности для проверки мониторинга"""
    print("Generating test activity...")
    
    try:
        # Создаем временный файл
        test_file = "/tmp/ebpf_test_file"
        with open(test_file, 'w') as f:
            f.write("test content")
        
        # Читаем файл
        with open(test_file, 'r') as f:
            content = f.read()
        
        # Удаляем файл
        os.unlink(test_file)
        
        print("✓ Test activity generated")
        return True
        
    except Exception as e:
        print(f"✗ Failed to generate test activity: {e}")
        return False

def main():
    """Основная функция тестирования"""
    print("eBPF Container Security Monitor - Test Suite")
    print("=" * 50)
    
    tests = [
        ("Dependencies", test_dependencies),
        ("Permissions", test_permissions),
        ("Configuration", test_config_file),
        ("eBPF Program", test_ebpf_program),
        ("Service Status", test_service_status),
        ("RabbitMQ Connection", test_rabbitmq_connection),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n--- {test_name} Test ---")
        if test_func():
            passed += 1
    
    print(f"\n{'=' * 50}")
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All tests passed!")
        
        # Дополнительные тесты если все базовые прошли
        print("\n--- Additional Tests ---")
        generate_test_activity()
        
        # Предлагаем прослушать события
        response = input("\nWould you like to listen for events? (y/N): ")
        if response.lower() == 'y':
            listen_to_events(10)
    else:
        print("✗ Some tests failed. Please check the configuration.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 