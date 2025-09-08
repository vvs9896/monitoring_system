// Global variables
let ws = null;
let timelineChart = null;
let severityChart = null;
let autoRefresh = true;
let currentPage = 'dashboard';

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupWebSocket();
    setupEventListeners();
    loadDashboardData();
});

// Initialize application
function initializeApp() {
    console.log('Container Security Monitoring System initialized');
    updateConnectionStatus('connecting');
}

// Setup WebSocket connection
function setupWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    ws = new WebSocket(wsUrl);
    
    ws.onopen = function() {
        console.log('WebSocket connected');
        updateConnectionStatus('connected');
    };
    
    ws.onmessage = function(event) {
        const message = JSON.parse(event.data);
        handleWebSocketMessage(message);
    };
    
    ws.onclose = function() {
        console.log('WebSocket disconnected');
        updateConnectionStatus('disconnected');
        // Попытка переподключения через 5 секунд
        setTimeout(setupWebSocket, 5000);
    };
    
    ws.onerror = function(error) {
        console.error('WebSocket error:', error);
        updateConnectionStatus('disconnected');
    };
}

// Handle WebSocket messages
function handleWebSocketMessage(message) {
    switch(message.type) {
        case 'new_event':
            handleNewEvent(message.data);
            break;
        case 'stats_update':
            updateStatsCards(message.data);
            break;
        case 'system_status':
            updateSystemStatus(message.data);
            break;
        default:
            console.log('Unknown message type:', message.type);
    }
}

// Handle new event
function handleNewEvent(event) {
    if (currentPage === 'dashboard') {
        addEventToRecentList(event);
        updateCharts();
    }
    
    // Update stats
    updateStatsFromAPI();
}

// Setup event listeners
function setupEventListeners() {
    // Navigation
    document.querySelectorAll('[data-page]').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const page = this.getAttribute('data-page');
            switchPage(page);
        });
    });
    
    // Time range filter
    document.getElementById('time-range').addEventListener('change', function() {
        updateCharts();
        updateStatsFromAPI();
    });
    
    // Auto refresh toggle
    document.getElementById('auto-refresh-btn').addEventListener('click', function() {
        autoRefresh = !autoRefresh;
        this.innerHTML = `<i class="fas fa-sync-alt"></i> Auto Refresh: ${autoRefresh ? 'ON' : 'OFF'}`;
        this.style.background = autoRefresh ? 
            'linear-gradient(135deg, #2a5298, #1e3c72)' : 
            'linear-gradient(135deg, #9e9e9e, #757575)';
    });
    
    // Event filters
    document.getElementById('apply-filters').addEventListener('click', function() {
        loadEventsWithFilters();
    });
    
    // Modal close
    document.getElementById('modal-close').addEventListener('click', function() {
        closeModal();
    });
    
    // Close modal on outside click
    document.getElementById('event-modal').addEventListener('click', function(e) {
        if (e.target === this) {
            closeModal();
        }
    });
}

// Switch page
function switchPage(page) {
    // Update navigation
    document.querySelectorAll('.sidebar-menu li').forEach(li => {
        li.classList.remove('active');
    });
    document.querySelector(`[data-page="${page}"]`).parentElement.classList.add('active');
    
    // Update page content
    document.querySelectorAll('.page').forEach(p => {
        p.classList.remove('active');
    });
    document.getElementById(`${page}-page`).classList.add('active');
    
    // Update page title
    const titles = {
        dashboard: 'Dashboard',
        events: 'Security Events',
        containers: 'Docker Containers',
        mitre: 'MITRE ATT&CK',
        services: 'Service Links',
        system: 'System Status'
    };
    document.getElementById('page-title').textContent = titles[page];
    
    currentPage = page;
    
    // Load page data
    switch(page) {
        case 'dashboard':
            loadDashboardData();
            break;
        case 'events':
            loadEventsPage();
            break;
        case 'containers':
            loadContainersPage();
            break;
        case 'mitre':
            loadMITREPage();
            break;
        case 'services':
            loadServicesPage();
            break;
        case 'system':
            loadSystemPage();
            break;
    }
}

// Load dashboard data
async function loadDashboardData() {
    try {
        const response = await fetch('/api/dashboard');
        const data = await response.json();
        
        updateStatsCards(data.stats);
        updateRecentEvents(data.recent_events);
        updateContainerCount(data.container_count);
        
        // Initialize charts
        if (!timelineChart) {
            initializeCharts();
        }
        updateChartsData(data.time_series, data.stats);
        
    } catch (error) {
        console.error('Error loading dashboard data:', error);
    }
}

// Update connection status
function updateConnectionStatus(status) {
    const indicator = document.getElementById('connection-indicator');
    const text = document.getElementById('connection-text');
    const statusEl = document.querySelector('.connection-status');
    
    statusEl.className = `connection-status ${status}`;
    
    switch(status) {
        case 'connected':
            text.textContent = 'Connected';
            break;
        case 'disconnected':
            text.textContent = 'Disconnected';
            break;
        case 'connecting':
            text.textContent = 'Connecting...';
            break;
    }
}

// Update stats cards
function updateStatsCards(stats) {
    document.getElementById('critical-count').textContent = stats.critical || 0;
    document.getElementById('medium-count').textContent = stats.medium || 0;
    document.getElementById('info-count').textContent = stats.info || 0;
}

// Update container count
function updateContainerCount(count) {
    document.getElementById('container-count').textContent = count || 0;
}

// Update recent events
function updateRecentEvents(events) {
    const container = document.getElementById('recent-events-list');
    container.innerHTML = '';
    
    events.forEach(event => {
        addEventToRecentList(event);
    });
}

// Add event to recent list
function addEventToRecentList(event) {
    const container = document.getElementById('recent-events-list');
    const eventEl = createEventElement(event);
    container.insertBefore(eventEl, container.firstChild);
    
    // Keep only latest 20 events
    while (container.children.length > 20) {
        container.removeChild(container.lastChild);
    }
}

// Create event element
function createEventElement(event) {
    const div = document.createElement('div');
    div.className = `event-item ${event.severity.toLowerCase()}`;
    div.onclick = () => showEventDetails(event);
    
    const time = new Date(event.time).toLocaleString();
    
    div.innerHTML = `
        <div class="event-header">
            <span class="event-severity ${event.severity.toLowerCase()}">${event.severity}</span>
            <span class="event-time">${time}</span>
        </div>
        <div class="event-type">${event.type}</div>
        <div class="event-message">${truncateMessage(event.message, 100)}</div>
    `;
    
    return div;
}

// Truncate message
function truncateMessage(message, maxLength) {
    if (message.length <= maxLength) return message;
    return message.substring(0, maxLength) + '...';
}

// Show event details modal
function showEventDetails(event) {
    const modal = document.getElementById('event-modal');
    const body = document.getElementById('event-details');
    
    body.innerHTML = `
        <div class="event-detail-grid">
            <div class="detail-row">
                <strong>Time:</strong> ${new Date(event.time).toLocaleString()}
            </div>
            <div class="detail-row">
                <strong>Severity:</strong> 
                <span class="event-severity ${event.severity.toLowerCase()}">${event.severity}</span>
            </div>
            <div class="detail-row">
                <strong>Type:</strong> ${event.type}
            </div>
            <div class="detail-row">
                <strong>Container ID:</strong> ${event.container_id}
            </div>
            <div class="detail-row">
                <strong>Process ID:</strong> ${event.process_id}
            </div>
            <div class="detail-row">
                <strong>Parent Process ID:</strong> ${event.parent_process_id}
            </div>
            <div class="detail-row">
                <strong>Command:</strong> ${event.command}
            </div>
            <div class="detail-row">
                <strong>Parent Command:</strong> ${event.parent_command}
            </div>
            <div class="detail-row">
                <strong>Threat Score:</strong> ${event.threat_score}
            </div>
            <div class="detail-row">
                <strong>Analysis Version:</strong> ${event.analysis_version}
            </div>
            <div class="detail-row">
                <strong>Processed At:</strong> ${new Date(event.processed_at).toLocaleString()}
            </div>
            <div class="detail-row">
                <strong>Message:</strong><br>
                <pre>${event.message}</pre>
            </div>
            ${event.recommendations && event.recommendations.length > 0 ? `
            <div class="detail-row">
                <strong>Recommendations:</strong><br>
                <ul>
                    ${event.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                </ul>
            </div>
            ` : ''}
        </div>
    `;
    
    modal.style.display = 'block';
}

// Close modal
function closeModal() {
    document.getElementById('event-modal').style.display = 'none';
}

// Initialize charts
function initializeCharts() {
    // Timeline Chart
    const timelineCtx = document.getElementById('timelineChart').getContext('2d');
    timelineChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Critical',
                    data: [],
                    borderColor: '#f44336',
                    backgroundColor: 'rgba(244, 67, 54, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Medium',
                    data: [],
                    borderColor: '#ff9800',
                    backgroundColor: 'rgba(255, 152, 0, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Info',
                    data: [],
                    borderColor: '#9e9e9e',
                    backgroundColor: 'rgba(158, 158, 158, 0.1)',
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
    
    // Severity Chart
    const severityCtx = document.getElementById('severityChart').getContext('2d');
    severityChart = new Chart(severityCtx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'Medium', 'Info'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#f44336', '#ff9800', '#9e9e9e']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

// Update charts data
function updateChartsData(timeSeries, stats) {
    if (timelineChart && timeSeries) {
        const labels = timeSeries.map(item => new Date(item.timestamp).toLocaleTimeString());
        const critical = timeSeries.map(item => item.critical);
        const medium = timeSeries.map(item => item.medium);
        const info = timeSeries.map(item => item.info);
        
        timelineChart.data.labels = labels;
        timelineChart.data.datasets[0].data = critical;
        timelineChart.data.datasets[1].data = medium;
        timelineChart.data.datasets[2].data = info;
        timelineChart.update();
    }
    
    if (severityChart && stats) {
        severityChart.data.datasets[0].data = [stats.critical, stats.medium, stats.info];
        severityChart.update();
    }
}

// Update charts
async function updateCharts() {
    try {
        const hours = document.getElementById('time-range').value;
        const response = await fetch(`/api/timeseries?hours=${hours}`);
        const timeSeries = await response.json();
        
        const statsResponse = await fetch(`/api/stats?hours=${hours}`);
        const stats = await statsResponse.json();
        
        updateChartsData(timeSeries, stats);
    } catch (error) {
        console.error('Error updating charts:', error);
    }
}

// Update stats from API
async function updateStatsFromAPI() {
    try {
        const hours = document.getElementById('time-range').value;
        const response = await fetch(`/api/stats?hours=${hours}`);
        const stats = await response.json();
        updateStatsCards(stats);
    } catch (error) {
        console.error('Error updating stats:', error);
    }
}

// Load events page
async function loadEventsPage() {
    try {
        const response = await fetch('/api/events');
        const events = await response.json();
        displayEventsTable(events);
    } catch (error) {
        console.error('Error loading events:', error);
    }
}

// Display events table
function displayEventsTable(events) {
    const tbody = document.getElementById('events-table-body');
    tbody.innerHTML = '';
    
    events.forEach(event => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${new Date(event.time).toLocaleString()}</td>
            <td><span class="event-severity ${event.severity.toLowerCase()}">${event.severity}</span></td>
            <td>${event.type}</td>
            <td>${event.container_id}</td>
            <td>${event.command}</td>
            <td>${event.threat_score}</td>
            <td><button class="btn btn-sm btn-primary" onclick="showEventDetails(${JSON.stringify(event).replace(/"/g, '&quot;')})">Details</button></td>
        `;
        tbody.appendChild(row);
    });
}

// Load events with filters
async function loadEventsWithFilters() {
    try {
        const severity = document.getElementById('severity-filter').value;
        const from = document.getElementById('date-from').value;
        const to = document.getElementById('date-to').value;
        
        let url = '/api/events?';
        if (severity) url += `severity=${severity}&`;
        if (from) url += `from=${from}&`;
        if (to) url += `to=${to}&`;
        
        const response = await fetch(url);
        const events = await response.json();
        displayEventsTable(events);
    } catch (error) {
        console.error('Error loading filtered events:', error);
    }
}

// Load containers page
async function loadContainersPage() {
    try {
        const response = await fetch('/api/containers');
        const containers = await response.json();
        displayContainers(containers);
    } catch (error) {
        console.error('Error loading containers:', error);
    }
}

// Display containers
function displayContainers(containers) {
    const grid = document.getElementById('containers-grid');
    grid.innerHTML = '';
    
    containers.forEach(container => {
        const card = document.createElement('div');
        card.className = 'container-card';
        
        const name = container.Names && container.Names.length > 0 ? 
            container.Names[0].replace('/', '') : container.Id.substring(0, 12);
        
        card.innerHTML = `
            <div class="container-header">
                <div class="container-name">${name}</div>
                <div class="container-status ${container.State.toLowerCase()}">${container.State}</div>
            </div>
            <div class="container-info">
                <p><strong>Image:</strong> ${container.Image}</p>
                <p><strong>Command:</strong> ${container.Command}</p>
                <p><strong>Status:</strong> ${container.Status}</p>
                <p><strong>Created:</strong> ${new Date(container.Created * 1000).toLocaleString()}</p>
            </div>
        `;
        
        grid.appendChild(card);
    });
}

// Load MITRE page
async function loadMITREPage() {
    try {
        const response = await fetch('/api/mitre');
        const techniques = await response.json();
        displayMITRETechniques(techniques);
    } catch (error) {
        console.error('Error loading MITRE techniques:', error);
    }
}

// Display MITRE techniques
function displayMITRETechniques(techniques) {
    const grid = document.getElementById('mitre-grid');
    grid.innerHTML = '';
    
    techniques.forEach(technique => {
        const card = document.createElement('div');
        card.className = 'mitre-card';
        
        card.innerHTML = `
            <div class="mitre-header">
                <div class="mitre-id">${technique.id}</div>
                <div class="mitre-name">${technique.name}</div>
            </div>
            <div class="mitre-description">${technique.description}</div>
            <div class="mitre-tactics">
                ${technique.tactics.map(tactic => `<span class="mitre-tactic">${tactic}</span>`).join('')}
            </div>
            <div class="mitre-mitigation">
                <strong>Mitigation:</strong> ${technique.mitigation}
            </div>
        `;
        
        grid.appendChild(card);
    });
}

// Load services page
async function loadServicesPage() {
    try {
        const response = await fetch('/api/services');
        const services = await response.json();
        displayServices(services);
    } catch (error) {
        console.error('Error loading services:', error);
    }
}

// Display services
function displayServices(services) {
    const grid = document.getElementById('services-grid');
    grid.innerHTML = '';
    
    Object.entries(services).forEach(([name, url]) => {
        const card = document.createElement('div');
        card.className = 'service-card';
        
        const icons = {
            rabbitmq: 'fas fa-exchange-alt',
            timescaledb: 'fas fa-database',
            portainer: 'fab fa-docker',
            grafana: 'fas fa-chart-line'
        };
        
        card.innerHTML = `
            <div class="service-icon">
                <i class="${icons[name] || 'fas fa-cog'}"></i>
            </div>
            <div class="service-name">${name.toUpperCase()}</div>
            <a href="${url}" target="_blank" class="service-link">Open Interface</a>
        `;
        
        grid.appendChild(card);
    });
}

// Load system page
async function loadSystemPage() {
    try {
        const response = await fetch('/api/system');
        const status = await response.json();
        displaySystemStatus(status);
    } catch (error) {
        console.error('Error loading system status:', error);
    }
}

// Display system status
function displaySystemStatus(status) {
    const container = document.getElementById('system-status');
    container.innerHTML = '';
    
    Object.entries(status).forEach(([serviceName, serviceStatus]) => {
        const card = document.createElement('div');
        card.className = 'service-status-card';
        
        card.innerHTML = `
            <div class="service-status-header">
                <div class="service-status-name">${serviceStatus.name}</div>
                <div class="service-health ${serviceStatus.healthy ? 'healthy' : 'unhealthy'}"></div>
            </div>
            <div class="service-status-info">
                <p><strong>Status:</strong> ${serviceStatus.status}</p>
                <p><strong>Memory:</strong> ${serviceStatus.memory}</p>
                <p><strong>Uptime:</strong> ${serviceStatus.uptime}</p>
            </div>
        `;
        
        container.appendChild(card);
    });
}

// Auto refresh functionality
setInterval(() => {
    if (autoRefresh && currentPage === 'dashboard') {
        updateStatsFromAPI();
        updateCharts();
    }
}, 30000); // Refresh every 30 seconds 