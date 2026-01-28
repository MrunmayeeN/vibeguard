"""
VibeGuard Dashboard - Web UI for monitoring and management.

Provides:
- Real-time monitoring of security events
- Approval workflow interface
- Usage statistics and charts
- Configuration management
- Audit log viewer

Usage:
    from vibeguard.dashboard import run_dashboard
    
    # Run standalone
    run_dashboard(port=8080)
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from dataclasses import dataclass, field


@dataclass
class DashboardStats:
    """Statistics for the dashboard."""
    
    total_requests: int = 0
    blocked_requests: int = 0
    issues_detected: int = 0
    pending_approvals: int = 0
    
    issues_by_type: dict[str, int] = field(default_factory=dict)
    issues_by_severity: dict[str, int] = field(default_factory=dict)
    
    hourly_requests: list[int] = field(default_factory=list)
    hourly_blocked: list[int] = field(default_factory=list)
    
    recent_events: list[dict[str, Any]] = field(default_factory=list)


class DashboardDataCollector:
    """Collects and aggregates data for the dashboard."""
    
    def __init__(
        self,
        audit_log_path: str | Path | None = None,
        max_recent_events: int = 100,
    ):
        self.audit_log_path = Path(audit_log_path) if audit_log_path else None
        self.max_recent_events = max_recent_events
        self._stats = DashboardStats()
        self._hourly_buckets: dict[str, dict[str, int]] = {}
        
        if self.audit_log_path and self.audit_log_path.exists():
            self._load_audit_log()
    
    def _load_audit_log(self) -> None:
        if not self.audit_log_path:
            return
        try:
            with open(self.audit_log_path) as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        self._process_entry(entry)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
    
    def _process_entry(self, entry: dict[str, Any]) -> None:
        self._stats.total_requests += 1
        
        if entry.get("blocked", False):
            self._stats.blocked_requests += 1
        
        issues = entry.get("issues", [])
        self._stats.issues_detected += len(issues)
        
        for issue in issues:
            issue_type = issue.get("type", "unknown")
            severity = issue.get("severity", "unknown")
            self._stats.issues_by_type[issue_type] = self._stats.issues_by_type.get(issue_type, 0) + 1
            self._stats.issues_by_severity[severity] = self._stats.issues_by_severity.get(severity, 0) + 1
        
        timestamp_str = entry.get("timestamp", "")
        if timestamp_str:
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                hour_key = timestamp.strftime("%Y-%m-%d-%H")
                if hour_key not in self._hourly_buckets:
                    self._hourly_buckets[hour_key] = {"requests": 0, "blocked": 0}
                self._hourly_buckets[hour_key]["requests"] += 1
                if entry.get("blocked", False):
                    self._hourly_buckets[hour_key]["blocked"] += 1
            except (ValueError, AttributeError):
                pass
        
        self._stats.recent_events.append({
            "timestamp": timestamp_str,
            "blocked": entry.get("blocked", False),
            "issues_count": len(issues),
            "direction": entry.get("direction", "unknown"),
        })
        
        if len(self._stats.recent_events) > self.max_recent_events:
            self._stats.recent_events = self._stats.recent_events[-self.max_recent_events:]
    
    def record_event(self, entry: dict[str, Any]) -> None:
        self._process_entry(entry)
    
    def get_stats(self) -> DashboardStats:
        now = datetime.utcnow()
        self._stats.hourly_requests = []
        self._stats.hourly_blocked = []
        
        for i in range(24):
            hour = now - timedelta(hours=23-i)
            hour_key = hour.strftime("%Y-%m-%d-%H")
            bucket = self._hourly_buckets.get(hour_key, {"requests": 0, "blocked": 0})
            self._stats.hourly_requests.append(bucket["requests"])
            self._stats.hourly_blocked.append(bucket["blocked"])
        
        return self._stats
    
    def get_recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._stats.recent_events[-limit:]


DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VibeGuard Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
    <nav class="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div class="flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <span class="text-2xl">🛡️</span>
                <h1 class="text-xl font-bold">VibeGuard Dashboard</h1>
            </div>
            <div class="flex items-center space-x-4">
                <span class="text-gray-400 text-sm">Last updated: <span id="lastUpdated">-</span></span>
                <button onclick="refreshData()" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-sm">Refresh</button>
            </div>
        </div>
    </nav>
    <main class="p-6">
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <p class="text-gray-400 text-sm">Total Requests</p>
                <p class="text-3xl font-bold mt-1" id="totalRequests">0</p>
            </div>
            <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <p class="text-gray-400 text-sm">Blocked</p>
                <p class="text-3xl font-bold mt-1 text-red-400" id="blockedRequests">0</p>
            </div>
            <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <p class="text-gray-400 text-sm">Issues Detected</p>
                <p class="text-3xl font-bold mt-1 text-yellow-400" id="issuesDetected">0</p>
            </div>
            <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <p class="text-gray-400 text-sm">Block Rate</p>
                <p class="text-3xl font-bold mt-1 text-blue-400" id="blockRate">0%</p>
            </div>
        </div>
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <h2 class="text-lg font-semibold mb-4">Traffic (Last 24 Hours)</h2>
                <canvas id="trafficChart" height="200"></canvas>
            </div>
            <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
                <h2 class="text-lg font-semibold mb-4">Issues by Type</h2>
                <canvas id="issuesChart" height="200"></canvas>
            </div>
        </div>
        <div class="bg-gray-800 rounded-xl p-6 border border-gray-700">
            <h2 class="text-lg font-semibold mb-4">Recent Events</h2>
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead>
                        <tr class="text-gray-400 text-sm border-b border-gray-700">
                            <th class="text-left pb-3">Time</th>
                            <th class="text-left pb-3">Direction</th>
                            <th class="text-left pb-3">Status</th>
                            <th class="text-left pb-3">Issues</th>
                        </tr>
                    </thead>
                    <tbody id="eventsTable">
                        <tr><td colspan="4" class="text-gray-500 py-4">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </main>
    <script>
        let trafficChart, issuesChart;
        
        async function fetchStats() {
            try {
                const response = await fetch('/api/stats');
                return await response.json();
            } catch (e) {
                console.error('Failed to fetch stats:', e);
                return null;
            }
        }
        
        async function refreshData() {
            const stats = await fetchStats();
            if (!stats) return;
            
            document.getElementById('totalRequests').textContent = stats.total_requests.toLocaleString();
            document.getElementById('blockedRequests').textContent = stats.blocked_requests.toLocaleString();
            document.getElementById('issuesDetected').textContent = stats.issues_detected.toLocaleString();
            document.getElementById('pendingApprovals').textContent = stats.pending_approvals.toLocaleString();
            document.getElementById('lastUpdated').textContent = new Date().toLocaleTimeString();
            
            // Update traffic chart
            if (trafficChart) {
                trafficChart.data.datasets[0].data = stats.hourly_requests;
                trafficChart.data.datasets[1].data = stats.hourly_blocked;
                trafficChart.update();
            }
            
            // Update issues chart
            if (issuesChart && stats.issues_by_type) {
                issuesChart.data.labels = Object.keys(stats.issues_by_type);
                issuesChart.data.datasets[0].data = Object.values(stats.issues_by_type);
                issuesChart.update();
            }
            
            // Update events table
            updateEventsTable(stats.recent_events || []);
        }
        
        function updateEventsTable(events) {
            const tbody = document.getElementById('eventsTable');
            if (events.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-gray-500 py-4">No events yet</td></tr>';
                return;
            }
            
            tbody.innerHTML = events.slice(-20).reverse().map(event => `
                <tr class="border-b border-gray-700">
                    <td class="py-3 text-sm">${new Date(event.timestamp).toLocaleString()}</td>
                    <td class="py-3">
                        <span class="px-2 py-1 rounded text-xs ${event.direction === 'input' ? 'bg-blue-900 text-blue-300' : 'bg-purple-900 text-purple-300'}">
                            ${event.direction}
                        </span>
                    </td>
                    <td class="py-3">
                        <span class="px-2 py-1 rounded text-xs ${event.blocked ? 'bg-red-900 text-red-300' : 'bg-green-900 text-green-300'}">
                            ${event.blocked ? 'Blocked' : 'Allowed'}
                        </span>
                    </td>
                    <td class="py-3 text-sm">${event.issues_count} issues</td>
                </tr>
            `).join('');
        }
        
        function initCharts() {
            // Traffic chart
            const trafficCtx = document.getElementById('trafficChart').getContext('2d');
            trafficChart = new Chart(trafficCtx, {
                type: 'line',
                data: {
                    labels: Array.from({length: 24}, (_, i) => `${23-i}h ago`).reverse(),
                    datasets: [{
                        label: 'Requests',
                        data: Array(24).fill(0),
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        fill: true,
                        tension: 0.4
                    }, {
                        label: 'Blocked',
                        data: Array(24).fill(0),
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    plugins: { legend: { labels: { color: '#9ca3af' } } },
                    scales: {
                        x: { ticks: { color: '#9ca3af' }, grid: { color: '#374151' } },
                        y: { ticks: { color: '#9ca3af' }, grid: { color: '#374151' } }
                    }
                }
            });
            
            // Issues chart
            const issuesCtx = document.getElementById('issuesChart').getContext('2d');
            issuesChart = new Chart(issuesCtx, {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: ['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6', '#ec4899']
                    }]
                },
                options: {
                    responsive: true,
                    plugins: { legend: { position: 'right', labels: { color: '#9ca3af' } } }
                }
            });
        }
        
        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            initCharts();
            refreshData();
            // Auto-refresh every 30 seconds
            setInterval(refreshData, 30000);
        });
    </script>
</body>
</html>
'''


def create_app(
    audit_log_path: str | Path | None = None,
    authorizer: Any = None,  # ActionAuthorizer
):
    """
    Create a Flask app for the dashboard.
    
    Args:
        audit_log_path: Path to audit log file
        authorizer: ActionAuthorizer instance for approval management
        
    Returns:
        Flask app instance
    """
    try:
        from flask import Flask, jsonify, request
    except ImportError:
        raise ImportError(
            "Flask is required for the dashboard. Install with: pip install flask"
        )
    
    app = Flask(__name__)
    collector = DashboardDataCollector(audit_log_path)
    
    @app.route('/')
    def index():
        return DASHBOARD_HTML
    
    @app.route('/api/stats')
    def get_stats():
        stats = collector.get_stats()
        return jsonify({
            "total_requests": stats.total_requests,
            "blocked_requests": stats.blocked_requests,
            "issues_detected": stats.issues_detected,
            "pending_approvals": stats.pending_approvals,
            "issues_by_type": stats.issues_by_type,
            "issues_by_severity": stats.issues_by_severity,
            "hourly_requests": stats.hourly_requests,
            "hourly_blocked": stats.hourly_blocked,
            "recent_events": stats.recent_events[-50:],
        })
    
    @app.route('/api/events')
    def get_events():
        limit = request.args.get('limit', 50, type=int)
        events = collector.get_recent_events(limit)
        return jsonify(events)
    
    @app.route('/api/approvals')
    def get_approvals():
        if authorizer is None:
            return jsonify([])
        
        pending = authorizer.get_pending_approvals()
        return jsonify([
            {
                "action_id": req.action.id,
                "action_name": req.action.name,
                "description": req.action.description,
                "risk": req.action.risk.value,
                "requested_at": req.requested_at.isoformat(),
                "expires_at": req.expires_at.isoformat() if req.expires_at else None,
            }
            for req in pending
        ])
    
    @app.route('/api/approvals/<action_id>/approve', methods=['POST'])
    def approve_action(action_id):
        if authorizer is None:
            return jsonify({"error": "No authorizer configured"}), 400
        
        approved_by = request.json.get('approved_by', 'dashboard_user')
        success = authorizer.approve(action_id, approved_by)
        return jsonify({"success": success})
    
    @app.route('/api/approvals/<action_id>/deny', methods=['POST'])
    def deny_action(action_id):
        if authorizer is None:
            return jsonify({"error": "No authorizer configured"}), 400
        
        reason = request.json.get('reason', 'Denied via dashboard')
        denied_by = request.json.get('denied_by', 'dashboard_user')
        success = authorizer.deny(action_id, reason, denied_by)
        return jsonify({"success": success})
    
    return app


def run_dashboard(
    host: str = "127.0.0.1",
    port: int = 8080,
    audit_log_path: str | Path | None = None,
    authorizer: Any = None,
    debug: bool = False,
):
    """
    Run the dashboard as a standalone server.
    
    Args:
        host: Host to bind to
        port: Port to listen on
        audit_log_path: Path to audit log file
        authorizer: ActionAuthorizer instance
        debug: Enable Flask debug mode
    """
    app = create_app(audit_log_path, authorizer)
    print(f"🛡️ VibeGuard Dashboard running at http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)
            document.getElementById('issuesDetected').textContent = stats.issues_detected.toLocaleString();
            document.getElementById('pendingApprovals').textContent = stats.pending_approvals.toLocaleString();
            document.getElementById('lastUpdated').textContent = new Date().toLocaleTimeString();
            
            // Update traffic chart
            updateTrafficChart(stats.hourly_requests, stats.hourly_blocked);
            
            // Update issues chart
            updateIssuesChart(stats.issues_by_type);
            
            // Update events table
            updateEventsTable(stats.recent_events);
        }
        
        function updateTrafficChart(requests, blocked) {
            const labels = [];
            const now = new Date();
            for (let i = 23; i >= 0; i--) {
                const hour = new Date(now - i * 3600000);
                labels.push(hour.getHours() + ':00');
            }
            
            if (trafficChart) {
                trafficChart.data.labels = labels;
                trafficChart.data.datasets[0].data = requests;
                trafficChart.data.datasets[1].data = blocked;
                trafficChart.update();
            } else {
                const ctx = document.getElementById('trafficChart').getContext('2d');
                trafficChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Requests',
                            data: requests,
                            borderColor: '#3b82f6',
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            fill: true,
                            tension: 0.4
                        }, {
                            label: 'Blocked',
                            data: blocked,
                            borderColor: '#ef4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            fill: true,
                            tension: 0.4
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: { legend: { labels: { color: '#9ca3af' } } },
                        scales: {
                            x: { ticks: { color: '#9ca3af' }, grid: { color: '#374151' } },
                            y: { ticks: { color: '#9ca3af' }, grid: { color: '#374151' } }
                        }
                    }
                });
            }
        }
        
        function updateIssuesChart(issuesByType) {
            const labels = Object.keys(issuesByType);
            const data = Object.values(issuesByType);
            const colors = ['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6', '#ec4899'];
            
            if (issuesChart) {
                issuesChart.data.labels = labels;
                issuesChart.data.datasets[0].data = data;
                issuesChart.update();
            } else {
                const ctx = document.getElementById('issuesChart').getContext('2d');
                issuesChart = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: data,
                            backgroundColor: colors.slice(0, labels.length)
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: { legend: { position: 'right', labels: { color: '#9ca3af' } } }
                    }
                });
            }
        }
        
        function updateEventsTable(events) {
            const tbody = document.getElementById('eventsTable');
            if (!events || events.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-gray-500 py-4">No events yet</td></tr>';
                return;
            }
            
            tbody.innerHTML = events.slice(-20).reverse().map(event => `
                <tr class="border-b border-gray-700/50 hover:bg-gray-700/30">
                    <td class="py-3 text-sm">${new Date(event.timestamp).toLocaleString()}</td>
                    <td class="py-3">
                        <span class="px-2 py-1 rounded text-xs ${event.direction === 'input' ? 'bg-blue-900 text-blue-300' : 'bg-purple-900 text-purple-300'}">
                            ${event.direction}
                        </span>
                    </td>
                    <td class="py-3">
                        <span class="px-2 py-1 rounded text-xs ${event.blocked ? 'bg-red-900 text-red-300' : 'bg-green-900 text-green-300'}">
                            ${event.blocked ? 'Blocked' : 'Allowed'}
                        </span>
                    </td>
                    <td class="py-3 text-sm">${event.issues_count} issue(s)</td>
                </tr>
            `).join('');
        }
        
        // Initial load
        refreshData();
        
        // Auto-refresh every 10 seconds
        setInterval(refreshData, 10000);
    </script>
</body>
</html>
'''


def create_app(
    collector: DashboardDataCollector | None = None,
    audit_log_path: str | Path | None = None,
):
    """
    Create a Flask app for the dashboard.
    
    Args:
        collector: Data collector instance
        audit_log_path: Path to audit log (used if collector not provided)
        
    Returns:
        Flask app instance
    """
    try:
        from flask import Flask, jsonify, render_template_string
    except ImportError:
        raise ImportError(
            "Flask not installed. Install with: pip install flask"
        )
    
    app = Flask(__name__)
    
    if collector is None:
        collector = DashboardDataCollector(audit_log_path=audit_log_path)
    
    @app.route('/')
    def index():
        return render_template_string(DASHBOARD_HTML)
    
    @app.route('/api/stats')
    def api_stats():
        stats = collector.get_stats()
        return jsonify({
            "total_requests": stats.total_requests,
            "blocked_requests": stats.blocked_requests,
            "issues_detected": stats.issues_detected,
            "pending_approvals": stats.pending_approvals,
            "issues_by_type": stats.issues_by_type,
            "issues_by_severity": stats.issues_by_severity,
            "hourly_requests": stats.hourly_requests,
            "hourly_blocked": stats.hourly_blocked,
            "recent_events": stats.recent_events[-50:],
        })
    
    @app.route('/api/events')
    def api_events():
        events = collector.get_recent_events(limit=100)
        return jsonify(events)
    
    return app


def run_dashboard(
    host: str = "0.0.0.0",
    port: int = 8080,
    audit_log_path: str | Path | None = None,
    debug: bool = False,
):
    """
    Run the dashboard server.
    
    Args:
        host: Host to bind to
        port: Port to listen on
        audit_log_path: Path to audit log file
        debug: Enable debug mode
    """
    app = create_app(audit_log_path=audit_log_path)
    
    print(f"🛡️  VibeGuard Dashboard running at http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)
            document.getElementById('issuesDetected').textContent = stats.issues_detected.toLocaleString();
            const blockRate = stats.total_requests > 0 ? (stats.blocked_requests / stats.total_requests * 100).toFixed(1) : 0;
            document.getElementById('blockRate').textContent = blockRate + '%';
            document.getElementById('lastUpdated').textContent = new Date().toLocaleTimeString();
            
            updateTrafficChart(stats.hourly_requests, stats.hourly_blocked);
            updateIssuesChart(stats.issues_by_type);
            updateEventsTable(stats.recent_events);
        }
        
        function updateTrafficChart(requests, blocked) {
            const labels = [];
            const now = new Date();
            for (let i = 23; i >= 0; i--) {
                const h = new Date(now - i * 3600000);
                labels.push(h.getHours() + ':00');
            }
            
            if (trafficChart) {
                trafficChart.data.labels = labels;
                trafficChart.data.datasets[0].data = requests;
                trafficChart.data.datasets[1].data = blocked;
                trafficChart.update();
            } else {
                const ctx = document.getElementById('trafficChart').getContext('2d');
                trafficChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Requests',
                            data: requests,
                            borderColor: '#3b82f6',
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            fill: true,
                            tension: 0.4
                        }, {
                            label: 'Blocked',
                            data: blocked,
                            borderColor: '#ef4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            fill: true,
                            tension: 0.4
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: { legend: { labels: { color: '#9ca3af' } } },
                        scales: {
                            x: { ticks: { color: '#9ca3af' }, grid: { color: '#374151' } },
                            y: { ticks: { color: '#9ca3af' }, grid: { color: '#374151' } }
                        }
                    }
                });
            }
        }
        
        function updateIssuesChart(issuesByType) {
            const labels = Object.keys(issuesByType);
            const data = Object.values(issuesByType);
            const colors = ['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6', '#ec4899'];
            
            if (labels.length === 0) {
                labels.push('No issues');
                data.push(1);
            }
            
            if (issuesChart) {
                issuesChart.data.labels = labels;
                issuesChart.data.datasets[0].data = data;
                issuesChart.update();
            } else {
                const ctx = document.getElementById('issuesChart').getContext('2d');
                issuesChart = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: labels,
                        datasets: [{ data: data, backgroundColor: colors.slice(0, labels.length) }]
                    },
                    options: {
                        responsive: true,
                        plugins: { legend: { position: 'right', labels: { color: '#9ca3af' } } }
                    }
                });
            }
        }
        
        function updateEventsTable(events) {
            const tbody = document.getElementById('eventsTable');
            if (!events || events.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-gray-500 py-4">No events yet</td></tr>';
                return;
            }
            
            tbody.innerHTML = events.slice().reverse().slice(0, 20).map(e => {
                const time = e.timestamp ? new Date(e.timestamp).toLocaleString() : '-';
                const dirClass = e.direction === 'input' ? 'bg-blue-900 text-blue-300' : 'bg-purple-900 text-purple-300';
                const statusClass = e.blocked ? 'bg-red-900 text-red-300' : 'bg-green-900 text-green-300';
                const status = e.blocked ? 'Blocked' : 'Allowed';
                return `<tr class="border-b border-gray-700/50 hover:bg-gray-700/30">
                    <td class="py-3 text-sm">${time}</td>
                    <td class="py-3"><span class="px-2 py-1 rounded text-xs ${dirClass}">${e.direction}</span></td>
                    <td class="py-3"><span class="px-2 py-1 rounded text-xs ${statusClass}">${status}</span></td>
                    <td class="py-3 text-sm">${e.issues_count}</td>
                </tr>`;
            }).join('');
        }
        
        refreshData();
        setInterval(refreshData, 5000);
    </script>
</body>
</html>'''


def create_app(
    collector: DashboardDataCollector | None = None,
    authorizer: Any | None = None,
) -> Any:
    """Create a Flask app for the dashboard."""
    try:
        from flask import Flask, jsonify, request
    except ImportError:
        raise ImportError("Flask is required. Install with: pip install flask")
    
    app = Flask(__name__)
    
    if collector is None:
        collector = DashboardDataCollector()
    
    @app.route('/')
    def index():
        return DASHBOARD_HTML
    
    @app.route('/api/stats')
    def api_stats():
        stats = collector.get_stats()
        return jsonify({
            "total_requests": stats.total_requests,
            "blocked_requests": stats.blocked_requests,
            "issues_detected": stats.issues_detected,
            "pending_approvals": stats.pending_approvals,
            "issues_by_type": stats.issues_by_type,
            "issues_by_severity": stats.issues_by_severity,
            "hourly_requests": stats.hourly_requests,
            "hourly_blocked": stats.hourly_blocked,
            "recent_events": stats.recent_events[-50:],
        })
    
    @app.route('/api/events')
    def api_events():
        limit = request.args.get('limit', 50, type=int)
        events = collector.get_recent_events(limit)
        return jsonify({"events": events})
    
    if authorizer:
        @app.route('/api/approvals', methods=['GET'])
        def api_get_approvals():
            pending = authorizer.get_pending_approvals()
            return jsonify({
                "approvals": [
                    {
                        "action_id": r.action.id,
                        "action_name": r.action.name,
                        "description": r.action.description,
                        "risk": r.action.risk.value,
                        "requested_at": r.requested_at.isoformat(),
                    }
                    for r in pending
                ]
            })
        
        @app.route('/api/approvals/<action_id>/approve', methods=['POST'])
        def api_approve(action_id):
            success = authorizer.approve(action_id, approved_by="dashboard")
            return jsonify({"success": success})
        
        @app.route('/api/approvals/<action_id>/deny', methods=['POST'])
        def api_deny(action_id):
            data = request.get_json() or {}
            success = authorizer.deny(action_id, reason=data.get('reason', 'Denied'))
            return jsonify({"success": success})
    
    return app


def run_dashboard(
    host: str = "127.0.0.1",
    port: int = 8080,
    audit_log_path: str | Path | None = None,
    authorizer: Any | None = None,
    debug: bool = False,
) -> None:
    """
    Run the dashboard server.
    
    Args:
        host: Host to bind to
        port: Port to listen on
        audit_log_path: Path to audit log file
        authorizer: Optional ActionAuthorizer
        debug: Enable debug mode
    """
    collector = DashboardDataCollector(audit_log_path=audit_log_path)
    app = create_app(collector=collector, authorizer=authorizer)
    
    print(f"🛡️ VibeGuard Dashboard running at http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)
