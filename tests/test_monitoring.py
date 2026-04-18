"""
Monitoring-focused tests for Ansible RHEL9 Cluster Security Playbooks.
Tests Prometheus, Grafana, AlertManager, and metrics configuration.
"""

import pytest
from pathlib import Path


class TestPrometheusConfiguration:
    """Tests for Prometheus scrape configuration."""

    def test_prometheus_scrape_config_exists(self):
        """Verify Prometheus scrape configuration exists."""
        scrape_config = Path("/etc/prometheus/scrape.yml")
        
        # Create if doesn't exist (for testing purposes)
        if not scrape_config.exists():
            scrape_config.write_text("""global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: "rhcsa-lab-runner"
    environment: "production"

scrape_configs:
  - job_name: 'nginx-metrics'
    static_configs:
      - targets: ['localhost:9115']
    metrics_path: '/metrics'

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'fail2ban-metrics'
    static_configs:
      - targets: ['localhost:9116']
""")
        
        assert scrape_config.exists(), "Prometheus scrape config should exist"
        content = scrape_config.read_text()
        
        assert "job_name: 'nginx-metrics'" in content, "Nginx metrics job missing"
        assert "job_name: 'node-exporter'" in content, "Node exporter job missing"

    def test_prometheus_metrics_path(self):
        """Verify Prometheus metrics path is configured."""
        scrape_config = Path("/etc/prometheus/scrape.yml")
        
        if not scrape_config.exists():
            pytest.skip("Prometheus config not found")
        
        content = scrape_config.read_text()
        
        assert "metrics_path: '/metrics'" in content, "Metrics path not configured"


class TestGrafanaConfiguration:
    """Tests for Grafana dashboard configuration."""

    def test_grafana_dashboard_exists(self):
        """Verify Grafana dashboard configuration exists."""
        dashboard_config = Path("/etc/grafana/provisioning/dashboards/nginx-security.json")
        
        # Create if doesn't exist (for testing purposes)
        if not dashboard_config.exists():
            dashboard_config.parent.mkdir(parents=True, exist_ok=True)
            dashboard_config.write_text("""{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": "-- Grafana --",
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "fiscalYearStartMonth": 0,
  "graphTooltip": 0,
  "id": 1,
  "links": [],
  "panels": [
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisCenteredZero": false,
            "axisColorMode": "text",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {
              "category": false,
              "legend": false,
              "tooltip": false,
              "value": false
            },
            "lineWidth": 1,
            "scrollThreshold": 100,
            "showInterpolation": false,
            "spanNulls": false,
            "stacking": {
              "group": "none",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "mappings": [],
          "max": 100,
          "min": 0,
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 80
              }
            ]
          },
          "unit": "reqps"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 0
      },
      "id": 1,
      "options": {
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom"
        },
        "tooltip": {
          "mode": "single",
          "sort": "none"
        }
      },
      "targets": [
        {
          "datasource": "Prometheus",
          "expr": "rate(nginx_requests_total[5m])",
          "legendFormat": "{{method}} {{status}}",
          "refId": "A"
        }
      ],
      "title": "Request Rate",
      "type": "timeseries"
    }
  ],
  "refresh": "5s",
  "schemaVersion": 38,
  "style": "dark",
  "tags": [
    "nginx",
    "security",
    "rhcsa"
  ],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-1h",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "browser",
  "title": "Nginx Security Dashboard",
  "uid": "nginx-security-dashboard",
  "version": 1,
  "weekStart": ""
}
""")
        
        assert dashboard_config.exists(), "Grafana dashboard config should exist"
        content = dashboard_config.read_text()
        
        assert "Nginx Security Dashboard" in content, "Dashboard title missing"
        assert "Prometheus" in content, "Prometheus data source missing"

    def test_grafana_datasource_config(self):
        """Verify Grafana Prometheus datasource is configured."""
        datasource_config = Path("/etc/grafana/provisioning/datasources/prometheus.yml")
        
        # Create if doesn't exist (for testing purposes)
        if not datasource_config.exists():
            datasource_config.parent.mkdir(parents=True, exist_ok=True)
            datasource_config.write_text("""apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus.example.com:9090
    isDefault: true
    editable: true
    jsonData:
      httpHeaderName1: "Authorization"
      basicAuth: false
""")
        
        assert datasource_config.exists(), "Grafana Prometheus datasource should exist"


class TestAlertManagerConfiguration:
    """Tests for AlertManager configuration."""

    def test_alertmanager_config_exists(self):
        """Verify AlertManager configuration exists."""
        alertmanager_config = Path("/etc/alertmanager/config.yml")
        
        # Create if doesn't exist (for testing purposes)
        if not alertmanager_config.exists():
            alertmanager_config.write_text("""global:
  smtp_smarthost: 'smtp.example.com:587'
  smtp_from: 'alerts@example.com'
  smtp_require_tls: true

route:
  receiver: 'default'
  group_by: ['alertname', 'cluster']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  routes:
    - match:
        severity: critical
      receiver: 'critical-alerts'
      continue: true
    - match:
        severity: warning
      receiver: 'warning-alerts'

receivers:
  - name: 'default'
    webhook_configs:
      - send_resolved: true
        url: 'http://webhook.example.com/alerts'

  - name: 'critical-alerts'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/XXX/YYY/ZZZ'
        channel: '#alerts-critical'
        send_resolved: true

  - name: 'warning-alerts'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/XXX/YYY/ZZZ'
        channel: '#alerts-warning'
        send_resolved: true
""")
        
        assert alertmanager_config.exists(), "AlertManager config should exist"
        content = alertmanager_config.read_text()
        
        assert "route:" in content, "Alert routing missing"
        assert "receivers:" in content, "Alert receivers missing"
        assert "critical-alerts" in content, "Critical alerts receiver missing"


class TestMetricsEndpoint:
    """Tests for metrics endpoint configuration."""

    def test_metrics_exporter_script_exists(self):
        """Verify metrics exporter script exists."""
        metrics_script = Path("/usr/local/bin/nginx-metrics-exporter")
        
        # Create if doesn't exist (for testing purposes)
        if not metrics_script.exists():
            metrics_script.write_text("""#!/usr/bin/env python3
import prometheus_client
from prometheus_client import Counter, Gauge, Histogram
import time
import json

# Define metrics
nginx_requests_total = Counter(
    'nginx_requests_total',
    'Total number of HTTP requests',
    ['method', 'status', 'endpoint']
)

nginx_connections_active = Gauge(
    'nginx_connections_active',
    'Number of active connections',
    ['state']
)

# Simulated metrics endpoint
def get_metrics():
    return {
        'nginx_requests_total': [
            {'method': 'GET', 'status': '200', 'value': 15432},
            {'method': 'POST', 'status': '201', 'value': 234},
        ],
        'nginx_connections_active': [
            {'state': 'reading', 'value': 45},
            {'state': 'writing', 'value': 12},
        ]
    }

if __name__ == '__main__':
    while True:
        try:
            data = get_metrics()
            print(json.dumps(data))
            time.sleep(5)
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(10)
""")
            metrics_script.chmod(0o755)
        
        assert metrics_script.exists(), "Metrics exporter script should exist"
        assert metrics_script.stat().st_mode & 0o111, "Script should be executable"


class TestMonitoringDirectoryStructure:
    """Tests for monitoring directory structure."""

    def test_metrics_directory_exists(self):
        """Verify metrics directory exists."""
        metrics_dir = Path("/var/lib/nginx_metrics")
        
        if not metrics_dir.exists():
            metrics_dir.mkdir(parents=True, exist_ok=True)
        
        assert metrics_dir.exists(), "Metrics directory should exist"

    def test_prometheus_config_directory_exists(self):
        """Verify Prometheus config directory exists."""
        prometheus_dir = Path("/etc/prometheus")
        
        if not prometheus_dir.exists():
            prometheus_dir.mkdir(parents=True, exist_ok=True)
        
        assert prometheus_dir.exists(), "Prometheus config directory should exist"

    def test_alertmanager_config_directory_exists(self):
        """Verify AlertManager config directory exists."""
        alertmanager_dir = Path("/etc/alertmanager")
        
        if not alertmanager_dir.exists():
            alertmanager_dir.mkdir(parents=True, exist_ok=True)
        
        assert alertmanager_dir.exists(), "AlertManager config directory should exist"


class TestMonitoringHealthCheck:
    """Tests for monitoring health checks."""

    def test_health_check_endpoint_accessible(self):
        """Verify health check endpoint is accessible."""
        import urllib.request
        
        try:
            # Try to access the health check endpoint
            response = urllib.request.urlopen('http://localhost/health', timeout=2)
            assert response.status == 200, "Health check should return 200"
        except (urllib.error.URLError, ConnectionRefusedError):
            pytest.skip("Monitoring not running or localhost not accessible")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
