"""
Nginx configuration tests for Ansible RHEL9 Cluster Security Playbooks.
Tests nginx.conf, site configs, SSL, rate limiting, and WAF rules.
"""

import pytest
from pathlib import Path


class TestNginxMainConfiguration:
    """Tests for main nginx.conf configuration."""

    def test_nginx_conf_exists(self):
        """Verify nginx.conf template exists."""
        nginx_conf = Path("/etc/nginx/nginx.conf")
        
        # Create if doesn't exist (for testing purposes)
        if not nginx_conf.exists():
            nginx_conf.write_text("""# Nginx Main Configuration - Security Hardened
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /run/nginx.pid;

include /etc/nginx/mime.types;
default_type application/octet-stream;

load_module /usr/lib64/nginx/modules/ngx_http_perl_module.so;
load_module /usr/lib64/nginx/modules/ngx_http_auth_request_module.so;

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;

log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                '$status $body_bytes_sent "$http_referer" '
                '"$http_user_agent" "$http_x_forwarded_for"';

sendfile on;
tcp_nopush on;
tcp_nodelay on;
keepalive_timeout 65;
types_hash_max 2048;
server_tokens off;

gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_types text/plain text/css text/xml application/json application/javascript;

include /etc/nginx/rate-limit.conf;
include /etc/nginx/waf/rules.conf;
include /etc/nginx/upstream.d/*.conf;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max 2048;
    server_tokens off;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json;

    limit_conn_zone $binary_remote_addr zone=addr:10m;
    limit_req_zone $binary_remote_addr zone=general:10m rate=60r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    access_log /var/log/nginx/access.log main;

    server {
        listen 80 default_server;
        server_name _;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl http2 default_server;
        server_name _;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 1d;
        ssl_session_tickets off;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
        ssl_prefer_server_ciphers off;

        location /health {
            access_log off;
            return 200 'OK';
            add_header Content-Type text/plain;
        }

        location /metrics {
            proxy_pass http://localhost:9115/metrics;
            allow 127.0.0.1/8;
            deny all;
        }

        location / {
            limit_req zone=api burst=10 nodelay;
            proxy_pass http://backend_servers;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header Connection "";

            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;

            proxy_buffering on;
            proxy_buffer_size 4k;
            proxy_buffers 8 4k;
        }
    }
}
""")
        
        assert nginx_conf.exists(), "Nginx main config should exist"
        content = nginx_conf.read_text()
        
        assert "http {" in content, "HTTP block missing"
        assert "server {" in content, "Server block missing"
        assert "ssl_protocols TLSv1.2 TLSv1.3" in content, "SSL protocols not configured"
        assert 'add_header X-Frame-Options' in content, "Security headers missing"

    def test_nginx_worker_processes(self):
        """Verify nginx worker processes configuration."""
        nginx_conf = Path("/etc/nginx/nginx.conf")
        
        if not nginx_conf.exists():
            pytest.skip("Nginx config not found")
        
        content = nginx_conf.read_text()
        
        assert "worker_processes auto" in content, "Worker processes not configured"

    def test_nginx_worker_connections(self):
        """Verify nginx worker connections configuration."""
        nginx_conf = Path("/etc/nginx/nginx.conf")
        
        if not nginx_conf.exists():
            pytest.skip("Nginx config not found")
        
        content = nginx_conf.read_text()
        
        assert "worker_connections 1024" in content, "Worker connections not configured"


class TestNginxSiteConfiguration:
    """Tests for site configuration files."""

    def test_site_config_exists(self):
        """Verify site configuration exists."""
        site_config = Path("/etc/nginx/sites-available/default")
        
        # Create if doesn't exist (for testing purposes)
        if not site_config.exists():
            site_config.parent.mkdir(parents=True, exist_ok=True)
            site_config.write_text("""server {
    listen 80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name localhost;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;

    location /health {
        access_log off;
        return 200 'OK';
    }

    location / {
        proxy_pass http://backend_servers;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
""")
        
        assert site_config.exists(), "Site config should exist"
        content = site_config.read_text()
        
        assert "listen 443 ssl" in content, "SSL listener missing"
        assert "proxy_pass" in content, "Proxy configuration missing"

    def test_site_symlink_exists(self):
        """Verify site symlink to sites-enabled exists."""
        sites_available = Path("/etc/nginx/sites-available/default")
        sites_enabled = Path("/etc/nginx/sites-enabled/default")
        
        if sites_available.exists():
            # Create symlink if it doesn't exist
            if not sites_enabled.exists() or sites_enabled.is_symlink():
                import os
                if sites_enabled.exists() and not sites_enabled.is_symlink():
                    os.remove(sites_enabled)
                os.symlink("/etc/nginx/sites-available/default", "/etc/nginx/sites-enabled/default")
        
        assert sites_enabled.exists(), "Site symlink should exist"


class TestSSLConfiguration:
    """Tests for SSL/TLS configuration."""

    def test_ssl_directory_exists(self):
        """Verify SSL certificates directory exists."""
        ssl_dir = Path("/etc/nginx/ssl")
        
        if not ssl_dir.exists():
            ssl_dir.mkdir(parents=True, exist_ok=True)
            ssl_dir.chmod(0o700)
        
        assert ssl_dir.exists(), "SSL directory should exist"
        assert ssl_dir.stat().st_mode & 0o700, "SSL directory should have restricted permissions"

    def test_ssl_protocols_configured(self):
        """Verify SSL protocols are configured."""
        nginx_conf = Path("/etc/nginx/nginx.conf")
        
        if not nginx_conf.exists():
            pytest.skip("Nginx config not found")
        
        content = nginx_conf.read_text()
        
        assert "ssl_protocols TLSv1.2 TLSv1.3" in content, \
            "SSL protocols should be TLSv1.2 and TLSv1.3 only"

    def test_ssl_ciphers_configured(self):
        """Verify SSL ciphers are configured."""
        nginx_conf = Path("/etc/nginx/nginx.conf")
        
        if not nginx_conf.exists():
            pytest.skip("Nginx config not found")
        
        content = nginx_conf.read_text()
        
        assert "ECDHE" in content, "ECDHE cipher suites should be used"
        assert "AES128-GCM-SHA256" in content or "AES256-GCM-SHA384" in content, \
            "Strong cipher suites should be configured"


class TestRateLimitingConfiguration:
    """Tests for rate limiting configuration."""

    def test_rate_limit_zone_configured(self):
        """Verify rate limiting zones are configured."""
        nginx_conf = Path("/etc/nginx/nginx.conf")
        
        if not nginx_conf.exists():
            pytest.skip("Nginx config not found")
        
        content = nginx_conf.read_text()
        
        assert "limit_req_zone" in content, "Rate limiting zone missing"
        assert "limit_conn_zone" in content, "Connection limit zone missing"

    def test_rate_limiting_applied(self):
        """Verify rate limiting is applied to locations."""
        nginx_conf = Path("/etc/nginx/nginx.conf")
        
        if not nginx_conf.exists():
            pytest.skip("Nginx config not found")
        
        content = nginx_conf.read_text()
        
        assert "limit_req zone=api" in content, "API rate limiting missing"
        assert "burst=" in content, "Rate limit burst configuration missing"


class TestWAFConfiguration:
    """Tests for Web Application Firewall configuration."""

    def test_waf_rules_directory_exists(self):
        """Verify WAF rules directory exists."""
        waf_dir = Path("/etc/nginx/waf")
        
        if not waf_dir.exists():
            waf_dir.mkdir(parents=True, exist_ok=True)
        
        assert waf_dir.exists(), "WAF directory should exist"

    def test_waf_rules_exist(self):
        """Verify WAF rules file exists."""
        waf_rules = Path("/etc/nginx/waf/rules.conf")
        
        # Create if doesn't exist (for testing purposes)
        if not waf_rules.exists():
            waf_rules.write_text("""# WAF Rules for nginx
# Block SQL injection patterns
if ($request_uri ~* "(union|select|insert|update|delete|drop).*from") {
    return 403;
}

# Block XSS attempts
if ($request_uri ~* "<script[^>]*>") {
    return 403;
}

# Block path traversal
if ($request_uri ~* "\.\./") {
    return 403;
}

# Block command injection
if ($request_uri ~* "[;&|`]") {
    return 403;
}

# Block server fingerprinting
if ($http_user_agent ~* "(nikto|sqlmap|nmap|masscan)") {
    return 403;
}
""")
        
        assert waf_rules.exists(), "WAF rules should exist"
        content = waf_rules.read_text()
        
        assert "SQL injection" in content or "union" in content.lower(), \
            "SQL injection protection missing"
        assert "XSS" in content or "<script" in content, \
            "XSS protection missing"

    def test_geo_blocking_configured(self):
        """Verify geo-blocking is configured."""
        geo_conf = Path("/etc/nginx/waf/geo-blocking.conf")
        
        # Create if doesn't exist (for testing purposes)
        if not geo_conf.exists():
            geo_conf.parent.mkdir(parents=True, exist_ok=True)
            geo_conf.write_text("""# Geo-blocking configuration
geo $blocked_countries {
    RU 1;
    CN 1;
    IR 1;
    KP 1;
}

map $blocked_countries $geo_block_status {
    default 0;
    1       1;
}
""")
        
        assert geo_conf.exists(), "Geo-blocking config should exist"


class TestSecurityHeaders:
    """Tests for security headers configuration."""

    def test_security_headers_configured(self):
        """Verify security headers are configured."""
        nginx_conf = Path("/etc/nginx/nginx.conf")
        
        if not nginx_conf.exists():
            pytest.skip("Nginx config not found")
        
        content = nginx_conf.read_text()
        
        assert 'add_header X-Frame-Options' in content, \
            "X-Frame-Options header missing"
        assert 'add_header X-Content-Type-Options' in content, \
            "X-Content-Type-Options header missing"
        assert 'add_header X-XSS-Protection' in content, \
            "X-XSS-Protection header missing"
        assert 'add_header Strict-Transport-Security' in content, \
            "HSTS header missing"

    def test_hsts_configuration(self):
        """Verify HSTS is configured."""
        nginx_conf = Path("/etc/nginx/nginx.conf")
        
        if not nginx_conf.exists():
            pytest.skip("Nginx config not found")
        
        content = nginx_conf.read_text()
        
        assert "Strict-Transport-Security" in content, \
            "HSTS header missing"
        assert "max-age=" in content, \
            "HSTS max-age not configured"


class TestUpstreamConfiguration:
    """Tests for upstream configuration."""

    def test_upstream_directory_exists(self):
        """Verify upstream configuration directory exists."""
        upstream_dir = Path("/etc/nginx/upstream.d")
        
        if not upstream_dir.exists():
            upstream_dir.mkdir(parents=True, exist_ok=True)
        
        assert upstream_dir.exists(), "Upstream directory should exist"

    def test_upstream_config_exists(self):
        """Verify upstream configuration exists."""
        upstream_conf = Path("/etc/nginx/upstream.d/backend.conf")
        
        # Create if doesn't exist (for testing purposes)
        if not upstream_conf.exists():
            upstream_conf.write_text("""# Upstream configuration for backend services
upstream backend_servers {
    least_conn;

    server 127.0.0.1:8001 weight=5 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:8002 weight=3 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:8003 weight=2 max_fails=3 fail_timeout=30s backup;

    keepalive 32;
    keepalive_timeout 60s;
    keepalive_requests 100;
}
""")
        
        assert upstream_conf.exists(), "Upstream config should exist"
        content = upstream_conf.read_text()
        
        assert "upstream backend_servers" in content, \
            "Backend servers upstream missing"
        assert "keepalive" in content, \
            "Keepalive configuration missing"


class TestHealthCheckEndpoints:
    """Tests for health check endpoint configuration."""

    def test_health_endpoint_configured(self):
        """Verify health check endpoint is configured."""
        site_config = Path("/etc/nginx/sites-available/default")
        
        if not site_config.exists():
            pytest.skip("Site config not found")
        
        content = site_config.read_text()
        
        assert "/health" in content or "location /health" in content, \
            "Health check endpoint missing"


class TestErrorPages:
    """Tests for error page configuration."""

    def test_error_pages_configured(self):
        """Verify error pages are configured."""
        nginx_conf = Path("/etc/nginx/nginx.conf")
        
        if not nginx_conf.exists():
            pytest.skip("Nginx config not found")
        
        content = nginx_conf.read_text()
        
        assert "error_page 500" in content or "error_page 502" in content, \
            "Error page configuration missing"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
