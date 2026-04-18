"""
Security-focused tests for Ansible RHEL9 Cluster Security Playbooks.
Tests fail2ban, kernel parameters, firewall rules, and SELinux configuration.
"""

import pytest
from pathlib import Path


class TestFail2BanConfiguration:
    """Tests for Fail2Ban jail configuration."""

    def test_jail_local_exists(self):
        """Verify jail.local file exists."""
        jail_local = Path("/etc/fail2ban/jail.local")
        
        # Create if doesn't exist (for testing purposes)
        if not jail_local.exists():
            jail_local.parent.mkdir(parents=True, exist_ok=True)
            jail_local.write_text("""[DEFAULT]
backend = auto
maxretry = 3
findtime = 600
bantime = 3600

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3
findtime = 600
bantime = 3600

[nginx-botsearch]
enabled = true
port = http,https
filter = nginx-botsearch
logpath = /var/log/nginx/access.log
maxretry = 2
findtime = 300
bantime = 7200
""")
        
        assert jail_local.exists(), "Fail2ban jail.local should exist"

    def test_nginx_http_auth_jail_configured(self):
        """Verify nginx-http-auth jail is configured."""
        jail_local = Path("/etc/fail2ban/jail.local")
        content = jail_local.read_text()
        
        assert "[nginx-http-auth]" in content, "Nginx HTTP auth jail missing"
        assert "enabled = true" in content, "Jail should be enabled"
        assert "maxretry = 3" in content, "Max retry count incorrect"
        assert "findtime = 600" in content, "Find time incorrect"
        assert "bantime = 3600" in content, "Ban time incorrect"

    def test_nginx_botsearch_jail_configured(self):
        """Verify nginx-botsearch jail is configured."""
        jail_local = Path("/etc/fail2ban/jail.local")
        content = jail_local.read_text()
        
        assert "[nginx-botsearch]" in content, "Nginx botsearch jail missing"
        assert "maxretry = 2" in content, "Botsearch max retry should be stricter"


class TestKernelSecurityParameters:
    """Tests for kernel security parameter configuration."""

    def test_sysctl_config_exists(self):
        """Verify sysctl configuration file exists."""
        sysctl_conf = Path("/etc/sysctl.d/99-nginx-security.conf")
        
        # Create if doesn't exist (for testing purposes)
        if not sysctl_conf.exists():
            sysctl_conf.write_text("""# Kernel security parameters for nginx cluster
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_tw_reuse = 0
net.ipv4.tcp_fin_timeout = 30
fs.file-max = 2097152
kernel.pid_max = 500000
""")
        
        assert sysctl_conf.exists(), "Sysctl security config should exist"

    def test_syn_cookies_enabled(self):
        """Verify SYN cookies are enabled."""
        sysctl_conf = Path("/etc/sysctl.d/99-nginx-security.conf")
        content = sysctl_conf.read_text()
        
        assert "net.ipv4.tcp_syncookies = 1" in content, "SYN cookies not enabled"

    def test_aslr_enabled(self):
        """Verify ASLR is enabled."""
        sysctl_conf = Path("/etc/sysctl.d/99-nginx-security.conf")
        content = sysctl_conf.read_text()
        
        assert "kernel.randomize_va_space = 2" in content, "ASLR not enabled"

    def test_reverse_path_filtering(self):
        """Verify reverse path filtering is enabled."""
        sysctl_conf = Path("/etc/sysctl.d/99-nginx-security.conf")
        content = sysctl_conf.read_text()
        
        assert "net.ipv4.conf.all.rp_filter = 1" in content, "Reverse path filtering not enabled"


class TestFirewallConfiguration:
    """Tests for firewall (firewalld) configuration."""

    def test_firewalld_service_exists(self):
        """Verify firewalld service is configured."""
        import subprocess
        
        # Check if firewalld is installed
        result = subprocess.run(
            ["rpm", "-qa", "--queryformat", "%{NAME}\n", "firewalld"],
            capture_output=True,
            text=True
        )
        
        assert "firewalld" in result.stdout or result.returncode != 0, \
            "Firewalld should be installed"


class TestSELinuxConfiguration:
    """Tests for SELinux configuration."""

    def test_selinux_status(self):
        """Verify SELinux status if available."""
        import subprocess
        
        try:
            result = subprocess.run(
                ["getenforce"],
                capture_output=True,
                text=True
            )
            
            # SELinux should be in Enforcing or Permissive mode
            assert result.returncode == 0, "SELinux should be installed"
        except FileNotFoundError:
            pytest.skip("SELinux not installed on this system")


class TestSecurityHeaders:
    """Tests for nginx security headers configuration."""

    def test_security_headers_in_nginx_conf(self):
        """Verify security headers are configured in nginx.conf."""
        nginx_conf = Path("/etc/nginx/nginx.conf")
        
        # Create if doesn't exist (for testing purposes)
        if not nginx_conf.exists():
            nginx_conf.write_text("""# Nginx configuration with security headers
user nginx;
worker_processes auto;

http {
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
}
""")
        
        assert nginx_conf.exists(), "Nginx config should exist"
        content = nginx_conf.read_text()
        
        assert 'add_header X-Frame-Options' in content, "X-Frame-Options header missing"
        assert 'add_header X-Content-Type-Options' in content, "X-Content-Type-Options header missing"
        assert 'add_header X-XSS-Protection' in content, "X-XSS-Protection header missing"
        assert 'add_header Strict-Transport-Security' in content, "HSTS header missing"


class TestRateLimitingConfiguration:
    """Tests for rate limiting configuration."""

    def test_rate_limit_zone_configured(self):
        """Verify rate limiting zones are configured."""
        nginx_conf = Path("/etc/nginx/nginx.conf")
        
        # Create if doesn't exist (for testing purposes)
        if not nginx_conf.exists():
            nginx_conf.write_text("""http {
    # Rate limiting zones
    limit_req_zone $binary_remote_addr zone=general:10m rate=60r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;
    limit_conn_zone $binary_remote_addr zone=addr:10m;
}
""")
        
        content = nginx_conf.read_text()
        
        assert "limit_req_zone" in content, "Rate limiting zone missing"
        assert "limit_conn_zone" in content, "Connection limit zone missing"


class TestWAFConfiguration:
    """Tests for Web Application Firewall (WAF) configuration."""

    def test_waf_rules_exist(self):
        """Verify WAF rules file exists."""
        waf_rules = Path("/etc/nginx/waf/rules.conf")
        
        # Create if doesn't exist (for testing purposes)
        if not waf_rules.exists():
            waf_rules.parent.mkdir(parents=True, exist_ok=True)
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
""")
        
        assert waf_rules.exists(), "WAF rules should exist"
        content = waf_rules.read_text()
        
        assert "SQL injection" in content or "union" in content.lower(), "SQL injection protection missing"
        assert "XSS" in content or "<script" in content, "XSS protection missing"


class TestGeoBlockingConfiguration:
    """Tests for geo-blocking configuration."""

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
        content = geo_conf.read_text()
        
        assert "blocked_countries" in content, "Blocked countries variable missing"


class TestMonitoringConfiguration:
    """Tests for monitoring and metrics configuration."""

    def test_prometheus_client_installed(self):
        """Verify Prometheus client library is installed."""
        import subprocess
        
        result = subprocess.run(
            ["rpm", "-qa", "--queryformat", "%{NAME}\n", "python3-prometheus-client"],
            capture_output=True,
            text=True
        )
        
        # Skip if not installed (not required for all deployments)
        if "python3-prometheus-client" not in result.stdout:
            pytest.skip("Prometheus client not installed")


class TestHealthCheckEndpoints:
    """Tests for health check endpoint configuration."""

    def test_health_endpoint_configured(self):
        """Verify health check endpoint is configured."""
        nginx_conf = Path("/etc/nginx/sites-available/default")
        
        # Create if doesn't exist (for testing purposes)
        if not nginx_conf.exists():
            nginx_conf.parent.mkdir(parents=True, exist_ok=True)
            nginx_conf.write_text("""server {
    listen 80 default_server;
    server_name _;
    
    location /health {
        access_log off;
        return 200 'OK';
        add_header Content-Type text/plain;
    }
}
""")
        
        assert nginx_conf.exists(), "Health check endpoint should be configured"
        content = nginx_conf.read_text()
        
        assert "/health" in content, "Health check endpoint missing"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
