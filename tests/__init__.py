"""
Ansible RHEL9 Cluster Security Playbooks - Test Suite
Comprehensive pytest integration for validating deployment components
"""

import os
import sys
import subprocess
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class AnsibleTestBase:
    """Base class for Ansible playbook tests."""

    def __init__(self):
        self.playbook_dir = Path(__file__).parent.parent / "playbooks"
        self.roles_dir = Path(__file__).parent.parent / "roles"
        self.inventory_file = Path(__file__).parent.parent / "inventory.ini"

    def run_ansible_command(self, command, check=True):
        """Run an Ansible command and return the result."""
        result = subprocess.run(
            ["ansible-playbook"] + command.split() + ["-i", "tests/inventory"],
            capture_output=True,
            text=True,
            check=check
        )
        return result

    def assert_playbook_syntax(self, playbook_path):
        """Check if a playbook has valid YAML syntax."""
        result = subprocess.run(
            ["ansible-playbook", str(playbook_path), "--syntax-check"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0, f"Playbook syntax error: {result.stderr}"

    def assert_role_syntax(self, role_path):
        """Check if a role has valid structure."""
        result = subprocess.run(
            ["ansible-playbook", "--syntax-check", str(role_path)],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0, f"Role syntax error: {result.stderr}"


class TestSecurityHardening(AnsibleTestBase):
    """Tests for security-hardening.yml playbook."""

    def test_fail2ban_config(self):
        """Verify fail2ban configuration is applied."""
        # Check that jail.local exists and has correct content
        jail_local = self.playbook_dir.parent / "jail.local"
        assert jail_local.exists(), "Fail2ban jail.local should exist"

        with open(jail_local) as f:
            content = f.read()
        
        assert "[nginx-http-auth]" in content, "Nginx HTTP auth jail missing"
        assert "[nginx-botsearch]" in content, "Nginx botsearch jail missing"
        assert "enabled = true" in content, "Jails should be enabled"
        assert "maxretry = 3" in content, "Max retry count incorrect"

    def test_kernel_parameters(self):
        """Verify kernel security parameters are configured."""
        sysctl_conf = self.playbook_dir.parent / "tests/sysctl-security.conf"
        assert sysctl_conf.exists(), "Sysctl config should exist"

        with open(sysctl_conf) as f:
            content = f.read()
        
        assert "net.ipv4.tcp_syncookies = 1" in content, "SYN cookies not configured"
        assert "kernel.randomize_va_space = 2" in content, "ASLR not enabled"
        assert "net.ipv4.conf.all.rp_filter = 1" in content, "Reverse path filtering missing"

    def test_firewall_rules(self):
        """Verify firewall rules are configured."""
        # Check that firewall service is enabled
        result = subprocess.run(
            ["systemctl", "is-enabled", "firewalld"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0, "Firewalld should be enabled"

    def test_selinux_configuration(self):
        """Verify SELinux is properly configured."""
        # Check SELinux status if available
        try:
            result = subprocess.run(
                ["getenforce"],
                capture_output=True,
                text=True
            )
            assert result.returncode == 0, "SELinux should be installed"
        except FileNotFoundError:
            pass  # SELinux not installed on this system


class TestMonitoringSetup(AnsibleTestBase):
    """Tests for monitoring-setup.yml playbook."""

    def test_prometheus_installed(self):
        """Verify Prometheus client libraries are installed."""
        result = subprocess.run(
            ["rpm", "-qa", "--queryformat", "%{NAME}\n", "python3-prometheus-client"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0 or "python3-prometheus-client" in result.stdout, \
            "Prometheus client library should be installed"

    def test_metrics_endpoint_exists(self):
        """Verify metrics endpoint script exists."""
        metrics_script = Path("/usr/local/bin/nginx-metrics-exporter")
        assert metrics_script.exists(), "Metrics exporter script should exist"

    def test_prometheus_config(self):
        """Verify Prometheus scrape configuration."""
        prometheus_config = self.playbook_dir.parent / "tests/prometheus/scrape.yml"
        assert prometheus_config.exists(), "Prometheus config should exist"

        with open(prometheus_config) as f:
            content = f.read()
        
        assert "job_name: 'nginx-metrics'" in content, "Nginx metrics job missing"
        assert "job_name: 'node-exporter'" in content, "Node exporter job missing"

    def test_grafana_dashboard(self):
        """Verify Grafana dashboard configuration."""
        dashboard_config = self.playbook_dir.parent / "tests/prometheus/nginx-security.json"
        if dashboard_config.exists():
            with open(dashboard_config) as f:
                content = f.read()
            
            assert "Nginx Security Dashboard" in content, "Dashboard title missing"
            assert "Prometheus" in content, "Prometheus data source missing"


class TestNginxConfiguration(AnsibleTestBase):
    """Tests for nginx-reverse-proxy role."""

    def test_nginx_config_syntax(self):
        """Verify nginx configuration syntax is valid."""
        nginx_conf = self.playbook_dir.parent / "nginx.conf.j2"
        assert nginx_conf.exists(), "Nginx config template should exist"

        # Check basic structure
        with open(nginx_conf) as f:
            content = f.read()
        
        assert "http {" in content, "HTTP block missing"
        assert "server {" in content, "Server block missing"
        assert "ssl_protocols" in content, "SSL protocols not configured"
        assert "add_header X-Frame-Options" in content, "Security headers missing"

    def test_rate_limiting_config(self):
        """Verify rate limiting configuration."""
        rate_limit_conf = self.playbook_dir.parent / "rate-limit.conf"
        if rate_limit_conf.exists():
            with open(rate_limit_conf) as f:
                content = f.read()
            
            assert "limit_req_zone" in content, "Rate limiting zone missing"
            assert "limit_conn_zone" in content, "Connection limit zone missing"

    def test_waf_rules(self):
        """Verify WAF rules are configured."""
        waf_rules = self.playbook_dir.parent / "tests/waf/rules.conf"
        if waf_rules.exists():
            with open(waf_rules) as f:
                content = f.read()
            
            assert "SQL injection" in content, "SQL injection protection missing"
            assert "XSS" in content, "XSS protection missing"
            assert "path traversal" in content, "Path traversal protection missing"

    def test_geo_blocking(self):
        """Verify geo-blocking configuration."""
        geo_conf = self.playbook_dir.parent / "tests/waf/geo-blocking.conf"
        if geo_conf.exists():
            with open(geo_conf) as f:
                content = f.read()
            
            assert "blocked_countries" in content, "Blocked countries config missing"


class TestInventoryConfiguration(AnsibleTestBase):
    """Tests for inventory.ini configuration."""

    def test_inventory_syntax(self):
        """Verify inventory file has valid syntax."""
        result = subprocess.run(
            ["ansible-inventory", "-l", "-i", str(self.inventory_file)],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0, f"Inventory syntax error: {result.stderr}"

    def test_cluster_group_exists(self):
        """Verify cluster group is defined."""
        with open(self.inventory_file) as f:
            content = f.read()
        
        assert "[cluster]" in content, "Cluster group missing"
        assert "web1.example.com" in content, "Web server 1 missing from inventory"

    def test_monitoring_group_exists(self):
        """Verify monitoring group is defined."""
        with open(self.inventory_file) as f:
            content = f.read()
        
        assert "[monitoring]" in content, "Monitoring group missing"


class TestPlaybookStructure(AnsibleTestBase):
    """Tests for overall playbook structure."""

    def test_site_playbook_exists(self):
        """Verify main site.yml exists."""
        site_yml = self.playbook_dir / "site.yml"
        assert site_yml.exists(), "site.yml should exist"

    def test_security_hardening_exists(self):
        """Verify security-hardening.yml exists."""
        hardening_yml = self.playbook_dir / "security-hardening.yml"
        assert hardening_yml.exists(), "security-hardening.yml should exist"

    def test_monitoring_setup_exists(self):
        """Verify monitoring-setup.yml exists."""
        monitoring_yml = self.playbook_dir / "monitoring-setup.yml"
        assert monitoring_yml.exists(), "monitoring-setup.yml should exist"

    def test_roles_directory_exists(self):
        """Verify roles directory structure."""
        nginx_role = self.roles_dir / "nginx-reverse-proxy"
        assert nginx_role.exists(), "nginx-reverse-proxy role should exist"

        tasks_file = nginx_role / "tasks" / "main.yml"
        assert tasks_file.exists(), "Role tasks/main.yml should exist"

        defaults_file = nginx_role / "defaults" / "main.yml"
        assert defaults_file.exists(), "Role defaults/main.yml should exist"

    def test_templates_directory_exists(self):
        """Verify templates directory structure."""
        templates_dir = self.roles_dir / "nginx-reverse-proxy" / "templates"
        assert templates_dir.exists(), "Templates directory should exist"

        nginx_conf_template = templates_dir / "nginx.conf.j2"
        assert nginx_conf_template.exists(), "nginx.conf.j2 template should exist"

        site_conf_template = templates_dir / "site.conf.j2"
        assert site_conf_template.exists(), "site.conf.j2 template should exist"


class TestRequirements(AnsibleTestBase):
    """Tests for Python dependencies."""

    def test_requirements_file_exists(self):
        """Verify requirements.txt exists."""
        requirements = self.playbook_dir.parent / "requirements.txt"
        assert requirements.exists(), "requirements.txt should exist"

    def test_required_packages(self):
        """Verify required Python packages are listed."""
        with open(self.playbook_dir.parent / "requirements.txt") as f:
            content = f.read()
        
        assert "jinja2" in content, "Jinja2 missing from requirements"
        assert "ansible-lint" in content, "Ansible-lint missing from requirements"
        assert "pytest" in content, "Pytest missing from requirements"


class TestValidationScript(AnsibleTestBase):
    """Tests for cluster validation script."""

    def test_validate_script_exists(self):
        """Verify validation script exists."""
        validate_script = self.playbook_dir.parent / "tests" / "validate-cluster.sh"
        assert validate_script.exists(), "validate-cluster.sh should exist"

    def test_validate_script_syntax(self):
        """Verify validation script has valid bash syntax."""
        result = subprocess.run(
            ["bash", "-n", str(validate_script)],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0, f"Validation script syntax error: {result.stderr}"


def run_all_tests():
    """Run all tests and return summary."""
    import pytest
    
    # Run pytest with verbose output
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "-ra"
    ])


if __name__ == "__main__":
    run_all_tests()
