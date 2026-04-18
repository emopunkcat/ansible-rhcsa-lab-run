# ansible-rhcsa-lab-runner

Ansible playbook suite for RHEL 9 security hardening, monitoring, and Nginx reverse proxy deployment.

## Overview

Production-ready automation for RHEL 9 / Rocky Linux 9 clusters. Covers CIS Benchmarks hardening, Prometheus/Grafana monitoring stack, and hardened Nginx reverse proxy with WAF and rate limiting.

## Architecture

```
                    Internet
                       |
              [Nginx Reverse Proxy]
              (SSL/TLS + WAF + Rate Limit)
                       |
          +------------+------------+
          |            |            |
     [web1]      [web2]      [web3]
       |            |            |
       +-- Security Hardening --+
       |   - fail2ban
       |   - sysctl kernel params
       |   - firewalld
       |   - SELinux
       +-- Monitoring Stack -----+
           - Prometheus
           - Node Exporter
           - Grafana
           - AlertManager
```

## Features

- **Security Hardening**: CIS-aligned kernel sysctls, fail2ban, firewalld, SELinux enforcement
- **Monitoring Stack**: Prometheus, Node Exporter, Grafana, AlertManager with Slack integration
- **Nginx Reverse Proxy**: SSL/TLS, security headers, rate limiting, WAF, geo-blocking
- **Environment-Driven**: Separate production/staging profiles in inventory
- **CI/CD**: Multi-stage linting, syntax checks, pytest, formatting, staging deploy
- **OpenShift Ready**: Deployment manifests alongside bare-metal support

## Quick Start

```bash
git clone https://github.com/emopunkcat/ansible-rhcsa-lab-runner.git
cd ansible-rhcsa-lab-runner

cp inventory.example inventory.ini
# Edit inventory.ini with your hosts

ansible-playbook playbooks/site.yml -i inventory.ini
```

## Requirements

- Ansible >= 2.14.0
- Python >= 3.8
- RHEL 9 or Rocky Linux 9 target hosts
- SSH key-based authentication to target hosts

### Installation

```bash
pip install -r requirements.txt
ansible-galaxy collection install -r requirements.yml
```

### Deployment

```bash
# Full stack
ansible-playbook playbooks/site.yml -i inventory.ini

# Security hardening only
ansible-playbook playbooks/security-hardening.yml -i inventory.ini --tags security

# Monitoring stack only
ansible-playbook playbooks/monitoring-setup.yml -i inventory.ini --tags monitoring

# Nginx reverse proxy only
ansible-playbook playbooks/security-hardening.yml -i inventory.ini --tags nginx
```

## Roles

### security-hardening

CIS Benchmark-aligned hardening for RHEL 9: CVE patches, kernel sysctls (SYN cookies, ASLR, reverse path filtering), fail2ban with nginx jails, firewalld custom zones, SELinux enforcing mode. Variables in `roles/security-hardening/defaults/main.yml`.

### monitoring-setup

Full observability stack: Prometheus server, Node Exporter, Grafana dashboards, AlertManager with Slack webhook. Variables in `roles/monitoring-setup/defaults/main.yml`.

### nginx-reverse-proxy

Hardened proxy: SSL/TLS with Let's Encrypt, security headers (CSP, HSTS, X-Frame-Options, Permissions-Policy), rate limiting, WAF rules, geo-blocking for RU/CN/IR/KP/SY/CU/VN/MM. Variables in `roles/nginx-reverse-proxy/defaults/main.yml`.

## Directory Structure

```
.
├── playbooks/              # Orchestration playbooks
├── roles/                  # Ansible roles (security-hardening, monitoring-setup, nginx-reverse-proxy)
├── openshift/              # Kubernetes/OpenShift manifests
├── tests/                  # Pytest integration suite
├── inventory.ini           # Host inventory
├── inventory.example       # Inventory template
├── galaxy.yml              # Ansible Galaxy metadata
├── requirements.txt        # Python dependencies
├── requirements.yml        # Ansible collection dependencies
├── ansible.cfg             # Ansible runtime config
└── pyproject.toml          # Python tooling config
```

## Inventory

Supports production and staging environments via `[cluster:vars:production]` and `[cluster:vars:staging]` blocks in `inventory.ini` for toggling ssl_enabled, geo_blocking_enabled, rate_limit_burst, api_rate_limit_burst.

## Testing

```bash
# All tests
python -m pytest tests/ -v

# Cluster validation
bash tests/validate-cluster.sh
```

## CI/CD Pipeline

`.github/workflows/ci.yml` runs: ansible-lint, yamllint, playbook syntax checks, pytest, Bandit security scanning, black/flake8 formatting, markdownlint, staging deployment diff check.

## License

MIT License. See LICENSE.
