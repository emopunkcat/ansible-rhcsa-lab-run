# OpenShift Deployment Variant

This directory contains Ansible playbooks for deploying hardened Nginx reverse proxy clusters on **Red Hat OpenShift**.

## 🎯 Use Case

Deploy production-grade Nginx reverse proxy with:
- ✅ OpenShift-native resources (DeploymentConfigs, Routes, Services)
- ✅ Security Context Constraints (SCC) for pod security
- ✅ Network Policies for micro-segmentation
- ✅ Prometheus Operator integration
- ✅ Grafana dashboards in monitoring namespace

## 📦 Prerequisites

- Red Hat OpenShift 4.x cluster
- `oc` CLI installed and configured
- Access to OpenShift API server
- Valid kubeconfig file

## 🚀 Quick Start

```bash
# Configure inventory
cp playbooks/openshift/inventory.example playbooks/openshift/inventory.ini
vi playbooks/openshift/inventory.ini  # Edit with your cluster details

# Deploy to OpenShift
ansible-playbook playbooks/openshift/site.yml -i playbooks/openshift/inventory.ini
```

## 📋 Available Resources

### Namespace Management
- Create dedicated `nginx-proxy` namespace
- Isolate resources from other namespaces

### Deployment Configuration
- DeploymentConfig for rolling updates
- Service for internal pod communication
- Route (Ingress) for external access

### Security Hardening
- Security Context Constraints (SCC): restricted profile
- Network Policies: limit pod-to-pod communication
- Read-only root filesystem where possible
- Drop all capabilities except NET_BIND_SERVICE

### Monitoring Integration
- Prometheus Operator deployment
- Grafana dashboards in monitoring namespace
- AlertManager integration for security events

## 🔒 Security Features

| Feature | Description |
|---------|-------------|
| **SCC: Restricted** | Only essential privileges, no host access |
| **Network Policies** | Default-deny, allow-list only required traffic |
| **Security Context** | Run containers as non-root where possible |
| **SELinux** | Enforced (OpenShift default) |
| **Pod Security Standards** | Restricted profile enforced |

## 📊 Monitoring Stack

The OpenShift variant includes:
- **Prometheus Operator**: Metrics collection and storage
- **Grafana**: Visualization dashboards
- **AlertManager**: Security event alerting

Access Grafana at: `https://grafana.your-domain.example.com`

## 🔗 Related Documentation

- [OpenShift Container Platform Documentation](https://docs.openshift.com/)
- [OpenShift Routes (Ingress)](https://docs.openshift.com/container-platform/latest/networking/routes.html)
- [Security Context Constraints](https://docs.openshift.com/security/scanning/scc.html)
- [Network Policies](https://docs.openshift.com/security/protecting-applications/nps.html)

## 📝 Notes

This variant is **complementary** to the standalone RHEL 9 VM deployment:
- **RHEL 9 VMs**: Use `playbooks/site.yml` for traditional infrastructure
- **OpenShift**: Use `playbooks/openshift/site.yml` for container platforms

Both can coexist in your infrastructure!
