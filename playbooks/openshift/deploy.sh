#!/bin/bash
# Ansible RHEL9 Cluster Security Playbooks - OpenShift Deployment Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INVENTORY_FILE="${SCRIPT_DIR}/inventory.ini"

echo "=========================================="
echo "  OpenShift Nginx Deployment Script"
echo "=========================================="
echo ""

# Check if oc CLI is installed
if ! command -v oc &> /dev/null; then
    echo "❌ Error: OpenShift CLI (oc) not found!"
    echo "   Install with: curl --proto '=https' --tlsv1.2 -LsSf https://release.openshift.com/release/openshift-client-linux.sh | sh"
    exit 1
fi

# Check if kubeconfig exists
if [ ! -f "${KUBECONFIG:-$HOME/.kube/config}" ]; then
    echo "❌ Error: Kubeconfig file not found!"
    echo "   Set KUBECONFIG environment variable or create ~/.kube/config"
    exit 1
fi

# Check if inventory is configured
if [ ! -f "${INVENTORY_FILE}" ]; then
    echo "❌ Error: Inventory file not found!"
    echo "   Run: cp ${SCRIPT_DIR}/inventory.example ${INVENTORY_FILE}"
    echo "   Then edit ${INVENTORY_FILE} with your cluster details"
    exit 1
fi

# Display deployment info
echo "📦 Deployment Configuration:"
echo "   Cluster: $(grep openshift_cluster_name ${INVENTORY_FILE} | cut -d= -f2)"
echo "   Route URL: $(grep openshift_route_url ${INVENTORY_FILE} | cut -d= -f2 2>/dev/null || echo 'N/A')"
echo ""

# Deploy to OpenShift
echo "🚀 Deploying Nginx reverse proxy cluster to OpenShift..."
ansible-playbook playbooks/openshift/site.yml \
    -i "${INVENTORY_FILE}" \
    --vault-password-file="${VAULT_PASSWORD_FILE:-${HOME}/.ansible_vault_pass}" \
    2>&1 | tee /var/log/nginx-openshift-deploy.log

# Check deployment status
echo ""
echo "📊 Checking deployment status..."
oc get pods -n nginx-proxy -o wide

echo ""
echo "=========================================="
echo "  Deployment Complete!"
echo "=========================================="
echo ""
echo "Next Steps:"
echo "1. Verify pods are running: oc get pods -n nginx-proxy"
echo "2. Check logs: oc logs -f -l app=nginx-proxy -n nginx-proxy"
echo "3. Access route: $(grep openshift_route_url ${INVENTORY_FILE} | cut -d= -f2 2>/dev/null || echo 'Check inventory.ini')"
echo ""
