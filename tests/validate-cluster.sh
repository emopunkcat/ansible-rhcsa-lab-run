#!/bin/bash
set -e
echo "Checking RHEL version..."
rpm -qa | grep '^redhat-release-' | head -1 || exit 1
echo "Verifying Ansible..."
ansible --version | grep Ansible || exit 1
