# Contributing to Ansible RHEL9 Cluster Security Playbooks

This project maintains enterprise-grade security standards and follows strict code quality guidelines.

## Code of Conduct

- Be respectful and professional
- Focus on security best practices
- Document your changes clearly
- Test before submitting

## Development Guidelines

### Before Submitting Changes

1. Run linting checks:

   ```bash
   ansible-lint playbooks/ roles/
   yamllint -d relaxed playbooks/ roles/
   ```

2. Test your changes:

   ```bash
   pytest tests/ -v
   ansible-playbook playbooks/site.yml -i tests/inventory --check
   ```

3. Update documentation:
   - Update README.md with new features
   - Add security context comments to sensitive tasks
   - Include usage examples for new variables

### Code Style Guidelines

#### Ansible Playbooks

```yaml
---
- name: Configure nginx security hardening
  hosts: cluster
  become: true
  vars_files:
    - vars/nginx-security.yml

  tasks:
    - name: Apply kernel security parameters
      ansible.builtin.sysctl:
        name: "{{ item.name }}"
        value: "{{ item.value }}"
        sysctl_set: true
        state: present
      loop: "{{ security_kernel_params }}"
      when: deployment_environment == 'production'

      # Security context comment explaining the change
      # sec: Prevents IP spoofing attacks by enabling reverse path filtering
```

#### Jinja2 Templates

```jinja2
{% set secure_headers = {
    'X-Frame-Options': 'SAMEORIGIN',
    'X-Content-Type-Options': "nosniff",
    'X-XSS-Protection': "1; mode=block"
} %}

http {
    # Security headers for all responses
    {% for header, value in secure_headers.items() %}
    add_header {{ header }} "{{ value }}" always;
    {% endfor %}

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
}
```

### Security Context Comments

All security-sensitive tasks should include context comments:

```yaml
tasks:
  - name: Disable IPv6 (security hardening)
    ansible.builtin.sysctl:
      name: net.ipv6.conf.all.disable_ipv6
      value: "1"
    # sec: Disables IPv6 to prevent potential IPv6-based attacks
    # sec: Only disable if IPv6 is not required for your infrastructure
```

## Testing Requirements

### Unit Tests

All new playbooks must include corresponding tests:

```python
"""Test for new playbook feature."""
import pytest


class TestNewFeature:
    def test_feature_configured(self):
        """Verify new feature is configured correctly."""
        # Your test code here
        assert True
```

### Integration Tests

Run integration tests in check mode before deploying:

```bash
ansible-playbook playbooks/site.yml \
  -i tests/inventory \
  --check \
  --diff \
  -v
```

## Pull Request Checklist

- [ ] Run `ansible-lint` on all playbooks
- [ ] Add security context comments to sensitive tasks
- [ ] Update README.md with new features
- [ ] Add corresponding tests in `tests/` directory
- [ ] Update `inventory.example` if new variables added
- [ ] Check for TODO/FIXME comments and address them
- [ ] Ensure all Jinja2 templates have proper variable escaping
- [ ] Verify SSL/TLS configuration uses modern protocols only

## Security Review Process

All pull requests will be reviewed for:

1. **Security implications** - Does this introduce vulnerabilities?
2. **Defense in depth** - Are there multiple layers of protection?
3. **Fail-safe defaults** - What happens if something goes wrong?
4. **Auditability** - Can changes be tracked and audited?

### Common Security Issues to Avoid

- Hardcoded secrets or API keys
- Insecure SSL/TLS configurations
- Missing input validation in templates
- Excessive logging of sensitive data
- Disabled security controls for convenience

## Resources

- [Ansible Security Best Practices](https://docs.ansible.com/ansible/latest/security.html)
- [Red Hat Security Guidelines](https://access.redhat.com/security/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Benchmarks for RHEL 9](https://www.cisecurity.org/benchmark/RHEL_9)

## Contact

For security issues or concerns:
1. Review the troubleshooting section in README.md
2. Check Ansible logs in `/var/log/ansible/`
3. Open a GitHub issue with detailed reproduction steps

---

**Last Updated:** April 2026
**Maintained by:** emopunkcat
