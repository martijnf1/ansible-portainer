# Ansible Collection - marzekan.portainer

This module was developed to automate deployment of Portainer stacks and initial setup of fresh Portainer installs.

**Install**

```bash
ansible-galaxy collection install marzekan.portainer
```

**Example:**

```yaml
- name: Deploy Portainer stacks
  hosts: localhost
  connection: local
  tasks:
    - name: Deploy stacks
      marzekan.portainer:
        root_url: "https://<ip>:9443"
        initial_setup: yes
        admin_username: "admin" # BEST IF STORED IN VAULT !
        admin_password: "bigsecret123" # BEST IF STORED IN VAULT !
        endpoint: "local"
        stacks:
          - name: Stack1
            compose_file: "./<path>/docker-compose.yml"
          - name: Stack2
            compose_file: "./<path>/docker-compose.yml"
```

> [!NOTE]
> It's normal for task to take 5+ minutes, even if `pipelining=True` is set in ansible config.

