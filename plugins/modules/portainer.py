#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: marzekan
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
module: portainer
short_description: Remotely deploy Portainer stacks and perform initial setup
description:
  - This module automates initial admin and endpoint setup on fresh Portainer install.
  - Stacks are deployed by providing a stack name and docker-compose.yml file from local machine.
  - Module's main purpose is to be used in playbooks for provisining infrastructure that rely on Portainer to host multile docker compose stacks.
version_added: "1.0.0"
author: marzekan (@marzekan)
options:
  root_url:
    description: C(https://<ip>:<port>) of Portainer instance.
    required: true
    type: bool
    version_added: "1.0.0"
  initial_setup:
    description:
      - Indicate whether or not to perform inital setup of admin user and endpoint.
      - Set to C(true) if dealing with fresh Portainer instance that has not been logged into yet.
    required: true
    type: str
    version_added: "1.0.0"
  admin_username:
    description:
      - Admin user to log in with, or create if C(initial_setup=true).
      - If C(initial_setup=true) this value will be used to create an admin user with this username.
    required: false
    type: str
    version_added: "1.0.0"
  admin_password:
    description: Admin user password. If C(initial_setup=true) this value will be used to set new admin users password.
    required: false
    type: str
    version_added: "1.0.0"
  endpoint:
    description:
      - Endpoint name to add stack to, or create if C(initial_setup=true).
      - If C(initial_setup=true) this value will be used to create endpoint of this name.
    required: true
    type: str
    version_added: "1.0.0"
  api_key:
    description:
      - API Key to use with portainer instance
    required: false
    type: str
    version_added: "1.1.0"
  verify:
    description:
      - Whether the requests module verifies HTTPS connections or not
    required: false
    type: bool
    version_added: "1.1.0"
  stacks:
    description:
      - List of stack names and their C(docker-compose.yml) files to deploy.
    required: true
    type: list
    elements: dict
    version_added: "1.0.0"
    suboptions:
      name:
        description: New stack name. If this stack already exists in Portainer, deployment will be skipped.
        required: true
        type: str
        version_added: "1.0.0"
      compose_file:
        description: New stack C(docker-compose.yml) file path on the local machine.
        required: true
        type: str
        version_added: "1.0.0"
'''

EXAMPLES = r'''
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
'''

RETURN = r'''
stacks_deployed:
  description: Number of stacks that were deployed successfully.
  returned: success
  type: str
stacks_failed_to_deploy:
  description: Number of stacks that failed to deploy.
  returned: success
  type: str

'''

import requests
from ansible.module_utils.basic import AnsibleModule

class PortainerAPI:

    useAPIToken : bool = False
    token : str = ""

    def __init__(self, ansible_module: AnsibleModule, root_url: str, verify : bool, api_token : str = ""):
        self.ansible_module = ansible_module
        self.root_url = root_url
        self.verify = verify

        # If an API token has been specified, use it instead of a login/JWT
        if api_token != "":
            self.useAPIToken = True
            self.token = api_token

    def ping(self):
        try:
            response = requests.get(
                f"{self.root_url}/",
                verify=self.verify
            )

            response.raise_for_status()
            return

        except requests.exceptions.RequestException as e:
            e.args = (f"ERROR (ping). Exception: {e}",)
            self.ansible_module.log(f"{e}")
            self.ansible_module.warn(f"Cannot reach portainer - check IP and port.")
            raise

    def _request(self, rtype : str, api_endpoint : str, **kwargs):
        """ Abstraction of requests so we can properly decorate it in one place """
        
        ret = None

        # Determine which auth method to use
        if self.useAPIToken:
            headers = { "X-API-Key": self.token}
        else:
            headers = { "Authorization": f"Bearer {self.token}" }

        if rtype == "post":
            ret = requests.post(
                f"{self.root_url}/api/{api_endpoint}",
                headers = headers,
                verify = self.verify,
                **kwargs
            )
        elif rtype == "get":
            ret = requests.get(f"{self.root_url}/api/{api_endpoint}", headers = headers, verify=self.verify, **kwargs)
        else:
            raise Exception("invalid request type")

        return ret


    def create_admin(self, admin_username: str, admin_password: str):
        """Initialize admin user, set new users username and password."""
        
        self.ansible_module.log(f"Changing password for admin user '{admin_username}'")

        body = {
            "password": admin_password,
            "username": admin_username
        }

        try:
            response = requests.post(
                f"{self.root_url}/api/users/admin/init",
                json=body,
                verify=self.verify
            )

            response.raise_for_status()

            self.ansible_module.log("Success: admin password changed")

        except requests.exceptions.RequestException as e:
            # Custom exception
            e.args = (f"ERROR (create_admin): Admin init failed for user '{admin_username}'. Exception: {e}",)
            self.ansible_module.log(msg=f"{e}")
            raise


    def check_admin_exists(self) -> bool:
        """Check if admin user already initialized, return True if it is."""

        self.ansible_module.log(f"Checking if admin already initialized...")

        try:

            response = self._request("get", f"users/admin/check")
            if response.status_code == 204:
                self.ansible_module.warn(f"Portainer already initialized, skipping 'initial_setup'...")
                return True
            else:
                return False

        except Exception as e:
            e.args = (f"ERROR (check_admin_exists): Check if admin exists failed. Exception: {e}",)
            self.ansible_module.log(f"{e}")
            raise


    def create_endpoint(self, endpoint_name: str):
        """Create new endpoint"""

        self.ansible_module.log(f"Creating endpoint {endpoint_name}")

        form_data = {
            "Name": f"{endpoint_name}",
            "EndpointCreationType": 1
        }

        try:
            response = self._request("post", f"endpoints", data=form_data)

            response.raise_for_status()

            self.ansible_module.log(f"Success: endpoint '{endpoint_name}' created")

        except requests.exceptions.RequestException as e:
            # Custom exception
            e.args = (f"ERROR (create_endpoint): failed to create endpoint '{endpoint_name}'. Exception: {e}",)
            self.ansible_module.log(msg=f"{e}")
            raise


    def create_session(self, admin_username: str, admin_password: str) -> str:
        """Logs in with provided credentials, returns session token."""

        # If we are using an API token, don't try to login and start a new
        # session
        if self.useAPIToken:
            return

        self.ansible_module.log(f"Trying to login to {self.root_url} as {admin_username}")

        body = {
            "password": admin_password,
            "username": admin_username
        }

        try:
            response = self._request("post", f"auth", data=body)
            response.raise_for_status()
            self.ansible_module.log(f"SUCCESS: Logged in as {admin_username} - token received.")

            self.token = response.json()['jwt']

        except requests.exceptions.RequestException as e:
            e.args = (f"ERROR (create_session): Failed to authenticate as '{admin_username}', token not obtained. Exception: {e}",)
            self.ansible_module.log(f"{e}")
            raise


    def get_all_stacks(self) -> list:
        """Get all stacks, return list of stack names."""
        
        self.ansible_module.log(f"Getting all stacks")
       
        try:
            response = self._request("get", f"stacks")
            response.raise_for_status()
            stacks = [stack['Name'] for stack in response.json()]
            self.ansible_module.log(f"Received {len(stacks)} stacks")
            
            return stacks

        except requests.exceptions.RequestException as e:
            e.args = (f"ERROR (get_all_stacks): Getting stacks failed. Exception {e}",)
            self.ansible_module.log(f"{e}")
            raise


    def _get_all_endpoints(self) -> list:

        self.ansible_module.log(f"Getting endpoints")

        try:
            response = self._request("get", f"endpoints")

            response.raise_for_status()
            endpoints = response.json()
            self.ansible_module.log(f"Received {len(endpoints)} endpoints")

            return endpoints

        except requests.exceptions.RequestException as e:
            e.args = (f"ERROR (_get_all_endpoints): Getting endpoints failed. Exception {e}",)
            self.ansible_module.log(f"{e}")
            raise

    
    def get_endpoint_id(self, endpoint_name: str) -> int:
        
        endpoints = self._get_all_endpoints()

        if len(endpoints) == 0:
            raise Exception("0 endpoints found.")

        for endpoint in endpoints:
            if endpoint["Name"] == endpoint_name:
                return int(endpoint["Id"])
        else:
            error_msg = f"ERROR (get_endpoint_id): Endpoint '{endpoint_name}' not found"
            self.ansible_module.log(error_msg)
            raise Exception(error_msg)


    def create_stack(self, stack_name: str, docker_compose_file: str, endpoint_id: int) -> bool:

        self.ansible_module.log(f"Creating stack - {stack_name}")

        form_data = {
            "Name": stack_name,
        }

        compose_file = {'file': open(docker_compose_file, 'rb')}

        params = {
            "type": 2,
            "method": "file",
            "endpointId": endpoint_id
        }

        try:
            response = self._request("post",
                f"stacks/create/standalone/file",
                data=form_data,
                files=compose_file,
                params=params)

            response.raise_for_status()
            self.ansible_module.log(f"SUCCESS: {stack_name} stack created")
            return True

        except requests.exceptions.RequestException as e:
            e.args = (f"ERROR (create_stack): '{stack_name}' failed to create. Exception: {e}",)
            self.ansible_module.log(f"{e}")
            return False


def main():

    # ------- Getting params from playbook ------- #

    module_args = dict(
        root_url=dict(type='str', required=True),
        initial_setup=dict(type='bool', required=False),
        admin_username=dict(type='str', required=False),
        admin_password=dict(type='str', required=False, no_log=True),
        api_key=dict(type='str', required=False, no_log=True),
        verify=dict(type='bool', required=False),
        endpoint=dict(type='str', required=True),
        stacks=dict(
            type='list',
            elements='dict',
            required=True, 
            options=dict(
            name=dict(type='str', required=True),
            compose_file=dict(type='str', required=True)
        ))
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    root_url_param = module.params['root_url']
    initial_setup_param = module.params['initial_setup']
    api_key_param = module.params['api_key']
    verify_param = module.params['verify']
    admin_username_param = module.params['admin_username']
    admin_password_param = module.params['admin_password']
    endpoint_param = module.params['endpoint']
    stacks_param = module.params['stacks']

    if not stacks_param:
        module.fail_json(msg="No stacks provided in playbook")
    
    # -------------------------------------------- #

    portainer = PortainerAPI(module, root_url_param, verify_param, api_key_param)

    try:
        portainer.ping()

        admin_exists = portainer.check_admin_exists()

        if not portainer.useAPIToken:
            if initial_setup_param and not admin_exists:
                portainer.create_admin(admin_username_param, admin_password_param)
                portainer.create_session(admin_username_param, admin_password_param)
                portainer.create_endpoint(endpoint_param)
            else:
                portainer.create_session(admin_username_param, admin_password_param)

        endpoint_id = portainer.get_endpoint_id(endpoint_param)
        existing_stacks = portainer.get_all_stacks()
        created_stacks=[]

        for stack in stacks_param:
            stack_name = stack['name']
            stack_compose_file = stack['compose_file']

            if stack_name.lower() in existing_stacks:
                module.warn(f"Stack '{stack_name}' already exists, skipping...")
                continue
            
            stack_created = portainer.create_stack(stack_name, stack_compose_file, endpoint_id)
            created_stacks.append(stack_created)
    
    except Exception as e:
        module.fail_json(changed=False, msg=f"{e}")
        return

    changed_status = True if created_stacks.count(True) > 0 else False
    message_status = f"{len(created_stacks)} stacks created"

    module.exit_json(
        changed=changed_status, 
        msg=message_status, 
        stacks_deployed=f"{created_stacks.count(True)}",
        stacks_failed_to_deploy=f"{created_stacks.count(False)}")

if __name__ == '__main__':
    main()
