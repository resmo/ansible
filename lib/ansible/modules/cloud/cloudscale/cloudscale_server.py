#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2017, Gaudenz Steinlin <gaudenz.steinlin@cloudscale.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: cloudscale_server
short_description: Manages servers on the cloudscale.ch IaaS service
description:
  - Create, start, stop and delete servers on the cloudscale.ch IaaS service.
  - All operations are performed using the cloudscale.ch public API v1.
  - "For details consult the full API documentation: U(https://www.cloudscale.ch/en/api/v1)."
  - A valid API token is required for all operations. You can create as many tokens as you like using the cloudscale.ch control panel at
    U(https://control.cloudscale.ch).
notes:
  - Instead of the api_token parameter the CLOUDSCALE_API_TOKEN environment variable can be used.
  - To create a new server at least the C(name), C(ssh_key), C(image) and C(flavor) options are required.
  - If more than one server with the name given by the C(name) option exists, execution is aborted.
  - Once a server is created all parameters except C(state) are read-only. You can't change the name, flavor or any other property. This is a limitation
    of the cloudscale.ch API. The module will silently ignore differences between the configured parameters and the running server if a server with the
    correct name or UUID exists. Only state changes will be applied.
version_added: 2.3
author: "Gaudenz Steinlin (@gaudenz) <gaudenz.steinlin@cloudscale.ch>"
options:
  state:
    description:
      - State of the server
    default: running
    choices: [ running, stopped, absent ]
  name:
    description:
      - Name of the Server.
      - Either C(name) or C(uuid) are required. These options are mutually exclusive.
  uuid:
    description:
      - UUID of the server.
      - Either C(name) or C(uuid) are required. These options are mutually exclusive.
  flavor:
    description:
      - Flavor of the server.
  image:
    description:
      - Image used to create the server.
  volume_size_gb:
    description:
      - Size of the root volume in GB.
    default: 10
  bulk_volume_size_gb:
    description:
      - Size of the bulk storage volume in GB.
      - No bulk storage volume if not set.
  ssh_keys:
    description:
       - List of SSH public keys.
       - Use the full content of your .pub file here.
  use_public_network:
    description:
      - Attach a public network interface to the server.
    default: True
    type: bool
  use_private_network:
    description:
      - Attach a private network interface to the server.
    default: False
    type: bool
  use_ipv6:
    description:
      - Enable IPv6 on the public network interface.
    default: True
    type: bool
  anti_affinity_with:
    description:
      - UUID of another server to create an anti-affinity group with.
  user_data:
    description:
      - Cloud-init configuration (cloud-config) data to use for the server.
  api_token:
    description:
      - cloudscale.ch API token.
      - This can also be passed in the CLOUDSCALE_API_TOKEN environment variable.
  api_timeout:
    description:
      - Timeout in seconds for calls to the cloudscale.ch API.
    default: 30
    version_added: "2.5"
'''

EXAMPLES = '''
# Start a server (if it does not exist) and register the server details

- name: Start cloudscale.ch server
  cloudscale_server:
    name: my-shiny-cloudscale-server
    image: debian-8
    flavor: flex-4
    ssh_keys: ssh-rsa XXXXXXXXXX...XXXX ansible@cloudscale
    use_private_network: True
    bulk_volume_size_gb: 100
    api_token: xxxxxx
  register: server1

# Start another server in anti-affinity to the first one
- name: Start second cloudscale.ch server
  cloudscale_server:
    name: my-other-shiny-server
    image: ubuntu-16.04
    flavor: flex-8
    ssh_keys: ssh-rsa XXXXXXXXXXX ansible@cloudscale
    anti_affinity_with: '{{ server1.uuid }}'
    api_token: xxxxxx

# Stop the first server
- name: Stop my first server
  cloudscale_server:
    uuid: '{{ server1.uuid }}'
    state: stopped
    api_token: xxxxxx

# Delete my second server
- name: Delete my second server
  cloudscale_server:
    name: my-other-shiny-server
    state: absent
    api_token: xxxxxx

# Start a server and wait for the SSH host keys to be generated
- name: Start server and wait for SSH host keys
  cloudscale_server:
    name: my-cloudscale-server-with-ssh-key
    image: debian-8
    flavor: flex-4
    ssh_keys: ssh-rsa XXXXXXXXXXX ansible@cloudscale
    api_token: xxxxxx
  register: server
  until: server.ssh_fingerprints
  retries: 60
  delay: 2
'''

RETURN = '''
href:
  description: API URL to get details about this server
  returned: success when not state == absent
  type: str
  sample: https://api.cloudscale.ch/v1/servers/cfde831a-4e87-4a75-960f-89b0148aa2cc
uuid:
  description: The unique identifier for this server
  returned: success
  type: str
  sample: cfde831a-4e87-4a75-960f-89b0148aa2cc
name:
  description: The display name of the server
  returned: success
  type: str
  sample: its-a-me-mario.cloudscale.ch
state:
  description: The current status of the server
  returned: success
  type: str
  sample: running
flavor:
  description: The flavor that has been used for this server
  returned: success when not state == absent
  type: str
  sample: flex-8
image:
  description: The image used for booting this server
  returned: success when not state == absent
  type: str
  sample: debian-8
volumes:
  description: List of volumes attached to the server
  returned: success when not state == absent
  type: list
  sample: [ {"type": "ssd", "device": "/dev/vda", "size_gb": "50"} ]
interfaces:
  description: List of network ports attached to the server
  returned: success when not state == absent
  type: list
  sample: [ { "type": "public", "addresses": [ ... ] } ]
ssh_fingerprints:
  description: A list of SSH host key fingerprints. Will be null until the host keys could be retrieved from the server.
  returned: success when not state == absent
  type: list
  sample: ["ecdsa-sha2-nistp256 SHA256:XXXX", ... ]
ssh_host_keys:
  description: A list of SSH host keys. Will be null until the host keys could be retrieved from the server.
  returned: success when not state == absent
  type: list
  sample: ["ecdsa-sha2-nistp256 XXXXX", ... ]
anti_affinity_with:
  description: List of servers in the same anti-affinity group
  returned: success when not state == absent
  type: str
  sample: []
'''

from datetime import datetime, timedelta
from time import sleep

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.cloudscale import AnsibleCloudscaleBase, cloudscale_argument_spec

ALLOWED_STATES = ('running',
                  'stopped',
                  'absent',
                  )


class AnsibleCloudscaleServer(AnsibleCloudscaleBase):

    def __init__(self, module):
        super(AnsibleCloudscaleServer, self).__init__(module)

        self.result = {
            'changed': False,
            'diff': dict(before=dict(), after=dict())
        }

        # Server container
        self.info = None

        self.returns = {
            'href': dict(),
            'state': dict(key='status'),
            'uuid': dict(),
            'name': dict(),
            'flavor': dict(),
            'image': dict(),
            'volumes': dict(),
            'interfaces': dict(),
            'ssh_fingerprints': dict(),
            'ssh_host_keys': dict(),
            'anti_affinity_with': dict(),
        }

    def get_server_info(self, refresh=False):
        if self.info is not None and not refresh:
            return self.info

        self.info = {}
        uuid = self._module.params.get('uuid') or self.info.get('uuid')
        if uuid is not None:
            server = self._get('servers/%s' % uuid)
            if server:
                self.info = server
        else:
            name = self._module.params.get('name')
            if name is not None:
                servers = self._get('servers') or []
                matching_server = []
                for s in servers:
                    if s['name'] == name:
                        matching_server.append(s)
                else:
                    if len(matching_server) == 1:
                        self.info = matching_server[0]
                    elif len(matching_server) > 1:
                        self._module.fail_json(msg="More than one server with name '%s' exists. "
                                               "Use the 'uuid' parameter to identify the server." % name)

        return self.info

    def wait_for_state(self, states):
        start = datetime.now()
        timeout = self._module.params['api_timeout'] * 2
        while datetime.now() - start < timedelta(seconds=timeout):
            server_info = self.get_server_info()

            if server_info.get('status') in states:
                return server_info
            sleep(1)

        if server_info:
            msg = "Timeout while waiting for a state change on server %s to states %s."
            "Current state is %s." % (server_info('name'), states, server_info.get('status'))
        else:
            name_uuid = self._module.params.get('name') or self._module.params.get('uuid')
            msg = 'Timeout while waiting to find the server %s' % name_uuid

        self._module.fail_json(msg=msg)

    def _create_server(self):
        self.result['changed'] = True
        server_info = {}

        params = self._module.params

        # check for required parameters to create a server
        missing_parameters = []
        for p in ('name', 'ssh_keys', 'image', 'flavor'):
            if p not in params or not params[p]:
                missing_parameters.append(p)

        if len(missing_parameters) > 0:
            self._module.fail_json(msg='Missing required parameter(s) to create a new server: %s.' %
                                   ' '.join(missing_parameters))

       data = {
        'name': params['name'],
       }

        if not self._module.check_mode():
            self._post('servers', data)
            server_info = self.wait_for_state(('running', ))
        return server_info


    def _update_server(self):


        return server_info

    def absent_server(self):
        server_info = self.get_server_info()
        if not server_info:
            self.result['changed'] = True
            if not self._module.check_mode():
                self._delete('servers/%s' % server_info['uuid'])
                self.wait_for_state(('absent', ))
        # Return last queried infos
        return server_info

    def start_server(self):
        server_info = self.get_server_info()
        if server_info and server_info.get('status') != "running":
            self.result['changed'] = True
            self._post('servers/%s/start' % server_info['uuid'])
            server_info = self.wait_for_state(('running', ))
        return server_info

    def stop_server(self):
        server_info = self.get_server_info()
        if server_info and server_info.get('status') != "stopped":
            self._post('servers/%s/stop' % server_info['uuid'])
            server_info = self.wait_for_state(('stopped', ))
        return server_info


def main():
    argument_spec = cloudscale_argument_spec()
    argument_spec.update(dict(
        state=dict(default='running', choices=ALLOWED_STATES),
        name=dict(),
        uuid=dict(),
        flavor=dict(),
        image=dict(),
        volume_size_gb=dict(type='int', default=10),
        bulk_volume_size_gb=dict(type='int'),
        ssh_keys=dict(type='list'),
        use_public_network=dict(type='bool', default=True),
        use_private_network=dict(type='bool', default=False),
        use_ipv6=dict(type='bool', default=True),
        anti_affinity_with=dict(),
        user_data=dict(),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=(('name', 'uuid'),),
        mutually_exclusive=(('name', 'uuid'),),
        supports_check_mode=True,
    )

    state = module.params['state']
    cloudscale_server = AnsibleCloudscaleServer(module)


    returns = server.get_returns()
    module.exit_json(**returns)


if __name__ == '__main__':
    main()
