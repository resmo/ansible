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
author: "Gaudenz Steinlin (@gaudenz)"
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
    type: int
  bulk_volume_size_gb:
    description:
      - Size of the bulk storage volume in GB.
      - No bulk storage volume if not set.
    type: int
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
    type: int
    version_added: "2.5"
  force:
    description:
      - Allow to stop the server for changing the flavor if necessary.
    default: no
    type: bool
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

# Force to update the flavor of a running server
- name: Start cloudscale.ch server
  cloudscale_server:
    name: my-shiny-cloudscale-server
    image: debian-8
    flavor: flex-8
    force: yes
    ssh_keys: ssh-rsa XXXXXXXXXX...XXXX ansible@cloudscale
    use_private_network: True
    bulk_volume_size_gb: 100
    api_token: xxxxxx
  register: server1

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
  until: server.ssh_fingerprints is defined
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
from copy import deepcopy

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.cloudscale import AnsibleCloudscaleBase, cloudscale_argument_spec

ALLOWED_STATES = ('running',
                  'stopped',
                  'absent',
                  )


class AnsibleCloudscaleServer(AnsibleCloudscaleBase):

    def __init__(self, module):
        super(AnsibleCloudscaleServer, self).__init__(module)

        self._result = {
            'changed': False,
            'diff': dict(before=dict(), after=dict())
        }

        # Server container
        self._info = {}

        self._transforms = {
            'status': dict(to_key='state'),
        }

    def get_server_info(self, refresh=False):
        if self._info and not refresh:
            return self._info

        uuid = self._module.params.get('uuid') or self._info.get('uuid')
        if uuid is not None:
            server = self._get('servers/%s' % uuid)
            if server:
                self._info = server
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
                        self._info = matching_server[0]
                    elif len(matching_server) > 1:
                        self._module.fail_json(msg="More than one server with name '%s' exists. "
                                               "Use the 'uuid' parameter to identify the server." % name)

        return self._info

    def wait_for_state(self, states):
        start = datetime.now()
        timeout = self._module.params['api_timeout'] * 2
        while datetime.now() - start < timedelta(seconds=timeout):
            server_info = self.get_server_info(refresh=True)

            if server_info.get('status') in states:
                return server_info
            sleep(1)

        if server_info:
            msg = "Timeout while waiting for a state change on server %s to states %s."
            "Current state is %s." % (server_info.get('name'), states, server_info.get('status'))
        else:
            name_uuid = self._module.params.get('name') or self._module.params.get('uuid')
            msg = 'Timeout while waiting to find the server %s' % name_uuid

        self._module.fail_json(msg=msg)

    def _create_server(self):
        self._result['changed'] = True
        server_info = {}

        required_params = ('name', 'ssh_keys', 'image', 'flavor')
        self._module.fail_on_missing_params(required_params)

        params = self._module.params
        data = {
            'name': params['name'],
            'ssh_keys': params['ssh_keys'],
            'image': params['image'],
            'flavor': params['flavor'],
            'volume_size_gb': params['volume_size_gb'],
            'bulk_volume_size_gb': params['bulk_volume_size_gb'],
            'ssh_keys': params['ssh_keys'],
            'use_public_network': params['use_public_network'],
            'use_ipv6': params['use_ipv6'],
            'anti_affinity_with': params['anti_affinity_with'],
            'user_data': params['user_data'],
        }

        # Set the diff output
        self._result['diff']['before'] = {}
        self._result['diff']['after'] = deepcopy(data)
        self._result['diff']['after'].update({
             'status': 'running',
        })
        if not self._module.check_mode:
            self._post('servers', data)
            server_info = self.wait_for_state(('running', ))

        return server_info

    def _has_changed(self, server_info, data):
        # Look if and what changed
        has_changed = False
        for k, v in data.items():
            if k in server_info:
                # compare with slug field if available
                if 'slug' in server_info[k]:
                    server_v = server_info[k]['slug']
                else:
                    server_v = server_info[k]

                if server_v != v:
                    has_changed = True
                    # Set the diff output
                    self._result['diff']['before'].update({k: server_v})
                    self._result['diff']['after'].update({k: v})

        return has_changed

    def _update_server(self, server_info):
        data = {
            'name': self._module.params.get('name'),
            'flavor': self._module.params.get('flavor'),
        }

        has_changed = self._has_changed(server_info, data)
        if has_changed:
            if server_info.get('status') == "running" and not self._module.params.get('force'):
                self._module.warn("Changes won't be applied to running servers. "
                                  "Use force=yes to allow the server %s to be stopped/started." % server_info['name'])
            else:
                self._result['changed'] = True
                if not self._module.check_mode:
                    self._start_stop_server(server_info, target_state="stopped")
                    server_info = self._patch('servers/%s' % server_info['uuid'], data)

        return server_info

    def _start_stop_server(self, server_info, target_state="running"):
        actions = {
            'stopped': 'stop',
            'running': 'start',
        }
        if server_info and server_info.get('status') != target_state:
            self._result['changed'] = True

            self._result['diff']['before'].update({
                'status': server_info.get('status'),
            })
            self._result['diff']['after'].update({
                'status': target_state,
            })
            if not self._module.check_mode:
                self._post('servers/%s/%s' % (server_info['uuid'], actions[target_state]))
                server_info = self.wait_for_state((target_state, ))

        return server_info

    def present_server(self):
        server_info = self.get_server_info()

        if server_info:
            server_info = self._start_stop_server(server_info, target_state="stopped")
            server_info = self._update_server(server_info)
        else:
            server_info = self._create_server()
            server_info = self._start_stop_server(server_info, target_state="stopped")

        server_info = self._start_stop_server(server_info, target_state="running")
        return server_info

    def absent_server(self):
        server_info = self.get_server_info()
        if not server_info:
            self._result['changed'] = True
            if not self._module.check_mode:
                self._delete('servers/%s' % server_info['uuid'])
                self.wait_for_state(('absent', ))
        # Return last queried infos when VM was still present
        return server_info

    def get_returns(self, resource):
        if not resource:
            self._result.update({
                'uuid': self._module.params.get('uuid'),
                'name': self._module.params.get('name'),
                'state': 'absent',
            })
        else:
            for k, v in resource.items():
                if k in self._transforms:
                    new_key = self._transforms[k]['to_key']
                    self._result[new_key] = v
                else:
                    self._result[k] = v
        return self._result


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
        force=dict(type='bool', default=False)
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=(('name', 'uuid'),),
        supports_check_mode=True,
    )

    cloudscale_server = AnsibleCloudscaleServer(module)
    if module.params['state'] == "absent":
        server = cloudscale_server.absent_server()
    else:
        server = cloudscale_server.present_server()

    returns = cloudscale_server.get_returns(server)

    module.exit_json(**returns)


if __name__ == '__main__':
    main()
