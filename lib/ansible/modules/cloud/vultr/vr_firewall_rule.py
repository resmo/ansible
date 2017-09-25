#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2017, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: vr_firewall_rule
short_description: Manages firewall rules on Vultr.
description:
  - Create and remove firewall rules.
version_added: "2.5"
author: "René Moser (@resmo)"
options:
  group:
    description:
      - Name of the firewall group.
    required: true
  ip_version:
    description:
      - IP address version
    choices: [ v4, v6 ]
    default: v4
    aliases: [ ip_type ]
  protocol:
    description:
      - Protocol of the firewall rule.
    choices: [ icmp, tcp, udp, gre ]
    default: tcp
  cidr:
    description:
      - Network in CIDR format
      - The CIDR format must match with the C(ip_type) value.
      - Required if C(state=present).
  start_port:
    description:
      - Start port for the firewall rule.
      - Required if C(protocol) is tcp or udp.
    aliases: [ port ]
  end_port:
    description:
      - End port for the firewall rule.
      - Only considered if C(protocol) is tcp or udp.
  state:
    description:
      - State of the firewall rule.
    default: present
    choices: [ present, absent ]
extends_documentation_fragment: vultr
'''

EXAMPLES = '''
- name: ensure a firewall rule is present
  local_action:
    module: vr_firewall_rule
    group: application
    protocol: tcp
    start_port: 8000
    end_port: 9000
    cidr: 17.17.17.0/24

- name: open DNS port
  local_action:
    module: vr_firewall_rule
    group: dns
    protocol: udp
    port: 53

- name: allow ping
  local_action:
    module: vr_firewall_rule
    group: web
    protocol: icmp

- name: ensure a firewall rule is absent
  local_action:
    module: vr_firewall_rule
    group: application
    protocol: tcp
    start_port: 8000
    end_port: 9000
    cidr: 17.17.17.0/24
    state: absent
'''

RETURN = '''
---
vultr_api:
  description: Response from Vultr API with a few additions/modification
  returned: success
  type: complex
  contains:
    api_account:
      description: Account used in the ini file to select the key
      returned: success
      type: string
      sample: default
    api_timeout:
      description: Timeout used for the API requests
      returned: success
      type: int
      sample: 60
vultr_firewall_rule:
  description: Response from Vultr API
  returned: success
  type: complex
  contains:
    id:
      description: ID of the firewall rule
      returned: success
      type: string
      sample: 1234abcd
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vultr import (
    Vultr,
    vultr_argument_spec,
)


class AnsibleVultrFirewallRule(Vultr):

    def __init__(self, module):
        super(AnsibleVultrFirewallRule, self).__init__(module, "vultr_firewall_rule")

        self.returns = {
            'rulenumber': dict(key='rule_number'),
            'action': dict(),
            'protocol': dict(),
        }
        self.firewall_group = None

    def get_firewall_group(self):
        if self.firewall_group is not None:
            return self.firewall_group

        firewall_groups = self.api_query(path="/v1/firewall/group_list")
        if firewall_groups:
            for firewall_group_id, firewall_group_data in firewall_groups.items():
                if firewall_group_data.get('description') == self.module.params.get('group'):
                    self.firewall_group = firewall_group_data
                    return self.firewall_group
        self.fail_json(msg="Firewall group not found: %s" % self.module.params.get('group'))

    def _transform_cidr(self):
        cidr = self.module.params.get('cidr')
        ip_version = self.module.params.get('ip_version')
        if cidr is None:
            if ip_version == "v6":
                cidr == "::/0"
            else:
                cidr == "0.0.0.0/0"
        elif cidr.count('/') != 1:
                self.fail_json(msg="CIDR seems invalid: %s" % cidr)

        return cidr.split('/')



    def get_firewall_rule(self):
        ip_version = self.module.params.get('ip_version')
        firewall_group = self.get_firewall_group()

        firewall_rules = self.api_query(
            path="/v1/firewall/rule_list"
                 "?FIREWALLGROUPID=%s"
                 "&direction=in"
                 "&ip_type=%s"
                 % (firewall_group, ip_version))

        if firewall_rules:
            subnet, subnet_size = self._transform_cidr()

            for firewall_rule_id, firewall_rule_data in firewall_rules.items():
                if firewall_rule_data.get('protocol') != self.module.params.get('protocol'):
                    continue

                if ip_version == 'v4' and (firewall_rule_data.get('subnet') or "0.0.0.0") != subnet:
                    continue

                if ip_version == 'v6' and (firewall_rule_data.get('subnet') or "::/0") != subnet:
                    continue

                if firewall_rule_data.get('subnet_size') != subnet_size:
                    continue

                if firewall_rule_data.get('protocol') in ['tcp', 'udp']:
                    # Port range "8000 - 8080" from the API
                    if '-' in firewall_rule_data.get('port'):
                        port_range = "%s - %s" % (self.module.params.get('start_port'), self.module.params.get('start_port'))
                        if firewall_rule_data.get('port') == port_range:
                            return firewall_rule_data
                    # Single port
                    elif int(firewall_rule_data.get('port')) == self.module.params.get('start_port'):
                        return firewall_rule_data
                else:
                    return firewall_rule_data
        return {}

    def present_firewall_rule(self):
        firewall_rule = self.get_firewall_rule()
        if not firewall_rule:
            firewall_rule = self._create_firewall_rule(firewall_rule)
        return firewall_rule

    def _create_firewall_rule(self, firewall_rule):
        self.result['changed'] = True
        data = {
            'FIREWALLGROUPID': self.get_firewall_group()['FIREWALLGROUPID'],
            'direction': 'in',
            'ip_type': self.module.params.get('ip_version'),
            'protocol': self.module.params.get('protocol'),
            'subnet': self.module.params.get('subnet'),
        }
        self.result['diff']['before'] = {}
        self.result['diff']['after'] = data

        if not self.module.check_mode:
            self.api_query(
                path="/v1/firewall/rule_create",
                method="POST",
                data=data
            )
            firewall_rule = self.get_firewall_rule()
        return firewall_rule

    def absent_firewall_rule(self):
        firewall_rule = self.get_firewall_rule()
        if firewall_rule:
            self.result['changed'] = True

            data = {
                'FIREWALLGROUPID': firewall_rule['FIREWALLGROUPID'],
                'rulenumber': firewall_rule['rulenumber']
            }

            self.result['diff']['before'] = firewall_rule
            self.result['diff']['after'] = {}

            if not self.module.check_mode:
                self.api_query(
                    path="/v1/firewall/rule_delete",
                    method="POST",
                    data=data
                )
        return firewall_rule


def main():
    argument_spec = vultr_argument_spec()
    argument_spec.update(dict(
        group=dict(required=True),
        start_port=dict(type='int', aliases=['port']),
        end_port=dict(type='int'),
        protocol=dict(choices=['tcp', 'upd', 'gre', 'icmp']),
        cidr=dict(default='0.0.0.0/0'),
        ip_version=dict(choices=['ipv4', 'ipv6'], default='ipv4'),
        state=dict(choices=['present', 'absent'], default='present'),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    vr_firewall_rule = AnsibleVultrFirewallRule(module)
    if module.params.get('state') == "absent":
        firewall_rule = vr_firewall_rule.absent_firewall_rule()
    else:
        firewall_rule = vr_firewall_rule.present_firewall_rule()

    result = vr_firewall_rule.get_result(firewall_rule)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
