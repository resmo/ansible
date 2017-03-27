#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2015, René Moser <mail@renemoser.net>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible. If not, see <http://www.gnu.org/licenses/>.

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['stableinterface'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: cs_instance
short_description: Manages instances and virtual machines on Apache CloudStack based clouds.
description:
    - Deploy, start, update, scale, restart, restore, stop and destroy instances.
version_added: '2.0'
author: "René Moser (@resmo)"
options:
  name:
    description:
      - Host name of the instance. C(name) can only contain ASCII letters.
      - Name will be generated (UUID) by CloudStack if not specified and can not be changed afterwards.
      - Either C(name) or C(display_name) is required.
    required: false
    default: null
  display_name:
    description:
      - Custom display name of the instances.
      - Display name will be set to C(name) if not specified.
      - Either C(name) or C(display_name) is required.
    required: false
    default: null
  group:
    description:
      - Group in where the new instance should be in.
    required: false
    default: null
  state:
    description:
      - State of the instance.
    required: false
    default: 'present'
    choices: [ 'deployed', 'started', 'stopped', 'restarted', 'restored', 'destroyed', 'expunged', 'present', 'absent' ]
  service_offering:
    description:
      - Name or id of the service offering of the new instance.
      - If not set, first found service offering is used.
    required: false
    default: null
  cpu:
    description:
      - The number of CPUs to allocate to the instance, used with custom service offerings
    required: false
    default: null
  cpu_speed:
    description:
      - The clock speed/shares allocated to the instance, used with custom service offerings
    required: false
    default: null
  memory:
    description:
      - The memory allocated to the instance, used with custom service offerings
    required: false
    default: null
  template:
    description:
      - Name or id of the template to be used for creating the new instance.
      - Required when using C(state=present).
      - Mutually exclusive with C(ISO) option.
    required: false
    default: null
  iso:
    description:
      - Name or id of the ISO to be used for creating the new instance.
      - Required when using C(state=present).
      - Mutually exclusive with C(template) option.
    required: false
    default: null
  template_filter:
    description:
      - Name of the filter used to search for the template or iso.
      - Used for params C(iso) or C(template) on C(state=present).
    required: false
    default: 'executable'
    choices: [ 'featured', 'self', 'selfexecutable', 'sharedexecutable', 'executable', 'community' ]
    aliases: [ 'iso_filter' ]
    version_added: '2.1'
  hypervisor:
    description:
      - Name the hypervisor to be used for creating the new instance.
      - Relevant when using C(state=present), but only considered if not set on ISO/template.
      - If not set or found on ISO/template, first found hypervisor will be used.
    required: false
    default: null
    choices: [ 'KVM', 'VMware', 'BareMetal', 'XenServer', 'LXC', 'HyperV', 'UCS', 'OVM' ]
  keyboard:
    description:
      - Keyboard device type for the instance.
    required: false
    default: null
    choices: [ 'de', 'de-ch', 'es', 'fi', 'fr', 'fr-be', 'fr-ch', 'is', 'it', 'jp', 'nl-be', 'no', 'pt', 'uk', 'us' ]
  networks:
    description:
      - List of networks to use for the new instance.
    required: false
    default: []
    aliases: [ 'network' ]
  ip_address:
    description:
      - IPv4 address for default instance's network during creation.
    required: false
    default: null
  ip6_address:
    description:
      - IPv6 address for default instance's network.
    required: false
    default: null
  ip_to_networks:
    description:
      - "List of mappings in the form {'network': NetworkName, 'ip': 1.2.3.4}"
      - Mutually exclusive with C(networks) option.
    required: false
    default: null
    aliases: [ 'ip_to_network' ]
  disk_offering:
    description:
      - Name of the disk offering to be used.
    required: false
    default: null
  disk_size:
    description:
      - Disk size in GByte required if deploying instance from ISO.
    required: false
    default: null
  root_disk_size:
    description:
      - Root disk size in GByte.
      - Required if deploying instance with KVM hypervisor and want resize the root disk size at startup.
      - Needs CloudStack >= 4.4, cloud-initramfs-growroot installed and enabled in the template.
    required: false
    default: null
  security_groups:
    description:
      - List of security groups the instance to be applied to.
    required: false
    default: null
    aliases: [ 'security_group' ]
  domain:
    description:
      - Domain the instance is related to.
    required: false
    default: null
  account:
    description:
      - Account the instance is related to.
    required: false
    default: null
  project:
    description:
      - Name of the project the instance to be deployed in.
    required: false
    default: null
  zone:
    description:
      - Name of the zone in which the instance should be deployed.
      - If not set, default zone is used.
    required: false
    default: null
  ssh_key:
    description:
      - Name of the SSH key to be deployed on the new instance.
    required: false
    default: null
  affinity_groups:
    description:
      - Affinity groups names to be applied to the new instance.
    required: false
    default: []
    aliases: [ 'affinity_group' ]
  user_data:
    description:
      - Optional data (ASCII) that can be sent to the instance upon a successful deployment.
      - The data will be automatically base64 encoded.
      - Consider switching to HTTP_POST by using C(CLOUDSTACK_METHOD=post) to increase the HTTP_GET size limit of 2KB to 32 KB.
    required: false
    default: null
  force:
    description:
      - Force stop/start the instance if required to apply changes, otherwise a running instance will not be changed.
    required: false
    default: false
  tags:
    description:
      - List of tags. Tags are a list of dictionaries having keys C(key) and C(value).
      - "If you want to delete all tags, set a empty list e.g. C(tags: [])."
    required: false
    default: null
    aliases: [ 'tag' ]
  poll_async:
    description:
      - Poll async jobs until job has finished.
    required: false
    default: true
extends_documentation_fragment: cloudstack
'''

EXAMPLES = '''
# Create a instance from an ISO
# NOTE: Names of offerings and ISOs depending on the CloudStack configuration.
- cs_instance:
    name: web-vm-1
    iso: Linux Debian 7 64-bit
    hypervisor: VMware
    project: Integration
    zone: ch-zrh-ix-01
    service_offering: 1cpu_1gb
    disk_offering: PerfPlus Storage
    disk_size: 20
    networks:
      - Server Integration
      - Sync Integration
      - Storage Integration
  delegate_to: localhost

# For changing a running instance, use the 'force' parameter
- cs_instance:
    name: web-vm-1
    display_name: web-vm-01.example.com
    iso: Linux Debian 7 64-bit
    service_offering: 2cpu_2gb
    force: yes
  delegate_to: localhost

# Create or update a instance on Exoscale's public cloud using display_name.
# Note: user_data can be used to kickstart the instance using cloud-init yaml config.
- cs_instance:
    display_name: web-vm-1
    template: Linux Debian 7 64-bit
    service_offering: Tiny
    ssh_key: john@example.com
    tags:
      - key: admin
        value: john
      - key: foo
        value: bar
    user_data: |
        #cloud-config
        packages:
          - nginx
  delegate_to: localhost

# Create an instance with multiple interfaces specifying the IP addresses
- cs_instance:
    name: web-vm-1
    template: Linux Debian 7 64-bit
    service_offering: Tiny
    network:
      - name: Network A
        ip: 10.1.1.1
      - Network B
  delegate_to: localhost

# Create an instance with multiple interfaces including VPC networks
- cs_instance:
    name: web-vm-1
    template: Linux Debian 7 64-bit
    service_offering: Tiny
    network:
      - name: Network A
        ip: 10.1.1.1
        vpc: my vpc
      - name: Network B
        vpc: my other vpc
      - name: Network C
        ip: 192.0.3.1
  delegate_to: localhost

# Ensure an instance is stopped
- cs_instance:
    name: web-vm-1
    state: stopped
  delegate_to: localhost

# Ensure an instance is running
- cs_instance:
    name: web-vm-1
    state: started
  delegate_to: localhost

# Remove an instance
- cs_instance:
    name: web-vm-1
    state: absent
  delegate_to: localhost
'''

RETURN = '''
---
id:
  description: UUID of the instance.
  returned: success
  type: string
  sample: 04589590-ac63-4ffc-93f5-b698b8ac38b6
name:
  description: Name of the instance.
  returned: success
  type: string
  sample: web-01
display_name:
  description: Display name of the instance.
  returned: success
  type: string
  sample: web-01
group:
  description: Group name of the instance is related.
  returned: success
  type: string
  sample: web
created:
  description: Date of the instance was created.
  returned: success
  type: string
  sample: 2014-12-01T14:57:57+0100
password_enabled:
  description: True if password setting is enabled.
  returned: success
  type: boolean
  sample: true
password:
  description: The password of the instance if exists.
  returned: success
  type: string
  sample: Ge2oe7Do
ssh_key:
  description: Name of SSH key deployed to instance.
  returned: success
  type: string
  sample: key@work
domain:
  description: Domain the instance is related to.
  returned: success
  type: string
  sample: example domain
account:
  description: Account the instance is related to.
  returned: success
  type: string
  sample: example account
project:
  description: Name of project the instance is related to.
  returned: success
  type: string
  sample: Production
default_ip:
  description: Default IP address of the instance.
  returned: success
  type: string
  sample: 10.23.37.42
public_ip:
  description: Public IP address with instance via static NAT rule.
  returned: success
  type: string
  sample: 1.2.3.4
iso:
  description: Name of ISO the instance was deployed with.
  returned: success
  type: string
  sample: Debian-8-64bit
template:
  description: Name of template the instance was deployed with.
  returned: success
  type: string
  sample: Debian-8-64bit
service_offering:
  description: Name of the service offering the instance has.
  returned: success
  type: string
  sample: 2cpu_2gb
zone:
  description: Name of zone the instance is in.
  returned: success
  type: string
  sample: ch-gva-2
state:
  description: State of the instance.
  returned: success
  type: string
  sample: Running
security_groups:
  description: Security groups the instance is in.
  returned: success
  type: list
  sample: '[ "default" ]'
affinity_groups:
  description: Affinity groups the instance is in.
  returned: success
  type: list
  sample: '[ "webservers" ]'
tags:
  description: List of resource tags associated with the instance.
  returned: success
  type: dict
  sample: '[ { "key": "foo", "value": "bar" } ]'
hypervisor:
  description: Hypervisor related to this instance.
  returned: success
  type: string
  sample: KVM
instance_name:
  description: Internal name of the instance (ROOT admin only).
  returned: success
  type: string
  sample: i-44-3992-VM
'''

import base64
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.cloudstack import (
    AnsibleCloudStack,
    CloudStackException,
    cs_argument_spec,
    cs_required_together,
    CS_HYPERVISORS,
    CS_TEMPLATE_FILTERS,
)


class AnsibleCloudStackInstance(AnsibleCloudStack):

    def __init__(self, module):
        super(AnsibleCloudStackInstance, self).__init__(module)
        self.returns = {
            'group': 'group',
            'hypervisor': 'hypervisor',
            'instancename': 'instance_name',
            'publicip': 'public_ip',
            'passwordenabled': 'password_enabled',
            'password': 'password',
            'serviceofferingname': 'service_offering',
            'isoname': 'iso',
            'templatename': 'template',
            'keypair': 'ssh_key',
            'nic': 'nic'
        }
        self.instance = None
        self.template = None
        self.iso = None
        self.vpcs = None

    def get_service_offering_id(self):
        service_offering = self.module.params.get('service_offering')

        service_offerings = self.cs.listServiceOfferings()
        if service_offerings:
            if not service_offering:
                return service_offerings['serviceoffering'][0]['id']

            for s in service_offerings['serviceoffering']:
                if service_offering in [s['name'], s['id']]:
                    return s['id']
        self.module.fail_json(msg="Service offering '%s' not found" % service_offering)

    def get_template_or_iso(self, key=None):
        template = self.module.params.get('template')
        iso = self.module.params.get('iso')

        if not template and not iso:
            return None

        args = {
            'account': self.get_account(key='name'),
            'domainid': self.get_domain(key='id'),
            'projectid': self.get_project(key='id'),
            'zoneid': self.get_zone(key='id'),
            'isrecursive': True,
        }

        if template:
            if self.template:
                return self._get_by_key(key, self.template)

            rootdisksize = self.module.params.get('root_disk_size')
            args['templatefilter'] = self.module.params.get('template_filter')
            templates = self.cs.listTemplates(**args)
            if templates:
                for t in templates['template']:
                    if template in [t['displaytext'], t['name'], t['id']]:
                        if rootdisksize and t['size'] > rootdisksize * 1024 ** 3:
                            continue
                        self.template = t
                        return self._get_by_key(key, self.template)
            more_info = ""
            if rootdisksize:
                more_info = " (with size <= %s)" % rootdisksize
            self.module.fail_json(msg="Template '%s' not found%s" % (template, more_info))

        elif iso:
            if self.iso:
                return self._get_by_key(key, self.iso)
            args['isofilter'] = self.module.params.get('template_filter')
            isos = self.cs.listIsos(**args)
            if isos:
                for i in isos['iso']:
                    if iso in [i['displaytext'], i['name'], i['id']]:
                        self.iso = i
                        return self._get_by_key(key, self.iso)
            self.module.fail_json(msg="ISO '%s' not found" % iso)

    def get_disk_offering_id(self):
        disk_offering = self.module.params.get('disk_offering')

        if not disk_offering:
            return None

        disk_offerings = self.cs.listDiskOfferings()
        if disk_offerings:
            for d in disk_offerings['diskoffering']:
                if disk_offering in [d['displaytext'], d['name'], d['id']]:
                    return d['id']
        self.module.fail_json(msg="Disk offering '%s' not found" % disk_offering)

    def get_instance(self):
        instance = self.instance
        if not instance:
            instance_name = self.get_or_fallback('name', 'display_name')
            args = {
                'account': self.get_account(key='name'),
                'domainid': self.get_domain(key='id'),
                'projectid': self.get_project(key='id'),
            }
            # Do not pass zoneid, as the instance name must be unique across zones.
            instances = self.cs.listVirtualMachines(**args)
            if instances:
                for v in instances['virtualmachine']:
                    if instance_name.lower() in [v['name'].lower(), v['displayname'].lower(), v['id']]:
                        self.instance = v
                        break
        return self.instance

    def _get_instance_user_data(self, instance):
        # Query the user data if we need to
        if 'userdata' in instance:
            return instance['userdata']

        user_data = ""
        if self.get_user_data() is not None:
            res = self.cs.getVirtualMachineUserData(virtualmachineid=instance['id'])
            user_data = res['virtualmachineuserdata'].get('userdata', "")
        return user_data

    def ssh_key_has_changed(self):
        ssh_key_name = self.module.params.get('ssh_key')
        if ssh_key_name is None:
            return False

        instance_ssh_key_name = self.instance.get('keypair')
        if instance_ssh_key_name is None:
            return True

        if ssh_key_name == instance_ssh_key_name:
            return False

        args = {
            'domainid': self.get_domain('id'),
            'account': self.get_account('name'),
            'projectid': self.get_project('id')
        }

        args['name'] = instance_ssh_key_name
        res = self.cs.listSSHKeyPairs(**args)
        instance_ssh_key = res['sshkeypair'][0]

        args['name'] = ssh_key_name
        res = self.cs.listSSHKeyPairs(**args)
        param_ssh_key = res['sshkeypair'][0]
        if param_ssh_key['fingerprint'] != instance_ssh_key['fingerprint']:
            return True
        return False

    def update_instance_nics(self, instance):
        networks = self.module.params.get('networks')
        if networks is None:
            return instance

        network_list = self.get_ip_to_networklist()

        remove_nics = []
        add_nics = []

        index = 0
        for nic in instance.get('nic') or []:
            if len(network_list) >= (index + 1):
                if nic['networkid'] != network_list[index]['networkid']:
                    remove_nics.append(nic)
                    add_nics.append(network_list[index])
                del network_list[index]
            else:
                remove_nics.append(nic)
            index += 1

        for network in network_list:
            add_nics.append(network)

        if add_nics or remove_nics:
            self.result['changed'] = True

        if not self.module.check_mode:
            for nic in remove_nics:
                args = {
                    'nicid': nic['id'],
                    'virtualmachineid': instance['id']
                }
                res = self.cs.removeNicFromVirtualMachine(**args)
                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % instance['errortext'])

                poll_async = self.module.params.get('poll_async')
                if poll_async:
                    instance = self.poll_job(res, 'virtualmachine')

            for network in add_nics:
                args = {
                    'networkid': network['networkid'],
                    'virtualmachineid': instance['id']
                }
                if 'ip' in network:
                    args['ipaddress'] = network['ip']
                res = self.cs.addNicToVirtualMachine(**args)
                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % instance['errortext'])

                poll_async = self.module.params.get('poll_async')
                if poll_async:
                    instance = self.poll_job(res, 'virtualmachine')
        return instance

    def security_groups_has_changed(self):
        security_groups = self.module.params.get('security_groups')
        if security_groups is None:
            return False

        security_groups = [s.lower() for s in security_groups]
        instance_security_groups = self.instance.get('securitygroup') or []

        instance_security_group_names = []
        for instance_security_group in instance_security_groups:
            if instance_security_group['name'].lower() not in security_groups:
                return True
            else:
                instance_security_group_names.append(instance_security_group['name'].lower())

        for security_group in security_groups:
            if security_group not in instance_security_group_names:
                return True
        return False

    def get_ip_to_networklist(self):
        network_list = self.module.params.get('networks')
        if network_list is None:
            return None

        args = {
            'account': self.get_account(key='name'),
            'domainid': self.get_domain(key='id'),
            'projectid': self.get_project(key='id'),
            'zoneid': self.get_zone(key='id'),
        }
        networks = self.cs.listNetworks(**args)
        if not networks:
            self.module.fail_json(msg="No networks available")

        network_results = []
        for n in networks['network']:
            # iterate over a copy of the network list
            for network in list(network_list):
                if isinstance(network, dict):
                    if 'name' not in network:
                        self.module.fail_json(msg="Missing name key in network argument: %s" % network)
                    # Skip networks not matching name a or ID
                    if network['name'] not in [n['id'], n['name'], n['displaytext']]:
                        continue
                    # Skip networks related to VPC when ours we ours is not a VPC network
                    if 'vcp' not in network and n.get('vpcid'):
                        continue
                    elif 'vcp' in network:
                        # Skip non-VPC networks when we are looking for a VPC one
                        if not n.get('vpcid'):
                            continue
                        # Skip non-matching VPC networks
                        elif n.get('vpcid') != self.get_vpc(key='id', id=network['vpc']):
                            continue
                    # We have found a matching network
                    network_results.append({
                        'networkid': n['id'],
                        'ip': network.get('ip')
                    })
                    # Remove the network from the origin list so we can later verify that all networks have been found.
                    network_list.remove(network)
                else:
                    # Backwards (before 2.4) compatible fallback for non dict networks
                    if network in [n['id'], n['name'], n['displaytext']]:
                        network_results.append({
                            'networkid': n['id'],
                        })
                        network_list.remove(network)

            # We have found all networks
            if not network_list:
                return network_results

        self.module.fail_json(msg="Network(s) not found: %s" % network_list)

    def get_vpc(self, key=None, id=None):
        if not self.vpcs:
            args = {
                'account': self.get_account(key='name'),
                'domainid': self.get_domain(key='id'),
                'projectid': self.get_project(key='id'),
                'zoneid': self.get_zone(key='id'),
            }
            vpcs = self.cs.listVPCs(**args)
            if not vpcs:
                self.module.fail_json(msg="No VPCs available.")
            self.vpcs = vpcs['vpc']

        vpc_match = None
        for v in self.vpcs:
            if id in [v['name'], v['displaytext'], v['id']]:
                if vpc_match is not None:
                    self.module.fail_json(msg="More than one VPC found with the provided identifyer '%s'" % id)
                else:
                    vpc_match = v
        if vpc_match:
            return self._get_by_key(key, vpc_match)
        self.module.fail_json(msg="VPC '%s' not found" % id)

    def present_instance(self, start_vm=True):
        instance = self.get_instance()

        if not instance:
            instance = self.deploy_instance(start_vm=start_vm)
        else:
            instance = self.recover_instance(instance=instance)
            instance = self.update_instance(instance=instance, start_vm=start_vm)
            instance = self.update_instance_nics(instance=instance)

        # In check mode, we do not necessarily have an instance
        if instance:
            instance = self.ensure_tags(resource=instance, resource_type='UserVm')
            # refresh instance data
            self.instance = instance

        return instance

    def get_user_data(self):
        user_data = self.module.params.get('user_data')
        if user_data is not None:
            user_data = base64.b64encode(str(user_data))
        return user_data

    def get_details(self):
        res = None
        cpu = self.module.params.get('cpu')
        cpu_speed = self.module.params.get('cpu_speed')
        memory = self.module.params.get('memory')
        if all([cpu, cpu_speed, memory]):
            res = [{
                'cpuNumber': cpu,
                'cpuSpeed': cpu_speed,
                'memory': memory,
            }]
        return res

    def deploy_instance(self, start_vm=True):
        self.result['changed'] = True

        args = {}
        args['templateid'] = self.get_template_or_iso(key='id')
        if not args['templateid']:
            self.module.fail_json(msg="Template or ISO is required.")

        args['zoneid'] = self.get_zone(key='id')
        args['serviceofferingid'] = self.get_service_offering_id()
        args['account'] = self.get_account(key='name')
        args['domainid'] = self.get_domain(key='id')
        args['projectid'] = self.get_project(key='id')
        args['diskofferingid'] = self.get_disk_offering_id()
        args['iptonetworklist'] = self.get_ip_to_networklist()
        args['userdata'] = self.get_user_data()
        args['keyboard'] = self.module.params.get('keyboard')
        args['ipaddress'] = self.module.params.get('ip_address')
        args['ip6address'] = self.module.params.get('ip6_address')
        args['name'] = self.module.params.get('name')
        args['displayname'] = self.get_or_fallback('display_name', 'name')
        args['group'] = self.module.params.get('group')
        args['keypair'] = self.module.params.get('ssh_key')
        args['size'] = self.module.params.get('disk_size')
        args['startvm'] = start_vm
        args['rootdisksize'] = self.module.params.get('root_disk_size')
        args['affinitygroupnames'] = ','.join(self.module.params.get('affinity_groups') or [])
        args['securitygroupnames'] = ','.join(self.module.params.get('security_groups') or [])
        args['details'] = self.get_details()

        template_iso = self.get_template_or_iso()
        if 'hypervisor' not in template_iso:
            args['hypervisor'] = self.get_hypervisor()

        instance = None
        if not self.module.check_mode:
            instance = self.cs.deployVirtualMachine(**args)

            if 'errortext' in instance:
                self.module.fail_json(msg="Failed: '%s'" % instance['errortext'])

            poll_async = self.module.params.get('poll_async')
            if poll_async:
                instance = self.poll_job(instance, 'virtualmachine')
        return instance

    def update_instance(self, instance, start_vm=True):
        # Service offering data
        args_service_offering = {}
        args_service_offering['id'] = instance['id']
        if self.module.params.get('service_offering'):
            args_service_offering['serviceofferingid'] = self.get_service_offering_id()
        service_offering_changed = self.has_changed(args_service_offering, instance)

        # Instance data
        args_instance_update = {}
        args_instance_update['id'] = instance['id']
        args_instance_update['userdata'] = self.get_user_data()
        instance['userdata'] = self._get_instance_user_data(instance)
        args_instance_update['ostypeid'] = self.get_os_type(key='id')
        if self.module.params.get('group'):
            args_instance_update['group'] = self.module.params.get('group')
        if self.module.params.get('display_name'):
            args_instance_update['displayname'] = self.module.params.get('display_name')
        instance_changed = self.has_changed(args_instance_update, instance)

        ssh_key_changed = self.ssh_key_has_changed()

        security_groups_changed = self.security_groups_has_changed()

        changed = [
            service_offering_changed,
            instance_changed,
            security_groups_changed,
            ssh_key_changed,
        ]

        if any(changed):
            force = self.module.params.get('force')
            instance_state = instance['state'].lower()
            if instance_state == 'stopped' or force:
                self.result['changed'] = True
                if not self.module.check_mode:

                    # Ensure VM has stopped
                    instance = self.stop_instance()
                    instance = self.poll_job(instance, 'virtualmachine')
                    self.instance = instance

                    # Change service offering
                    if service_offering_changed:
                        res = self.cs.changeServiceForVirtualMachine(**args_service_offering)
                        if 'errortext' in res:
                            self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
                        instance = res['virtualmachine']
                        self.instance = instance

                    # Update VM
                    if instance_changed or security_groups_changed:
                        if security_groups_changed:
                            args_instance_update['securitygroupnames'] = ','.join(self.module.params.get('security_groups'))
                        res = self.cs.updateVirtualMachine(**args_instance_update)
                        if 'errortext' in res:
                            self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
                        instance = res['virtualmachine']
                        self.instance = instance

                    # Reset SSH key
                    if ssh_key_changed:
                        # SSH key data
                        args_ssh_key = {}
                        args_ssh_key['id'] = instance['id']
                        args_ssh_key['projectid'] = self.get_project(key='id')
                        args_ssh_key['keypair'] = self.module.params.get('ssh_key')
                        instance = self.cs.resetSSHKeyForVirtualMachine(**args_ssh_key)
                        if 'errortext' in instance:
                            self.module.fail_json(msg="Failed: '%s'" % instance['errortext'])

                        instance = self.poll_job(instance, 'virtualmachine')
                        self.instance = instance

                    # Start VM again if it was running before
                    if instance_state == 'running' and start_vm:
                        instance = self.start_instance()
        return instance

    def recover_instance(self, instance):
        if instance['state'].lower() in ['destroying', 'destroyed']:
            self.result['changed'] = True
            if not self.module.check_mode:
                res = self.cs.recoverVirtualMachine(id=instance['id'])
                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
                instance = res['virtualmachine']
        return instance

    def absent_instance(self):
        instance = self.get_instance()
        if instance:
            if instance['state'].lower() not in ['expunging', 'destroying', 'destroyed']:
                self.result['changed'] = True
                if not self.module.check_mode:
                    res = self.cs.destroyVirtualMachine(id=instance['id'])

                    if 'errortext' in res:
                        self.module.fail_json(msg="Failed: '%s'" % res['errortext'])

                    poll_async = self.module.params.get('poll_async')
                    if poll_async:
                        instance = self.poll_job(res, 'virtualmachine')
        return instance

    def expunge_instance(self):
        instance = self.get_instance()
        if instance:
            res = {}
            if instance['state'].lower() in ['destroying', 'destroyed']:
                self.result['changed'] = True
                if not self.module.check_mode:
                    res = self.cs.destroyVirtualMachine(id=instance['id'], expunge=True)

            elif instance['state'].lower() not in ['expunging']:
                self.result['changed'] = True
                if not self.module.check_mode:
                    res = self.cs.destroyVirtualMachine(id=instance['id'], expunge=True)

            if res and 'errortext' in res:
                self.module.fail_json(msg="Failed: '%s'" % res['errortext'])

            poll_async = self.module.params.get('poll_async')
            if poll_async:
                res = self.poll_job(res, 'virtualmachine')
        return instance

    def stop_instance(self):
        instance = self.get_instance()
        # in check mode intance may not be instanciated
        if instance:
            if instance['state'].lower() in ['stopping', 'stopped']:
                return instance

            if instance['state'].lower() in ['starting', 'running']:
                self.result['changed'] = True
                if not self.module.check_mode:
                    instance = self.cs.stopVirtualMachine(id=instance['id'])

                    if 'errortext' in instance:
                        self.module.fail_json(msg="Failed: '%s'" % instance['errortext'])

                    poll_async = self.module.params.get('poll_async')
                    if poll_async:
                        instance = self.poll_job(instance, 'virtualmachine')
        return instance

    def start_instance(self):
        instance = self.get_instance()
        # in check mode intance may not be instanciated
        if instance:
            if instance['state'].lower() in ['starting', 'running']:
                return instance

            if instance['state'].lower() in ['stopped', 'stopping']:
                self.result['changed'] = True
                if not self.module.check_mode:
                    instance = self.cs.startVirtualMachine(id=instance['id'])

                    if 'errortext' in instance:
                        self.module.fail_json(msg="Failed: '%s'" % instance['errortext'])

                    poll_async = self.module.params.get('poll_async')
                    if poll_async:
                        instance = self.poll_job(instance, 'virtualmachine')
        return instance

    def restart_instance(self):
        instance = self.get_instance()
        # in check mode intance may not be instanciated
        if instance:
            if instance['state'].lower() in ['running', 'starting']:
                self.result['changed'] = True
                if not self.module.check_mode:
                    instance = self.cs.rebootVirtualMachine(id=instance['id'])

                    if 'errortext' in instance:
                        self.module.fail_json(msg="Failed: '%s'" % instance['errortext'])

                    poll_async = self.module.params.get('poll_async')
                    if poll_async:
                        instance = self.poll_job(instance, 'virtualmachine')

            elif instance['state'].lower() in ['stopping', 'stopped']:
                instance = self.start_instance()
        return instance

    def restore_instance(self):
        instance = self.get_instance()
        self.result['changed'] = True
        # in check mode intance may not be instanciated
        if instance:
            args = {}
            args['templateid'] = self.get_template_or_iso(key='id')
            args['virtualmachineid'] = instance['id']
            res = self.cs.restoreVirtualMachine(**args)
            if 'errortext' in res:
                self.module.fail_json(msg="Failed: '%s'" % res['errortext'])

            poll_async = self.module.params.get('poll_async')
            if poll_async:
                instance = self.poll_job(res, 'virtualmachine')
        return instance

    def get_result(self, instance):
        super(AnsibleCloudStackInstance, self).get_result(instance)
        if instance:
            self.result['user_data'] = self._get_instance_user_data(instance)
            if 'securitygroup' in instance:
                security_groups = []
                for securitygroup in instance['securitygroup']:
                    security_groups.append(securitygroup['name'])
                self.result['security_groups'] = security_groups
            if 'affinitygroup' in instance:
                affinity_groups = []
                for affinitygroup in instance['affinitygroup']:
                    affinity_groups.append(affinitygroup['name'])
                self.result['affinity_groups'] = affinity_groups
            if 'nic' in instance:
                for nic in instance['nic']:
                    if nic['isdefault'] and 'ipaddress' in nic:
                        self.result['default_ip'] = nic['ipaddress']
        return self.result


def main():
    argument_spec = cs_argument_spec()
    argument_spec.update(dict(
        name=dict(),
        display_name=dict(),
        group=dict(),
        state=dict(choices=['present', 'deployed', 'started', 'stopped', 'restarted', 'restored', 'absent', 'destroyed', 'expunged'], default='present'),
        service_offering=dict(),
        cpu=dict(type='int'),
        cpu_speed=dict(type='int'),
        memory=dict(type='int'),
        template=dict(),
        iso=dict(),
        template_filter=dict(default="executable", aliases=['iso_filter'], choices=CS_TEMPLATE_FILTERS),
        networks=dict(type='list', aliases=['network']),
        ip_to_networks=dict(type='list', aliases=['ip_to_network'], removed_in_version="2.7"),
        ip_address=dict(defaul=None),
        ip6_address=dict(defaul=None),
        disk_offering=dict(),
        disk_size=dict(type='int'),
        root_disk_size=dict(type='int'),
        keyboard=dict(choices=['de', 'de-ch', 'es', 'fi', 'fr', 'fr-be', 'fr-ch', 'is', 'it', 'jp', 'nl-be', 'no', 'pt', 'uk', 'us']),
        hypervisor=dict(choices=CS_HYPERVISORS),
        security_groups=dict(type='list', aliases=['security_group']),
        affinity_groups=dict(type='list', aliases=['affinity_group'], default=[]),
        domain=dict(),
        account=dict(),
        project=dict(),
        user_data=dict(),
        zone=dict(),
        ssh_key=dict(),
        force=dict(type='bool', default=False),
        tags=dict(type='list', aliases=['tag']),
        poll_async=dict(type='bool', default=True),
    ))

    required_together = cs_required_together()
    required_together.extend([
        ['cpu', 'cpu_speed', 'memory'],
    ])

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_together=required_together,
        required_one_of=(
            ['display_name', 'name'],
        ),
        mutually_exclusive=(
            ['template', 'iso'],
        ),
        supports_check_mode=True
    )

    try:
        acs_instance = AnsibleCloudStackInstance(module)

        state = module.params.get('state')

        if state in ['absent', 'destroyed']:
            instance = acs_instance.absent_instance()

        elif state in ['expunged']:
            instance = acs_instance.expunge_instance()

        elif state in ['restored']:
            acs_instance.present_instance()
            instance = acs_instance.restore_instance()

        elif state in ['present', 'deployed']:
            instance = acs_instance.present_instance()

        elif state in ['stopped']:
            acs_instance.present_instance(start_vm=False)
            instance = acs_instance.stop_instance()

        elif state in ['started']:
            acs_instance.present_instance()
            instance = acs_instance.start_instance()

        elif state in ['restarted']:
            acs_instance.present_instance()
            instance = acs_instance.restart_instance()

        if instance and 'state' in instance and instance['state'].lower() == 'error':
            module.fail_json(msg="Instance named '%s' in error state." % module.params.get('name'))

        result = acs_instance.get_result(instance)

    except CloudStackException as e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)


if __name__ == '__main__':
    main()
