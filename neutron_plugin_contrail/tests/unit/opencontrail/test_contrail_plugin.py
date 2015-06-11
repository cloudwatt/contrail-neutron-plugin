# Copyright 2014 Juniper Networks.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import datetime
import json
import uuid

import mock
import netaddr
try:
    from oslo_config import cfg
except ImportError:
    from oslo.config import cfg
from testtools import matchers
import webob.exc

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base as api_base
from neutron.common import exceptions as exc
from neutron import context as neutron_context
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import l3_db
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_db
from neutron.extensions import portbindings
from neutron.extensions import securitygroup as ext_sg
from neutron.tests.unit import _test_extension_portbindings as test_bindings

try:
    from neutron.tests.unit import test_db_plugin as test_plugin
except ImportError:
    from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin

try:
    from neutron.tests.unit import test_extension_security_group as test_sg
except ImportError:
    from neutron.tests.unit.extensions import test_securitygroup as test_sg

try:
    from neutron.tests.unit import test_extensions
except ImportError:
    from neutron.tests.unit.api import test_extensions

try:
    from neutron.tests.unit import test_l3_plugin
except ImportError:
    from neutron.tests.unit.extensions import test_l3 as test_l3_plugin


from vnc_api import vnc_api
from neutron_plugin_contrail.tests.unit.opencontrail.vnc_mock import MockVnc
from neutron_plugin_contrail.plugins.opencontrail.vnc_client import contrail_res_handler


CONTRAIL_PKG_PATH = "neutron_plugin_contrail.plugins.opencontrail.contrail_plugin_v3"


class Context(object):
    def __init__(self, tenant_id=''):
        self.read_only = False
        self.show_deleted = False
        self.roles = [u'admin', u'KeystoneServiceAdmin', u'KeystoneAdmin']
        self._read_deleted = 'no'
        self.timestamp = datetime.datetime.now()
        self.auth_token = None
        self._session = None
        self._is_admin = True
        self.admin = uuid.uuid4().hex.decode()
        self.request_id = 'req-' + str(uuid.uuid4())
        self.tenant = tenant_id


class KeyStoneInfo(object):
    """To generate Keystone Authentication information
       Contrail Driver expects Keystone auth info for testing purpose.
    """
    auth_protocol = 'http'
    auth_host = 'host'
    auth_port = 5000
    admin_user = 'neutron'
    auth_url = "http://localhost:5000/"
    auth_type = ""
    admin_password = 'neutron'
    admin_token = 'neutron'
    admin_tenant_name = 'neutron'


class JVContrailPluginTestCase(test_plugin.NeutronDbPluginV2TestCase):
    _plugin_name = ('%s.NeutronPluginContrailCoreV3' % CONTRAIL_PKG_PATH)

    def setUp(self, plugin=None, ext_mgr=None):

        cfg.CONF.keystone_authtoken = KeyStoneInfo()
        from neutron_plugin_contrail import extensions
        cfg.CONF.api_extensions_path = "extensions:" + extensions.__path__[0]
        contrail_res_handler.ContrailResourceHandler._project_id_vnc_to_neutron = lambda x, y: y
        contrail_res_handler.ContrailResourceHandler._project_id_neutron_to_vnc = lambda x, y: y
        vnc_api.VncApi = MockVnc
        self.domain_obj = vnc_api.Domain()
        MockVnc().domain_create(self.domain_obj)

        super(JVContrailPluginTestCase, self).setUp(self._plugin_name)

    def tearDown(self):
        MockVnc.resources_collection = dict()
        MockVnc._kv_dict = dict()
        super(JVContrailPluginTestCase, self).tearDown()


class TestContrailNetworksV2(test_plugin.TestNetworksV2,
                             JVContrailPluginTestCase):
    def setUp(self):
        super(TestContrailNetworksV2, self).setUp()

    def test_create_network_default_mtu(self):
        self.skipTest("Contrail doesn't support this feature yet")

    def test_create_network_vlan_transparent(self):
        self.skipTest("Contrail doesn't support this feature yet")


class TestContrailSubnetsV2(test_plugin.TestSubnetsV2,
                            JVContrailPluginTestCase):
    def setUp(self):
        super(TestContrailSubnetsV2, self).setUp()

    def test_create_2_subnets_overlapping_cidr_not_allowed_returns_400(self):
        self.skipTest("TODO: Not supported yet")

    def test_create_subnet_bad_tenant(self):
        self.skipTest("TODO: Investigate, why this fails in neutron itself")

    def test_create_subnet_ipv6_addr_modes(self):
        self.skipTest("TODO: Investigate what needs to be done")

    def test_create_subnet_ipv6_same_ra_and_addr_modes(self):
        self.skipTest("TODO: Investigate what needs to be done")

    def test_delete_subnet_port_exists_owned_by_other(self):
        self.skipTest("TODO: Very tough to mock this in vnc_mock")

    def test_port_prevents_subnet_deletion(self):
        self.skipTest("TODO: Very tough to mock this in vnc_mock")

    def test_delete_subnet_ipv6_slaac_router_port_exists(self):
        self.skipTest("TODO: Very tough to mock this in vnc_mock")

    def test_delete_subnet_ipv6_slaac_port_exists(self):
        self.skipTest("TODO: Very tough to mock this in vnc_mock")

    def test_create_subnet_ipv6_different_ra_and_addr_modes(self):
        self.skipTest("TODO: Investigate what needs to be done")

    def test_create_subnet_ipv6_ra_modes(self):
        self.skipTest("TODO: Investigate what needs to be done")

    def test_update_subnet(self):
        self.skipTest("Contrail does not support updating gateway ip")

    def test_update_subnet_no_gateway(self):
        self.skipTest("Contrail does not support updating gateway ip")

    def test_update_subnet_route_with_too_many_entries(self):
        self.skipTest("TODO: Investigate - contrail support mutliple host routes")

    def test_update_subnet_gw_ip_in_use_returns_409(self):
        self.skipTest("Contrail does not support updating gateway ip")

    def test_update_subnet_gateway_in_allocation_pool_returns_409(self):
        self.skipTest("Contrail does not support updating allocation pools")

    def test_update_subnet_allocation_pools(self):
        self.skipTest("Contrail does not support updating allocation pools")

    def test_update_subnet_dns_with_too_many_entries(self):
        self.skipTest("TODO: Check why this should fail")

    # Support ipv6 in contrail is planned in Juno
    def test_create_subnet_ipv6_ra_mode_ip_version_4(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_create_subnet_with_v6_allocation_pool(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_create_subnet_ipv6_gw_values(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_cannot_disable_dhcp(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_create_subnet_ipv6_attributes_no_dhcp_enabled(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_attributes(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_create_subnet_ipv6_out_of_cidr_lla(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_inconsistent_address_attribute(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_inconsistent_enable_dhcp(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_create_subnet_inconsistent_ipv6_dns_v4(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_inconsistent_ra_attribute(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_delete_subnet_dhcp_port_associated_with_other_subnets(self):
        self.skipTest("There is no dhcp port in contrail")


class TestContrailPortsV2(test_plugin.TestPortsV2,
                          JVContrailPluginTestCase):
    def setUp(self):
        super(TestContrailPortsV2, self).setUp()

    def test_delete_ports_by_device_id(self):
        self.skipTest("This method tests rpc API of "
                      "which contrail isn't using")

    def test_delete_ports_by_device_id_second_call_failure(self):
        self.skipTest("This method tests rpc API of "
                      "which contrail isn't using")

    def test_delete_ports_ignores_port_not_found(self):
        self.skipTest("This method tests private method of "
                      "which contrail isn't using")


class TestContrailSecurityGroups(test_sg.TestSecurityGroups,
                                 JVContrailPluginTestCase):
    def setUp(self, plugin=None, ext_mgr=None):
        super(TestContrailSecurityGroups, self).setUp(self._plugin_name,
                                                      ext_mgr)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def test_create_security_group_rule_duplicate_rule_in_post_emulated(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_security_group_rule_duplicate_rule_db_emulated(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_security_group_rule_duplicate_rules(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_security_group_rule_invalid_ethertype_for_prefix(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_security_group_rule_invalid_ip_prefix(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_security_group_source_group_ip_and_ip_prefix(self):
        self.skipTest("Investigation needed")

class TestContrailPortBinding(JVContrailPluginTestCase,
                              test_bindings.PortBindingsTestCase):
    from neutron_plugin_contrail.plugins.opencontrail.contrail_plugin import NeutronPluginContrailCoreV2
    VIF_TYPE = portbindings.VIF_TYPE_VROUTER
    HAS_PORT_FILTER = True

    def setUp(self):
        super(TestContrailPortBinding, self).setUp()


class TestContrailL3NatTestCase(JVContrailPluginTestCase,
                                test_l3_plugin.L3NatDBIntTestCase):
    mock_rescheduling = False

    def setUp(self):
        super(TestContrailL3NatTestCase, self).setUp()
