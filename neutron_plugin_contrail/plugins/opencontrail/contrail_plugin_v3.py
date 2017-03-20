# Copyright 2015.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import time

try:
    from neutron.api.v2.attributes import ATTR_NOT_SPECIFIED
except:
    from neutron_lib.constants import ATTR_NOT_SPECIFIED
try:
    from neutron.common.exceptions import BadRequest
except ImportError:
    from neutron_lib.exceptions import BadRequest
from neutron.common.config import cfg
import requests

try:
    from neutron.openstack.common import log as logging
except ImportError:
    from oslo_log import log as logging

from eventlet import greenthread

import contrail_plugin_base as plugin_base

from vnc_api import vnc_api

from vnc_client import fip_res_handler as fip_handler
from vnc_client import ipam_res_handler as ipam_handler
from vnc_client import policy_res_handler as policy_handler
from vnc_client import route_table_res_handler as route_table_handler
from vnc_client import router_res_handler as rtr_handler
from vnc_client import sg_res_handler as sg_handler
from vnc_client import sgrule_res_handler as sgrule_handler
from vnc_client import subnet_res_handler as subnet_handler
from vnc_client import svc_instance_res_handler as svc_instance_handler
from vnc_client import virtual_router_res_handler as vrouter_handler
from vnc_client import vmi_res_handler as vmi_handler
from vnc_client import vn_res_handler as vn_handler


LOG = logging.getLogger(__name__)

vnc_extra_opts = [
    cfg.BoolOpt('apply_subnet_host_routes', default=False),
    cfg.BoolOpt('multi_tenancy', default=False)
]


class NeutronPluginContrailCoreV3(plugin_base.NeutronPluginContrailCoreBase):

    PLUGIN_URL_PREFIX = '/neutron'

    def __init__(self):
        super(NeutronPluginContrailCoreV3, self).__init__()
        cfg.CONF.register_opts(vnc_extra_opts, 'APISERVER')
        self._vnc_lib = None
        self.connected = self._connect_to_vnc_server()
        self._res_handlers = {}
        self._prepare_res_handlers()

    def _connect_to_vnc_server(self):
        admin_user = cfg.CONF.keystone_authtoken.admin_user
        admin_password = cfg.CONF.keystone_authtoken.admin_password
        admin_tenant_name = cfg.CONF.keystone_authtoken.admin_tenant_name
        api_srvr_ip = cfg.CONF.APISERVER.api_server_ip
        api_srvr_port = cfg.CONF.APISERVER.api_server_port
        try:
            auth_host = cfg.CONF.keystone_authtoken.auth_host
        except cfg.NoSuchOptError:
            auth_host = "127.0.0.1"

        try:
            auth_protocol = cfg.CONF.keystone_authtoken.auth_protocol
        except cfg.NoSuchOptError:
            auth_protocol = "http"

        try:
            auth_port = cfg.CONF.keystone_authtoken.auth_port
        except cfg.NoSuchOptError:
            auth_port = "35357"

        try:
            auth_url = cfg.CONF.keystone_authtoken.auth_url
        except cfg.NoSuchOptError:
            auth_url = "/v2.0/tokens"

        try:
            auth_type = cfg.CONF.auth_strategy
        except cfg.NoSuchOptError:
            auth_type = "keystone"

        try:
            api_server_url = cfg.CONF.APISERVER.api_server_url
        except cfg.NoSuchOptError:
            api_server_url = "/"

        # Retry till a api-server is up
        connected = False
        while not connected:
            try:
                self._vnc_lib = vnc_api.VncApi(
                    admin_user, admin_password, admin_tenant_name,
                    api_srvr_ip, api_srvr_port, api_server_url,
                    auth_host=auth_host, auth_port=auth_port,
                    auth_protocol=auth_protocol, auth_url=auth_url,
                    auth_type=auth_type)
                self._vnc_lib_member = vnc_api.VncApi(
                    admin_user, admin_password, admin_tenant_name,
                    api_srvr_ip, api_srvr_port, api_server_url,
                    auth_host=auth_host, auth_port=auth_port,
                    auth_protocol=auth_protocol, auth_url=auth_url,
                    auth_type=auth_type)
                connected = True
            except requests.exceptions.RequestException:
                time.sleep(3)
        return True

    def _set_user_infos(self, context):
        """From the request context, the auth token and user roles are
        forwarded to the API server.

        """
        if not cfg.CONF.APISERVER.multi_tenancy:
            return

        # forward user token to API server for RBAC
        # token saved earlier in the pipeline
        if hasattr(self._vnc_lib, "set_auth_token"):
            self._vnc_lib.set_auth_token(context.auth_token)
        if self.get_role_kind(context) == 'admin':
            self._vnc_lib.set_user_roles(context.roles)
        else:
            self._vnc_lib_member.set_user_roles(context.roles)

    def _prepare_res_handlers(self):
        contrail_extension_enabled = cfg.CONF.APISERVER.contrail_extensions
        apply_subnet_host_routes = cfg.CONF.APISERVER.apply_subnet_host_routes
        kwargs = {'contrail_extensions_enabled': contrail_extension_enabled,
                  'apply_subnet_host_routes': apply_subnet_host_routes}

        self._res_handlers['network'] = self.vnc_per_role(
            vn_handler.VNetworkHandler, **kwargs)
        self._res_handlers['subnet'] = self.vnc_per_role(
            subnet_handler.SubnetHandler, **kwargs)
        self._res_handlers['port'] = self.vnc_per_role(
            vmi_handler.VMInterfaceHandler, **kwargs)
        self._res_handlers['router'] = self.vnc_per_role(
            rtr_handler.LogicalRouterHandler, **kwargs)
        self._res_handlers['floatingip'] = self.vnc_per_role(
            fip_handler.FloatingIpHandler,  **kwargs)
        self._res_handlers['security_group'] = self.vnc_per_role(
            sg_handler.SecurityGroupHandler, **kwargs)
        self._res_handlers['security_group_rule'] = self.vnc_per_role(
            sgrule_handler.SecurityGroupRuleHandler, **kwargs)
        self._res_handlers['ipam'] = self.vnc_per_role(
            ipam_handler.IPamHandler, **kwargs)
        self._res_handlers['policy'] = self.vnc_per_role(
            policy_handler.PolicyHandler, **kwargs)
        self._res_handlers['route_table'] = self.vnc_per_role(
            route_table_handler.RouteTableHandler, **kwargs)
        self._res_handlers['svc'] = self.vnc_per_role(
            svc_instance_handler.SvcInstanceHandler, **kwargs)
        self._res_handlers['virtual_router'] = self.vnc_per_role(
            vrouter_handler.VirtualRouterHandler, **kwargs)

    def get_role_kind(self, context):
        if 'admin' in context.roles:
            return 'admin'
        else:
            return 'member'

    def vnc_per_role(self, handler, **kwargs):
        return {
            'admin': handler(self._vnc_lib, **kwargs),
            'member': handler(self._vnc_lib_member, **kwargs)}

    def _get_context_dict(self, context):
        return dict(context.__dict__)

    def _create_resource(self, res_type, context, res_data):
        for key, value in res_data[res_type].items():
            if value == ATTR_NOT_SPECIFIED:
                del res_data[res_type][key]

        self._set_user_infos(context)
        return self._res_handlers[res_type][self.get_role_kind(context)].resource_create(
            self._get_context_dict(context), res_data[res_type])

    def _get_resource(self, res_type, context, id, fields):
        self._set_user_infos(context)
        return self._res_handlers[res_type][self.get_role_kind(context)].resource_get(
            self._get_context_dict(context), id, fields)

    def _update_resource(self, res_type, context, id, res_data):
        self._set_user_infos(context)
        return self._res_handlers[res_type][self.get_role_kind(context)].resource_update(
            self._get_context_dict(context), id, res_data[res_type])

    def _delete_resource(self, res_type, context, id):
        self._set_user_infos(context)
        return self._res_handlers[res_type][self.get_role_kind(context)].resource_delete(
            self._get_context_dict(context), id)

    def _list_resource(self, res_type, context, filters, fields):
        self._set_user_infos(context)
        return self._res_handlers[res_type][self.get_role_kind(context)].resource_list(
            self._get_context_dict(context), filters, fields)

    def _count_resource(self, res_type, context, filters):
        self._set_user_infos(context)
        res_count = self._res_handlers[res_type][self.get_role_kind(context)].resource_count(
            self._get_context_dict(context), filters)
        return {'count': res_count}

    def add_router_interface(self, context, router_id, interface_info):
        """Add interface to a router."""

        if not interface_info:
            msg = "Either subnet_id or port_id must be specified"
            raise BadRequest(resource='router', msg=msg)

        if 'port_id' in interface_info:
            if 'subnet_id' in interface_info:
                msg = "Cannot specify both subnet-id and port-id"
                raise BadRequest(resource='router', msg=msg)

        self._set_user_infos(context)
        port_id = interface_info.get('port_id')
        subnet_id = interface_info.get('subnet_id')

        rtr_iface_handler = self.vnc_per_role(
            rtr_handler.LogicalRouterInterfaceHandler)
        return rtr_iface_handler[self.get_role_kind(context)].add_router_interface(
            self._get_context_dict(context), router_id,
            port_id=port_id, subnet_id=subnet_id)

    def remove_router_interface(self, context, router_id, interface_info):
        """Delete interface from a router."""

        if not interface_info:
            msg = "Either subnet_id or port_id must be specified"
            raise BadRequest(resource='router', msg=msg)

        port_id = interface_info.get('port_id')
        subnet_id = interface_info.get('subnet_id')

        self._set_user_infos(context)
        rtr_iface_handler = self.vnc_per_role(
            rtr_handler.LogicalRouterInterfaceHandler)
        return rtr_iface_handler[self.get_role_kind(context)].remove_router_interface(
            self._get_context_dict(context), router_id, port_id=port_id,
            subnet_id=subnet_id)
