"""
Datadog Provider is a class that allows to ingest/digest data from Datadog.
"""

import dataclasses
import datetime
import json
import logging
import os
import re
import time
from collections import defaultdict
from dataclasses import asdict
from typing import List, Literal, Optional

import pydantic
import requests

from keep.api.models.alert import AlertDto, AlertSeverity, AlertStatus
from keep.api.models.db.topology import TopologyServiceInDto
from keep.contextmanager.contextmanager import ContextManager
from keep.providers.base.base_provider import BaseTopologyProvider, ProviderHealthMixin
from keep.providers.base.provider_exceptions import GetAlertException
from keep.providers.datadog_provider.datadog_alert_format_description import (
    DatadogAlertFormatDescription,
)
from keep.providers.models.provider_config import ProviderConfig, ProviderScope
from keep.providers.models.provider_method import ProviderMethod
from keep.providers.providers_factory import ProvidersFactory
from keep.validation.fields import HttpsUrl


logger = logging.getLogger(__name__)


@pydantic.dataclasses.dataclass
class WhitecloudProviderAuthConfig:
    """
    Whitecloud authentication configuration.
    """
    token_endpoint: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Keystone API endpoint URL",
        }
    )
    
    username: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "keystone admin username",
        }
    )

    password: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "keystone admin password",
            "sensitive": True,
        }
    )


class WhitecloudProvider(BaseTopologyProvider, ProviderHealthMixin):
   
    PROVIDER_DISPLAY_NAME = "Whitecloud"
    PROVIDER_CATEGORY = ["Monitoring"]
    PROVIDER_TAGS = ["data"]
    PROVIDER_SCOPES = []

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)

    def validate_config(self):
        self.authentication_config = WhitecloudProviderAuthConfig(
            **self.config.authentication
        )

    def dispose(self):
        """
        Cleanup any resources when provider is disposed.
        
        This is an abstract method that MUST be implemented, even if it just passes.
        """
        pass

    def _query(self, query="", timeframe="", query_type="", **kwargs: dict):
       pass
   
    def get_auth_token(self):
        body = {
            "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                "user": {
                    "domain": { "name": "Default" },
                    "name": "admin",
                    "password": self.authentication_config.password
                }
                }
            },
            "scope": {
                "project": {
                "domain": { "name": "Default" },
                "name": self.authentication_config.username
                }
            }
            }
        }
        response = requests.post(url=f"{self.authentication_config.token_endpoint}/v3/auth/tokens", json=body)
        self.logger.info(f"Request to endpoint {self.authentication_config.token_endpoint} : {response}")
        token = response.headers.get('x-subject-token', '')
        return token

    def _openstack_api_get(self, url):
        auth_token = self.get_auth_token()
        self.logger.info(f"Auth token {auth_token}")
        response = requests.get(url, headers={"X-Auth-Token":auth_token})
        if not response:
            raise Exception(f"Error in request to URL: {url}, with TOKEN {auth_token}: {response}")
        return response.json()

    def _get_vms(self):
        self.logger.info(f"Querying servers from openstack")
        response = self._openstack_api_get("http://10.100.3.7:8774/v2.1/servers/detail")
        vms = response.get('servers', [])
        self.logger.info(f"Servers {vms}")
        return vms

    def _get_hypervisors(self):
        self.logger.info(f"Querying Hypervisors from openstack")
        response = self._openstack_api_get("http://10.100.3.7:8774/v2.1/os-hypervisors")
        vms = response.get('hypervisors', [])
        self.logger.info(f"Hypervisors {vms}")
        return vms

    def _get_vm_ports(self):
        self.logger.info(f"Querying Ports from openstack")
        response = self._openstack_api_get("http://10.100.3.7:9696/v2.0/ports?device_owner=compute:nova")
        ports = response.get('ports', [])
        self.logger.info(f"Ports {ports}")

        return ports

    def _build_server_dependencies(self, server, raw_services):
        
        networks = server.get('addresses', {})
        server_dependencies = {}

        for ip_group in networks.values():
            for port_data in ip_group:
                if 'addr' in port_data:
                    ip = port_data.get('addr')
                    if not ip:
                        continue
                    raw_port = raw_services.get(ip)
                    if not raw_port or 'id' not in raw_port:
                        continue
                    server_dependencies[raw_port['id']] = 'connected_to'

        hypervisor_name = server.get('OS-EXT-SRV-ATTR:hypervisor_hostname')
        hypervisor_dep = raw_services.get(hypervisor_name, {}).get('hypervisor_hostname')

        server_dependencies[hypervisor_dep] = 'runs_on'
        return server_dependencies

    def pull_topology(self) -> tuple[list[TopologyServiceInDto], dict]:

        services = {}
        servers = self._get_vms()
        hypervisors = self._get_hypervisors()
        ports = self._get_vm_ports()

        for hypervisor in hypervisors:
            service = TopologyServiceInDto(
                    source_provider_id=self.provider_id,
                    display_name=f"Hostname: {hypervisor['hypervisor_hostname']} ; Status {hypervisor['status']}",
                    service=hypervisor['hypervisor_hostname'],
                    environment='environment',
                )
            services[hypervisor['hypervisor_hostname']] = service

        for port in ports:
            service = TopologyServiceInDto(
                    source_provider_id=self.provider_id,
                    display_name=f"Port: {port['name']} ; Status {port['status']}",
                    service=port['id'],
                    environment='environment',
                )
            services[port['id']] = service

        servers_dependencies = { h['hypervisor_hostname']: h for h in hypervisors} | \
                                {p['fixed_ips'][0]['ip_address']: p for p in ports} 


        for server in servers:
            deps = self._build_server_dependencies(server, servers_dependencies)
            service = TopologyServiceInDto(
                    source_provider_id=self.provider_id,
                    display_name=server['name'],
                    service=f"instance_name: {server['name']} ; instance_id {server['id']}",
                    environment='environment',
                    dependencies=deps
                )

            services[server['name']] = service

        return list(services.values()), {}
