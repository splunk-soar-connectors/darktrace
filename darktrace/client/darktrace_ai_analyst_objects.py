# File: darktrace_ai_analyst_objects.py
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List

from ..darktrace_utils import SplunkSeverity, nget


@dataclass
class AIAnalystContainer:
    name: str
    description: str
    severity: str
    source_data_identifier: str
    asset_name: str
    data: str

    def __init__(self, incident_id: str, incident_events: List[dict]):

        event = incident_events[len(incident_events) - 1]
        device_name = nget(event, "breachDevices", 0, "identifier", default="")
        ip = nget(event, "breachDevices", 0, "ip", default="")

        self.name = f"AI Analyst found incident for {device_name or ip}"
        self.description = self.name
        self.severity = SplunkSeverity.from_category(event.get("groupCategory", "")).value
        self.source_data_identifier = incident_id
        self.asset_name = "Darktrace"
        self.data = incident_events


@dataclass
class AIAnalystArtifact:
    """
    Class to represent an artifact created from an AI Analyst event
    """

    name: str
    label: str
    type: str
    start_time: str
    end_time: str
    severity: str
    source_data_identifier: str
    asset_name: str
    container_id: str
    uuid: str
    summary: str
    cef: dict

    def __init__(self, incident: Dict[str, Any], container_id: str, base_url: str):

        start_time = nget(incident, "periods", 0, "start")
        start_formatted = datetime.fromtimestamp(start_time // 1000).strftime(
            "%Y-%m-%dT%H:%M:%S.00Z"
        )
        end_time = nget(incident, "periods", 0, "end")
        end_formatted = datetime.fromtimestamp(end_time / 1000).strftime("%Y-%m-%dT%H:%M:%S.00Z")

        breach_devices = incident.get("breachDevices", [])
        current_group = incident["currentGroup"]

        self.name = incident["title"]
        self.label = "AI Analyst Incident"
        self.type = "Incident"
        self.start_time = start_formatted
        self.end_time = end_formatted
        self.severity = SplunkSeverity.from_category(incident.get("groupCategory", "")).value
        self.source_data_identifier = incident["id"]
        self.asset_name = "Darktrace"
        self.container_id = container_id
        self.uuid = incident["id"]
        self.summary = incident.get("summary", "")
        self.cef = self.get_cef(breach_devices, base_url, current_group)

    def get_cef(
        self, breach_devices: List[Dict[str, Any]], base_url: str, current_group: str
    ) -> Dict[str, Any]:
        """Get the CEF (Common Event Format) data from the model breach devices"""
        cef = dict()
        if breach_devices:
            cef["deviceId"] = nget(breach_devices, 0, "did")
            cef["deviceHostname"] = nget(breach_devices, 0, "hostname")
            cef["deviceAddress"] = nget(breach_devices, 0, "ip")
            cef["deviceLabel"] = nget(breach_devices, 0, "identifier")
        cef["incidentUrl"] = f"{base_url}/#aiagroup/{current_group}"
        return cef

    def get_breach_artifacts(self, incident: Dict[str, Any], base_url: str) -> List[Dict[str, Any]]:
        """Construct artifacts from the related breaches in an incident"""
        related_breaches = incident.get("relatedBreaches") or []
        breach_artifacts = []  # type: List[dict]
        for breach in related_breaches:
            breach_artifacts.append(self._construct_breach_artifact(breach, base_url))
        return breach_artifacts

    def _construct_breach_artifact(self, breach: Dict[str, Any], base_url: str) -> Dict[str, Any]:
        """Construct an artifact from a model breach"""

        name = breach["modelName"]  # type: str
        name_list = name.split(" / ")
        alert_type = name_list[0]
        alert_name = "/".join(name_list[1:])

        score = breach["threatScore"]  # type: int
        start_time = datetime.fromtimestamp(breach["timestamp"] / 1000)
        time_formatted = start_time.strftime("%Y-%m-%dT%H:%M:%S.00Z")
        breach_id = breach["pbid"]

        cef = dict()
        cef["modelBreachId"] = breach_id
        cef["modelBreachUrl"] = f"{base_url}/#modelbreach/{breach_id}"

        return {
            "name": alert_name,
            "type": alert_type,
            "label": "Model Breach",
            "description": "See the corresponding model breach event for more information",
            "start_time": time_formatted,
            "severity": SplunkSeverity.from_score(score).value,
            "source_data_identifier": breach_id,
            "asset_name": "Darktrace",
            "container_id": self.container_id,
            "cef": cef,
        }
