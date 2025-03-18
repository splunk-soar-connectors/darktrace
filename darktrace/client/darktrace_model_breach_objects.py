# Copyright (c) 2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# File: darktrace_model_breach_objects.py
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
from datetime import datetime, timedelta
from typing import Any

from ..darktrace_utils import SplunkSeverity, description_cleanup, get_device_name, nget


@dataclass
class ModelBreachContainer:
    """
    Dataclass to store the data for a Container from a Model Breach Event
    """

    name: str
    description: str
    start_time: str
    severity: str
    source_data_identifier: str
    asset_name: str
    score: str

    def __init__(self, model_breach: dict[str, Any]) -> None:
        time = model_breach["time"] / 1000
        time_formatted = datetime.fromtimestamp(time).strftime("%Y-%m-%dT%H:%M:%S.00Z")
        score = round(model_breach["score"] * 100)

        severity = nget(model_breach, "model", "then", "category")
        is_compliance = nget(model_breach, "model", "then", "compliance")

        if is_compliance or severity:
            self.severity = SplunkSeverity.from_category("Compliance" if is_compliance else severity).value
        else:
            self.severity = SplunkSeverity.from_score(score).value

        pbid = model_breach.get("pbid")
        category = nget(model_breach, "model", "then", "name")
        did = nget(model_breach, "device", "did")
        hostname = nget(model_breach, "device", "hostname")
        devicelabel = nget(model_breach, "device", "devicelabel")
        ip = nget(model_breach, "device", "ip")
        device_name = get_device_name(devicelabel, hostname, ip, category)

        self.name = f"{device_name} breached model {category} with a score of {score}%"
        self.description = f"{device_name} ({did}) breached model {category} ({pbid}) with a score of {score}%"

        self.start_time = time_formatted
        self.source_data_identifier = pbid
        self.asset_name = "Darktrace"
        self.score = str(score)


@dataclass
class ModelBreachArtifact:
    """
    Dataclass to store the data for an Artifact created from a model breach
    """

    asset_name: str
    container_id: str
    name: str
    device_label: str
    type: str
    start_time: str
    severity: str
    source_data_identifier: str
    description: str
    cef: dict

    def __init__(
        self,
        model_breach_container: ModelBreachContainer,
        model_breach: dict[str, Any],
        container_id: str,
        base_url: str,
    ):
        description = nget(model_breach, "model", "then", "description")
        self.description = description_cleanup(description)

        category = nget(model_breach, "model", "then", "name")
        category_list = category.split("::")

        self.asset_name = model_breach_container.asset_name
        self.container_id = str(container_id)
        self.name = " / ".join(category_list[1:])
        self.device_label = nget(model_breach, "device", "devicelabel")
        self.type = category_list[0]
        self.start_time = model_breach_container.start_time
        self.severity = model_breach_container.severity
        self.source_data_identifier = model_breach_container.source_data_identifier

        self.cef = self.get_cef(model_breach, base_url)

    def get_cef(self, model_breach: dict[str, Any], base_url) -> dict[str, Any]:
        """Create the CEF (Common Event Format) object for a model breach artifact"""

        cef = dict()
        cef["modelBreachId"] = self.source_data_identifier
        cef["modelBreachUrl"] = f"{base_url}/#modelbreach/{self.source_data_identifier!s}"

        if "System" != self.type:
            cef["deviceId"] = nget(model_breach, "device", "did")
            cef["deviceAddress"] = nget(model_breach, "device", "ip")
            cef["deviceHostname"] = nget(model_breach, "device", "hostname")
            cef["deviceLabel"] = nget(model_breach, "device", "devicelabel")
        else:
            cef["systemNote"] = "Login to the Darktrace UI to see the system alerts"

        if "Antigena" in self.type:
            antigena = nget(model_breach, "model", "now", "actions", "antigena")
            if antigena is not None:
                cef["antigenaAction"] = antigena.get("action")
                cef["antigenaDuration"] = str(timedelta(seconds=antigena.get("duration")))
                cef["antigenaNote"] = "Use the post tag action to trigger antigena actions for deployments in human confirmation mode"

        return cef
