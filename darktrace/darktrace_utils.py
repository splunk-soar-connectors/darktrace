# File: darktrace_utils.py
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

import datetime
import enum
import json
from typing import Mapping, Union


class SplunkSeverity(enum.Enum):
    """Enum representing the severity of a model breach"""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def from_category(cls, category: str) -> "SplunkSeverity":
        """Convert model breach category into severity"""
        return SEVERITY_MAP.get(category.lower(), cls.LOW)

    @classmethod
    def from_score(cls, score: int) -> "SplunkSeverity":
        """Convert model breach score into a severity"""
        if score > 75:
            return cls.HIGH
        if score > 45:
            return cls.MEDIUM
        return cls.LOW


SEVERITY_MAP = {
    "critical": SplunkSeverity.HIGH,
    "suspicious": SplunkSeverity.MEDIUM,
    "compliance": SplunkSeverity.LOW,
    "informational": SplunkSeverity.LOW,
}


def description_cleanup(description: str) -> str:
    """Clean up the model brach description"""
    description_str = json.dumps(description)
    description_cleaned = description_str.replace("\\", "#")
    description_cleaned = description_cleaned.replace("##n##n", " ")
    description_cleaned = description_cleaned.replace('"', "")
    return description_cleaned


def get_device_name(devicelabel: str, hostname: str, ip: str, category: str) -> str:
    """Pick a device name out of a set of model breach fields"""
    if devicelabel != "Unknown":
        device_name = devicelabel
    elif hostname != "Unknown":
        device_name = hostname
    elif ip != "Unknown":
        device_name = ip
    elif category == "System::System":
        device_name = "Darktrace"
    else:
        device_name = "A Device"
    return device_name


def nget(structure: Union[dict, list, tuple], *fields: Union[str, int], default: str = "Unknown"):
    """
    Extract a value safely from a JSON structure,
    returning a default value if any error occurs or no value is found
    """

    while fields:
        try:
            structure = structure[fields[0]]
        except (KeyError, TypeError, IndexError):
            return default

        fields = fields[1:]
    if structure is None or structure == "":
        return default
    return structure


def now() -> datetime.datetime:
    """Returns datetime aware UTC time now"""
    return datetime.datetime.now(datetime.timezone.utc)


def stringify_data(data: Mapping) -> str:
    """Stringify a params or data dict without encoding"""
    return "&".join([f"{k}={v}" for k, v in data.items()])
