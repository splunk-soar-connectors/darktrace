# File: darktrace_handler.py
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

from abc import ABCMeta
from typing import TYPE_CHECKING, Any, List, Optional, Tuple

from phantom.action_result import ActionResult

from ..client.darktrace_client import DarktraceClient

if TYPE_CHECKING:
    from darktrace_connector import DarktraceConnector


class DarktraceHandler(metaclass=ABCMeta):
    """
    Splunk SOAR docs: https://docs.splunk.com/Documentation/SOAR/current/DevelopApps/AppDevAPIRef
    """

    def __init__(self, connector: "DarktraceConnector", param: dict) -> None:
        self._connector = connector
        self.param = param  # Parameter dictionary to be acted on
        self.action_result = self._connector.add_action_result(ActionResult(dict(param)))
        self._client = DarktraceClient.from_connector(self._connector)

    def save_progress(self, message: str):
        """
        Sends a progress message to the Splunk SOAR core, which is saved in persistent storage.
        """
        self._connector.save_progress(message)

    def debug_print(self, message: str, dump_object: Any = None):
        """Debug logs a message followed by a pretty printed object"""
        self._connector.debug_print(message, dump_object)

    def save_container(self, container: dict) -> Tuple[bool, str, Optional[str]]:
        """
        Saves a container and artifacts. Returns a tuple of (status, status_message, id or None)
        """
        return self._connector.save_container(container)

    def save_artifacts(self, artifact: List[dict]) -> Tuple[bool, str, Optional[List[str]]]:
        """Saves artifacts. Returns a tuple of (status, status_message, List[id] or None)"""
        return self._connector.save_artifacts(artifact)
