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
