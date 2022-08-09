# File: darktrace_client.py
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

"""
Client for making requests to the Darktrace API
"""

import hashlib
import hmac
import json
from datetime import datetime
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple, Union

import requests

if TYPE_CHECKING:
    import phantom.app as phantom  # noqa: F401
    from phantom.action_result import ActionResult  # noqa: F401

from ..darktrace_consts import (ACK_BREACH, AI_ANALYST_ENDPOINT, COMMENT_BREACH, DEVICE_SUMMARY_ENDPOINT, DEVICES_ENDPOINT,
                                MODEL_BREACH_COMMENT_ENDPOINT, MODEL_BREACH_CONNECTIONS_ENDPOINT, MODEL_BREACH_ENDPOINT, TAG_ENTITIES_ENDPOINT,
                                TEST_CONNECTIVITY_ENDPOINT, UNACK_BREACH)
from ..darktrace_utils import now, stringify_data
from .darktrace_resp_processer import process_response

if TYPE_CHECKING:
    from darktrace_connector import DarktraceConnector


class DarktraceClient:
    """
    Client class to interact with the Darktrace API
    """

    @classmethod
    def from_connector(cls, connector: "DarktraceConnector") -> "DarktraceClient":
        """Create a client from the DarktraceConnector object"""
        config = connector.get_config()
        connector.debug_print(config)
        return cls(
            config["base_url"],
            config["public_token"],
            config["private_token"],
            config["tls_verify"],
        )

    def __init__(
        self, base_url: str, token: str, private_token: str, use_tls_certificate: bool = True
    ):
        self.base_url = base_url
        self._token = token
        self._private_token = private_token
        self._use_tsl_certificate = use_tls_certificate

    def test_connectivity(self, action_result: ActionResult) -> Tuple[bool, dict]:
        """Call the summary statistics endpoint to test connecting to the Darktrace Box"""
        return self.get(
            action_result, TEST_CONNECTIVITY_ENDPOINT, params={"responsedata": "subnets"}
        )  # type: ignore

    def get_device_summary(self, action_result: ActionResult, device_id: int) -> Tuple[bool, dict]:
        """Get a device summary"""
        return self.get(
            action_result, DEVICE_SUMMARY_ENDPOINT, params={"did": device_id}
        )  # type: ignore

    def get_tags_for_device(
        self, action_result: ActionResult, device_id: int
    ) -> Tuple[bool, List[dict]]:
        """Get the tags on a device"""
        return self.get(
            action_result, TAG_ENTITIES_ENDPOINT, params={"did": device_id}
        )  # type: ignore

    def post_tag_to_device(
        self, action_result: ActionResult, device_id: int, tag: str, duration: int = None
    ) -> Tuple[bool, dict]:
        """Tag a device for a specified duration (or indefinitely if unspecified)"""
        data = {"did": device_id, "tag": tag}
        if duration:
            data["duration"] = duration
        return self.post(action_result, TAG_ENTITIES_ENDPOINT, data)  # type: ignore

    def get_tagged_devices(
        self, action_result: ActionResult, tag: str
    ) -> Tuple[bool, Dict[str, List[dict]]]:
        """Get devices with a specific tag"""
        params = {"tag": tag, "fulldevicedetails": "true"}
        return self.get(action_result, TAG_ENTITIES_ENDPOINT, params=params)  # type: ignore

    def get_device(self, action_result: ActionResult, device_id: int) -> Tuple[bool, dict]:
        """Get Darktrace data about a device ID"""
        return self.get(action_result, DEVICES_ENDPOINT, params={"did": device_id})  # type: ignore

    def post_model_breach_comment(
        self, action_result: ActionResult, model_breach_id: int, comment: str
    ) -> Tuple[bool, Optional[dict]]:
        """Post a comment on a model breach"""
        query_uri = f"{MODEL_BREACH_ENDPOINT}/{model_breach_id}{COMMENT_BREACH}"
        return self.post(action_result, query_uri, json={"message": comment})  # type: ignore

    def acknowledge_breach(
        self, action_result: ActionResult, model_breach_id: int
    ) -> Tuple[bool, Optional[dict]]:
        """Acknowledge a model breach"""
        query = f"{MODEL_BREACH_ENDPOINT}/{model_breach_id}{ACK_BREACH}"
        return self.post(action_result, query, data={"acknowledge": "true"})  # type: ignore

    def unacknowledge_breach(
        self, action_result: ActionResult, model_breach_id: int
    ) -> Tuple[bool, Optional[dict]]:
        """Unacknowledge a model breach"""
        query = f"{MODEL_BREACH_ENDPOINT}/{model_breach_id}{UNACK_BREACH}"
        return self.post(action_result, query, data={"unacknowledge": "true"})  # type: ignore

    def get_breach_comments(
        self, action_result: ActionResult, model_breach_id: int
    ) -> Tuple[bool, Optional[List[dict]]]:
        """Get comments on a model breach"""
        return self.get(
            action_result, MODEL_BREACH_COMMENT_ENDPOINT, params={"pbid": model_breach_id}
        )  # type: ignore

    def get_breach_connections(
        self, action_result: ActionResult, model_breach_id: int
    ) -> Tuple[bool, Optional[List[dict]]]:
        """Get connection data associated to a model breach"""
        return self.get(
            action_result, MODEL_BREACH_CONNECTIONS_ENDPOINT, params={"pbid": model_breach_id}
        )  # type: ignore

    def get_model_breaches(
        self, action_result: ActionResult, start_time: datetime, end_time: datetime
    ) -> Tuple[bool, Optional[List[dict]]]:
        """Get model breach data in a time range"""
        params = {
            "from": start_time.strftime("%Y-%m-%dT%H:%M:%S.00Z"),
            "to": end_time.strftime("%Y-%m-%dT%H:%M:%S.00Z"),
            "includeacknowledged": "true",
        }
        query_uri = f"{MODEL_BREACH_ENDPOINT}"
        return self.get(action_result, query_uri, params)  # type: ignore

    def get_ai_analyst_incidents(
        self, action_result: ActionResult, start_time: datetime, end_time: datetime
    ) -> Tuple[bool, Optional[List[dict]]]:
        """Get AI Analyst incident data in a time range"""
        params = {
            "starttime": int(start_time.timestamp() * 1000),
            "endtime": int(end_time.timestamp() * 1000),
            "includeacknowledged": "true",
        }
        return self.get(action_result, AI_ANALYST_ENDPOINT, params=params)  # type: ignore

    def post(
        self, action_result: ActionResult, query_uri: str, data: dict = None, json: dict = None
    ) -> Tuple[bool, Optional[Union[dict, List[dict]]]]:
        """Make an HTTP POST request to the Darktrace API"""
        return process_response(
            self._request(query_uri, method="POST", data=data, json=json), action_result
        )

    def get(
        self, action_result: ActionResult, query_uri: str, params: dict = None
    ) -> Tuple[bool, Optional[Union[dict, List[dict]]]]:
        """Make an HTTP GET request to the Darktrace API"""
        return process_response(self._request(query_uri, "GET", params=params), action_result)

    def _request(
        self,
        query_uri: str,
        method: str,
        params: dict = None,
        data: dict = None,
        json: dict = None,
        headers: Dict[str, str] = None,
    ) -> requests.Response:
        """Make an HTTP request to the Darktrace API"""

        url = f"{self.base_url}{query_uri}"
        headers = {
            **self._create_headers(query_uri, params or data or json or None, is_json=bool(json)),
            **(headers or {}),
        }

        TIMEOUT = 10

        return requests.request(
            method=method,
            url=url,
            params=params,
            data=data,
            json=json,
            headers=headers,
            verify=self._use_tsl_certificate,
            timeout=TIMEOUT
        )

    def _create_headers(
        self, query_uri: str, query_data: dict = None, is_json: bool = False
    ) -> Dict[str, str]:
        """Create headers required for successful authentication"""
        date = now().isoformat(timespec="auto")
        signature = self._create_signature(query_uri, date, query_data, is_json=is_json)
        return {"DTAPI-Token": self._token, "DTAPI-Date": date, "DTAPI-Signature": signature}

    def _create_signature(
        self, query_uri: str, date: str, query_data: dict = None, is_json: bool = False
    ) -> str:
        """Create signature from Darktrace private token"""
        if is_json:
            query_string = f"?{json.dumps(query_data)}"
        else:
            query_string = f"?{stringify_data(query_data)}" if query_data else ""

        return hmac.new(
            self._private_token.encode("ASCII"),
            f"{query_uri}{query_string}\n{self._token}\n{date}".encode("ASCII"),
            hashlib.sha1,
        ).hexdigest()
