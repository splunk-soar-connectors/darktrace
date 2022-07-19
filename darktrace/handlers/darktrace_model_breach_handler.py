from datetime import datetime
from typing import Any, Dict, List

import phantom.app as phantom

from ..utils import nget
from .darktrace_handler import DarktraceHandler


class ModelBreachHandler(DarktraceHandler):
    def handle_post_comment(self):
        """
        Handler for `post_comment` action.

        Params:
            `model_breach_id`: The ID of a model breach
            `message`: The comment to post
        """

        model_breach_id = int(self.param["model_breach_id"])
        message = self.param["message"]

        action_status, comment_result = self._client.post_model_breach_comment(
            self.action_result, model_breach_id, message
        )

        if phantom.is_fail(action_status):
            self.save_progress("Failed posting comment to model breach")
            return self.action_result.get_status()

        self.action_result.add_data(comment_result)

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def handle_acknowledge_breach(self):
        """
        Handler for `acknowledge_breach` action.

        Params:
            `model_breach_id`: The ID of the model breach to acknowledge
        """

        model_breach_id = int(self.param["model_breach_id"])

        action_status, breach_result = self._client.acknowledge_breach(
            self.action_result, model_breach_id
        )

        if phantom.is_fail(action_status):
            self.save_progress("Failed acknowledge action to model breach")
            return self.action_result.get_status()

        self.action_result.add_data(breach_result)

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def handle_unacknowledge_breach(self):
        """
        Handler for `unacknowledge_breach` action.

        Params:
            `model_breach_id`: The ID of the model breach to unacknowledge
        """

        model_breach_id = int(self.param["model_breach_id"])

        action_status, breach_result = self._client.unacknowledge_breach(
            self.action_result, model_breach_id
        )

        if phantom.is_fail(action_status):
            self.save_progress("Failed unacknowledge action to model breach")
            return self.action_result.get_status()

        self.action_result.add_data(breach_result)

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def handle_get_breach_comments(self) -> bool:
        """
        Handler for `get_breach_comments` action.

        Params:
            `model_breach_id`: The ID of the model breach to get the comments for
        """

        model_breach_id = int(self.param["model_breach_id"])
        action_status, comments = self._client.get_breach_comments(
            self.action_result, model_breach_id
        )

        if phantom.is_fail(action_status):
            self.save_progress("Failed getting model breach comments")
            return self.action_result.get_status()

        for comment in comments:
            self.action_result.add_data(comment)

        self._add_comment_summary(comments)

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def handle_get_breach_connections(self) -> bool:
        """
        Handler for `get_breach_connections` action.

        Params:
            `model_breach_id`: The ID of the model breach to get the connections for
        """

        model_breach_id = int(self.param["model_breach_id"])

        action_status, connections = self._client.get_breach_connections(
            self.action_result, model_breach_id
        )

        if phantom.is_fail(action_status):
            self.save_progress("Failed model breach connection")
            return self.action_result.get_status()

        for connection in connections:
            if connection["action"] == "connection":
                entry = self._get_connection_data(connection)
                self.action_result.add_data(entry)

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _add_comment_summary(self, comments: List[Dict[str, Any]]):
        """Add comment info to the action summary"""
        comment_summary = dict()
        for i, curr_entry in enumerate(comments):
            time = datetime.fromtimestamp(int(curr_entry["time"]) / 1000)
            comment_summary[str(i)] = {
                "username": str(curr_entry.get("username")),
                "comment": str(curr_entry.get("message")),
                "time": str(time) + " UTC",
            }
        self.action_result.update_summary(comment_summary)

    def _get_connection_data(self, conn: Dict[str, Any]) -> Dict[str, str]:
        """Extract data from a connection"""

        protocol = conn.get("protocol", "Unknown")
        application_protocol = conn.get("applicationprotocol", "Unknown")

        conn_data = {}
        conn_data["time"] = str(conn["time"])
        conn_data["proto"] = f"{protocol} - {application_protocol}"
        conn_data["dest_hostname"] = str(nget(conn, "destinationDevice", "hostname"))
        conn_data["dest_ip"] = str(nget(conn, "destinationDevice", "ip"))
        conn_data["src_hostname"] = str(nget(conn, "sourceDevice", "hostname"))
        conn_data["src_ip"] = str(nget(conn, "sourceDevice", "ip"))
        conn_data["src_port"] = conn.get("sourcePort", "Unknown")
        conn_data["dest_port"] = conn.get("destinationPort", "Unknown")

        return conn_data
