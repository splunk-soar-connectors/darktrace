from typing import Any, Dict, List

import phantom.app as phantom

from .darktrace_handler import DarktraceHandler
from ..utils import SplunkSeverity, nget

class DeviceHandler(DarktraceHandler):
    def handle_get_device_description(self):
        """
        Handler for `get_device_description` action.

        Takes `device_id` as a parameter
        """

        device_id = int(self.param["device_id"])

        action_status, device_description = self._client.get_device_summary(
            self.action_result, device_id
        )

        if phantom.is_fail(action_status):
            self.save_progress("Failed retrieving device summary")
            return self.action_result.get_status()

        self.action_result.add_data(device_description["data"])

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def handle_get_device_model_breaches(self):
        """
        Handler for `get_device_model_breaches` action.

        Takes `device_id` as a parameter
        """

        device_id = int(self.param["device_id"])

        action_status, device_model_breaches = self._client.get_device_summary(
            self.action_result, device_id
        )

        if phantom.is_fail(action_status):
            self.save_progress("Failed retrieving device model breaches")
            return self.action_result.get_status()

        model_breaches = device_model_breaches["data"]["modelbreaches"]
        for model_breach in model_breaches:
            self.action_result.add_data(model_breach)

        self._get_model_breach_additional_info(model_breaches)

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def handle_get_tags_for_device(self):
        """
        Handler for `get_tags_for_device` action.

        Takes `device_id` as a parameter
        """

        device_id = int(self.param["device_id"])

        action_status, tags = self._client.get_tags_for_device(self.action_result, device_id)

        if phantom.is_fail(action_status):
            self.save_progress("Failed retrieving tags for device")
            return self.action_result.get_status()

        for tag in tags:
            self.action_result.add_data(tag)

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def handle_get_tagged_devices(self) -> bool:
        """
        Handler for `get_tagged_devices` action.

        Takes `tag` (name of tag) as a parameter
        """

        tag = self.param["tag"]

        action_status, tagged_devices = self._client.get_tagged_devices(self.action_result, tag)

        if phantom.is_fail(action_status):
            self.save_progress("Failed retrieving devices for tag")
            return self.action_result.get_status()

        tag_entities = tagged_devices["entities"]
        devices = tagged_devices["devices"]

        self._add_device_info_to_summary(devices)

        for tag_device in tag_entities:
            self.action_result.add_data(tag_device)

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def handle_post_tag_to_device(self) -> bool:
        """
        Handler for `post_tag` action.

        Params:
            device_id
            tag
            duration (Optional: Length of time to apply the tag for)
        """

        device_id = int(self.param["device_id"])
        tag = self.param["tag"]
        duration = int(self.param["duration"]) if "duration" in self.param else None

        action_status, tag_result = self._client.post_tag_to_device(
            self.action_result, device_id, tag, duration
        )

        if phantom.is_fail(action_status):
            self.save_progress("Failed posting tag to device")
            return self.action_result.get_status()

        self.action_result.add_data(tag_result)

        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _add_device_info_to_summary(self, devices: List[Dict[str, Any]]):
        """
        Add device info from a list of devices to the action result summary
        """

        summary = {}
        for i, device in enumerate(devices):
            summary[str(i)] = {
                "did": device["did"],
                "hostname": device.get("hostname"),
                "ip": device.get("ip"),
                "mac": device.get("macaddress"),
                "label": device.get("devicelabel"),
            }

        self.action_result.update_summary(summary)

    def _get_model_breach_additional_info(self, model_breaches):

        """
        Adds model breach url and Severity to every model breach action result summary
        """
        
        model_breach_additional_info = {}

        for i, model_breach in enumerate(model_breaches):

            severity = nget(model_breach, "model", "then", "category")
            is_compliance = nget(model_breach, "model", "then", "compliance")
            pbid = nget(model_breach, "pbid")
            score = nget(model_breach, "score")

            if is_compliance or severity:
                severity = SplunkSeverity.from_category(
                    "Compliance" if is_compliance else severity
                ).value
            else:
                severity = SplunkSeverity.from_score(score).value

            model_breach_additional_info[str(i)] = {
                "severity": severity,
                "darktrace_url": f"{self._client.base_url}/#modelbreach/{str(pbid)}"
            }

        self.action_result.update_summary(model_breach_additional_info)