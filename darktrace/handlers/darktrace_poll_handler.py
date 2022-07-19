import dataclasses
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

import phantom.app as phantom

from darktrace.client.ai_analyst_objects import AIAnalystArtifact, AIAnalystContainer
from darktrace.client.model_breach_objects import ModelBreachArtifact, ModelBreachContainer

from ..utils import now
from .darktrace_handler import DarktraceHandler


class PollHandler(DarktraceHandler):
    """
    Handler for the on_poll action.

    Polls for AI Analyst incidents and Model Breaches
    """

    def handle_on_poll(self) -> bool:
        """Poll for model breaches and AI Analyst incidents in a time range"""

        self.save_progress("Polling Darktrace")

        mb_start_time, aia_start_time, end_time = self._determine_time_range()

        model_breach_error = False
        if self._connector.should_poll_model_breach:
            self.debug_print(f"Model Breach Poll Time Range: {mb_start_time} <-> {end_time}")
            model_breach_error = self._poll_model_breach(mb_start_time, end_time)

        aia_error = False
        if self._connector.should_poll_ai_analyst:
            self.debug_print(f"AI Analyst Poll Time Range: {aia_start_time} <-> {end_time}")
            aia_error = self._poll_ai_analyst(aia_start_time, end_time)

        if model_breach_error:
            self.debug_print("Error occurred while processing model breaches")
        if aia_error:
            self.debug_print("Error occurred while processing AI Analyst incidents")

        if model_breach_error or aia_error:
            return self.action_result.set_status(phantom.APP_ERROR)

        self._connector._state["last_poll"] = end_time.strftime("%Y-%m-%dT%H:%M:%S.00Z")
        self.save_progress("Completed poll cycle")
        return self.action_result.set_status(phantom.APP_SUCCESS)

    def _determine_time_range(self) -> Tuple[datetime, datetime, datetime]:
        """
        Get the time range for a poll.

        Returns a tuple of (start_model_breach, start_ai_analyst, end)
        """

        poll_now = self._connector.is_poll_now()
        last_poll = self._connector._state.get("last_poll")

        end_time = now()
        mb_start_time = end_time - timedelta(hours=6)
        aia_start_time = end_time - timedelta(days=1)

        self.debug_print(f"Last Poll: {last_poll}")
        if poll_now:
            self.debug_print("Run Mode: Poll Now")
        else:
            self.debug_print("Run Mode: Scheduled Poll")

        return mb_start_time, aia_start_time, end_time

    def _poll_model_breach(self, start_datetime: datetime, end_datetime: datetime) -> bool:
        """Poll for model breaches"""

        self.debug_print("Polling Darktrace model breaches")
        action_status, model_breaches = self._client.get_model_breaches(
            self.action_result, start_datetime, end_datetime
        )

        if phantom.is_fail(action_status):
            self.save_progress("Failed posting tag to device")
            return self.action_result.get_status()

        self.debug_print(f"{len(model_breaches)} model breaches found")  # type: ignore
        previous_mb_ids = set(self._connector._state.get("seen_mb_ids", []))  # type: Set[str]
        current_mb_ids = []  # type: List[str]

        error_occurred = False
        new_model_breaches = 0
        for model_breach in model_breaches:  # type: ignore
            # Check for already seen breaches
            mb_id = model_breach["pbid"]
            current_mb_ids.append(mb_id)
            if mb_id in previous_mb_ids:
                continue

            new_model_breaches += 1
            container_id, container = self._save_model_breach(model_breach)
            if container is None:
                error_occurred = True
                continue
            self._create_model_breach_artifacts(container, model_breach, container_id)

        self.debug_print(f"{new_model_breaches} new model breaches found")

        self._connector._state["seen_mb_ids"] = current_mb_ids

        return error_occurred

    def _save_model_breach(
        self, model_breach_dict: Dict[str, Any]
    ) -> Tuple[str, Optional[ModelBreachContainer]]:
        """Construct and save a container from a model breach"""

        model_breach_container = ModelBreachContainer(model_breach_dict)
        container = dataclasses.asdict(model_breach_container)
        action_status, creation_msg, container_id = self.save_container(container=container)
        if phantom.is_fail(action_status):
            self.debug_print(creation_msg)
            err_msg = f"Error creating container for pbid {creation_msg}"
            self.save_progress(err_msg)
            self.action_result.set_status(phantom.APP_ERROR, err_msg)
            return "", None

        self.save_progress(f"Container saved - {container_id}")
        return container_id, model_breach_container  # type: ignore

    def _create_model_breach_artifacts(
        self, container: ModelBreachContainer, model_breach_dict: Dict[str, Any], container_id: str
    ):
        """Construct artifacts from a model breach"""

        model_breach_artifact = ModelBreachArtifact(
            container, model_breach_dict, container_id, self._client.base_url
        )
        artifact = dataclasses.asdict(model_breach_artifact)
        creation_status, creation_msg, artifact_id_list = self.save_artifacts([artifact])
        if phantom.is_fail(creation_status):
            self.debug_print(creation_msg)
            err_msg = f"Error creating Artifact for pbid {creation_msg}"
            self.save_progress(err_msg)
            self.action_result.set_status(phantom.APP_ERROR, err_msg)

        self.save_progress(f"Artifact saved - {artifact_id_list[0]}")  # type: ignore

    def _poll_ai_analyst(self, start_datetime: datetime, end_datetime: datetime) -> bool:
        """Poll for AI Analyst incidents"""

        self.debug_print("Polling Darktrace AI Analyst incidents")
        action_status, raw_incident_events = self._client.get_ai_analyst_incidents(
            self.action_result, start_datetime, end_datetime
        )

        if phantom.is_fail(action_status):
            self.save_progress("Failed posting tag to device")
            return self.action_result.get_status()

        incidents = self._create_incidents(raw_incident_events)  # type: ignore

        self.debug_print(f"{len(raw_incident_events)} incident events found")  # type: ignore
        self.debug_print(f"{len(incidents)} incidents found")

        error_occurred = False
        for incident_id, incident_events in incidents.items():

            # save ai analyst container
            container_id = self._save_ai_analyst_incident(incident_id, incident_events)

            if not container_id:
                error_occurred = True
                continue
            # create one artifact for each container + one artifact per
            # related model breach
            self._create_ai_analyst_artifacts(incident_events, container_id)

        return error_occurred

    def _create_incidents(self, incident_events: List[dict]) -> Dict[str, List[dict]]:
        """
        Extract incident events into a dictionary of incidents.

        Groups incident events by `currentGroup`
        """

        incidents = dict()  # type: Dict[str, List[dict]]

        for incident_event in incident_events:
            current_group = incident_event.get("currentGroup", "")  # type: str

            if current_group in incidents:
                incidents[current_group].append(incident_event)
            else:
                incidents[current_group] = [incident_event]

        return incidents

    def _save_ai_analyst_incident(self, incident_id: str, incident_events: List[dict]) -> str:
        """
        Constuct and save a container from an incident
        """

        ai_analyst_container = AIAnalystContainer(incident_id, incident_events)
        container = dataclasses.asdict(ai_analyst_container)
        action_status, creation_msg, container_id = self.save_container(container=container)
        if phantom.is_fail(action_status):
            self.debug_print(creation_msg)
            self.save_progress(f"Error creating container for AIAnalyst Incident {creation_msg}")
            self.action_result.set_status(
                phantom.APP_ERROR, f"Error creating container for pbid {creation_msg}"
            )
            return ""
        self.save_progress(f"Container saved - {container_id}")
        return container_id  # type: ignore

    def _create_ai_analyst_artifacts(self, incident_events: List[dict], container_id: str):
        """
        Create the artifacts for an incident

        Creates an artifact for each incident
        """

        for incident in incident_events:
            ai_analyst_artifact = AIAnalystArtifact(incident, container_id, self._client.base_url)
            incident_artifact = dataclasses.asdict(ai_analyst_artifact)
            related_breach_artifacts = ai_analyst_artifact.get_breach_artifacts(
                incident, self._client.base_url
            )
            artifacts = [incident_artifact, *related_breach_artifacts]
            creation_status, creation_msg, artifact_ids = self.save_artifacts(artifacts)

            if phantom.is_fail(creation_status):
                self.debug_print(creation_msg)
                err_msg = f"Error creating Artifact for uuid {creation_msg}"
                self.save_progress(err_msg)
                self.action_result.set_status(phantom.APP_ERROR, err_msg)
            else:
                self.save_progress(f"Artifacts saved - {artifact_ids}")
