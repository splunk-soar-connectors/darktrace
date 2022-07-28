import json
import sys

import phantom.app as phantom
import requests
from phantom.base_connector import BaseConnector

from darktrace.handlers.darktrace_connectivity_handler import ConnectivityHandler
from darktrace.handlers.darktrace_device_handler import DeviceHandler
from darktrace.handlers.darktrace_model_breach_handler import ModelBreachHandler
from darktrace.handlers.darktrace_poll_handler import PollHandler


class DarktraceConnector(BaseConnector):
    def handle_action(self, param: dict):
        """
        Handle an action.

        Takes an action ID from the parameter dictionary and calls the appropriate handler
        """
        returned_value = phantom.APP_SUCCESS
        action_id = self.get_action_identifier()
        self.debug_print("Running action: ", self.get_action_identifier())
        self.debug_print("Action params: ", param)

        # Special Purpose Actions
        if action_id == "test_connectivity":
            returned_value = ConnectivityHandler(self, param)._handle_test_connectivity()
        elif action_id == "on_poll":
            returned_value = PollHandler(self, param)._handle_on_poll()

        # Device Actions
        elif action_id == "get_device_description":
            returned_value = DeviceHandler(self, param)._handle_get_device_description()
        elif action_id == "get_device_model_breaches":
            returned_value = DeviceHandler(self, param)._handle_get_device_model_breaches()
        elif action_id == "get_device_tags":
            returned_value = DeviceHandler(self, param)._handle_get_tags_for_device()
        elif action_id == "get_tagged_devices":
            returned_value = DeviceHandler(self, param)._handle_get_tagged_devices()
        elif action_id == "post_tag":
            returned_value = DeviceHandler(self, param)._handle_post_tag_to_device()

        # Model Breach Actions
        elif action_id == "post_comment":
            returned_value = ModelBreachHandler(self, param)._handle_post_comment()
        elif action_id == "acknowledge_breach":
            returned_value = ModelBreachHandler(self, param)._handle_acknowledge_breach()
        elif action_id == "unacknowledge_breach":
            returned_value = ModelBreachHandler(self, param)._handle_unacknowledge_breach()
        elif action_id == "get_breach_comments":
            returned_value = ModelBreachHandler(self, param)._handle_get_breach_comments()
        elif action_id == "get_breach_connections":
            returned_value = ModelBreachHandler(self, param)._handle_get_breach_connections()

        self.debug_print("Action result: ", returned_value)

        return returned_value

    def initialize(self):
        self._state = self.load_state()
        config = self.get_config()

        # Access values in asset config by the name
        self._base_url = config["base_url"]
        self._token = config["public_token"]
        self._private_token = config["private_token"]
        self.should_poll_ai_analyst = config.get("poll_aia")
        self.should_poll_model_breach = config.get("poll_mb")

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    """Debugging func"""
    import argparse  # pylint: disable=import-outside-toplevel

    import pudb  # pylint: disable=import-outside-toplevel

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)
    argparser.add_argument(
        "-v", "--verify", action="store_true", help="verify", required=False, default=False
    )

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify
    TIMEOUT = 5

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass  # pylint: disable=import-outside-toplevel

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = DarktraceConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            token_resp = requests.get(login_url, verify=verify, timeout=TIMEOUT)
            csrftoken = token_resp.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            login_resp = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=TIMEOUT)
            session_id = login_resp.cookies["sessionid"]
        except Exception as ex:
            print("Unable to get session id from the platform. Error: " + str(ex))
            sys.exit(1)

    with open(args.input_test_json) as fh:
        in_json = fh.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = DarktraceConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)


if __name__ == "__main__":
    main()
