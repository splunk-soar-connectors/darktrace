import phantom.app as phantom

from .darktrace_handler import DarktraceHandler


class ConnectivityHandler(DarktraceHandler):
    def _handle_test_connectivity(self):
        """
        Handler for the `test_connectivity` action
        """

        action_status, result = self._client.test_connectivity(self.action_result)

        if phantom.is_fail(action_status):
            self.save_progress("Test Connectivity Failed")
            return self.action_result.get_status()

        if not result:
            message = "Test Connectivity did not return any data in the response"
            self.save_progress(message)
            return self.action_result.set_status(phantom.APP_ERROR, message)

        self.save_progress("Test Connectivity passed")
        return self.action_result.set_status(phantom.APP_SUCCESS)
