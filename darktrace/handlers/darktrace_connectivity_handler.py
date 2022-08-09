# File: darktrace_connectivity_handler.py
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

import phantom.app as phantom

from .darktrace_handler import DarktraceHandler


class ConnectivityHandler(DarktraceHandler):
    def _handle_test_connectivity(self):
        """
        Handler for the `test_connectivity` action
        """
        self.save_progress("Testing Connectivity to your Darktrace Instance")
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
