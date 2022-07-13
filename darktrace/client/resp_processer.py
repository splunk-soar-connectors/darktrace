"""
Functions to process a response from the Darktrace API
"""

from typing import Any, List, Optional, Tuple, Union

import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult


def _process_empty_response(
    response: requests.Response, action_result: ActionResult
) -> Tuple[bool, Optional[dict]]:
    """Handler for an empty response. Always errors as never expected."""
    if response.status_code == 200:
        return (phantom.APP_SUCCESS, {})

    return (
        action_result.set_status(
            phantom.APP_ERROR, "Empty response and no information in the header"
        ),
        None,
    )


def _process_html_response(
    response: requests.Response, action_result: ActionResult
) -> Tuple[bool, Optional[dict]]:
    """Handler for an HTML response. Always errors as HTML is never expected."""

    status_code = response.status_code

    try:
        soup = BeautifulSoup(response.text, "html.parser")
        error_text = soup.text
        split_lines = error_text.split("\n")
        split_lines = [x.strip() for x in split_lines if x.strip()]
        error_text = "\n".join(split_lines)
    except BaseException:
        error_text = "Cannot parse error details"

    message = f"Status Code: {status_code}. Data from server:\n{error_text}\n"

    message = message.replace("{", "{{").replace("}", "}}")
    return (action_result.set_status(phantom.APP_ERROR, message), None)


def _process_json_response(
    resp: requests.Response, action_result: ActionResult
) -> Tuple[bool, Optional[Any]]:
    """
    Handler for a JSON response.
    Tries to return the JSON from the response and errors if this fails.
    """

    try:
        resp_json = resp.json()
    except requests.JSONDecodeError as excep:
        return (
            action_result.set_status(
                phantom.APP_ERROR, "Unable to parse JSON response.", exception=excep
            ),
            None,
        )

    if 200 <= resp.status_code < 399:
        return (phantom.APP_SUCCESS, resp_json)

    message = (
        "Error from server. "
        f"Status Code: {resp.status_code} "
        f'Data from server: {resp.text.replace("{", "{{").replace("}", "}}")}'
        # f"Original request: Url - {resp.request.url} Body - {resp.request.body}"
    )

    return (action_result.set_status(phantom.APP_ERROR, message), None)


def process_response(
    resp: requests.Response, action_result: ActionResult
) -> Tuple[bool, Optional[Union[dict, List[dict]]]]:
    """
    Process a response from the Darktrace API. Only returns a success for JSON responses or empty 200 responses
    """

    # store the r_text in debug data, it will get dumped in the logs if the
    # action fails
    if hasattr(action_result, "add_debug_data"):
        action_result.add_debug_data({"r_status_code": resp.status_code})
        action_result.add_debug_data({"r_text": resp.text})
        action_result.add_debug_data({"r_headers": resp.headers})

    # Process a json response
    if "json" in resp.headers.get("Content-Type", ""):
        return _process_json_response(resp, action_result)

    # Process html response in case proxy errors
    if "html" in resp.headers.get("Content-Type", ""):
        return _process_html_response(resp, action_result)

    # Handle an empty response
    if not resp.text:
        return _process_empty_response(resp, action_result)

    # everything else is an error at this point
    message = (
        "Can't process response from server. "
        f"Status Code: {resp.status_code} "
        f'Data from server: {resp.text.replace("{", "{{").replace("}", "}}")}'
    )

    return (action_result.set_status(phantom.APP_ERROR, message), None)
