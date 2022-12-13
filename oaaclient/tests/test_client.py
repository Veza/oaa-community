"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

import base64
import logging
import os
import time
import uuid
from http.client import HTTPMessage, HTTPResponse
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
import requests
from oaaclient.client import OAAClient, OAAClientError, OAAConnectionError, OAAResponseError
from requests.models import Response

from generate_app import generate_app
from generate_idp import generate_idp

# enable debug logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger()
log.setLevel(logging.DEBUG)


@pytest.mark.skipif(not os.getenv("PYTEST_VEZA_HOST"), reason="Test host is not configured")
def test_client_provider(veza_con):
    """ tests for client provider management code using live API

    Does not use the app_provider fixture since this includes all the additional validations
    and tests around provider create/delete behavior
    """
    test_uuid = uuid.uuid4()
    provider_name = f"Pytest-{test_uuid}"

    all_providers = veza_con.get_provider_list()
    assert isinstance(all_providers, list)

    # ensure that randomly generated provider doesn't already exist
    provider_exists = veza_con.get_provider(provider_name)
    assert provider_exists is None

    created_provider = veza_con.create_provider(provider_name, "application")
    assert created_provider is not None
    assert created_provider.get("name") == provider_name
    assert created_provider.get("custom_template") == "application"
    assert created_provider.get("state") == "ENABLED"
    assert created_provider.get("id") is not None

    provider_info = veza_con.get_provider_by_id(created_provider.get("id"))
    assert provider_info is not None
    assert provider_info.get("id") == created_provider.get("id")
    assert provider_info.get("name") == provider_name

    # test getting non-existed
    not_provider = veza_con.get_provider_by_id(uuid.uuid4())
    assert not_provider is None

    # delete the provider
    delete_response = veza_con.delete_provider(created_provider["id"])
    assert isinstance(delete_response, dict)

    deleted = False
    deleted_provider = veza_con.get_provider(provider_name)
    print(deleted_provider)
    if not deleted_provider:
        # delete already succeeded
        deleted = True
    elif deleted_provider["state"] == "DELETING":
        deleted = True
    print(deleted_provider)
    assert deleted

@pytest.mark.skipif(not os.getenv("PYTEST_VEZA_HOST"), reason="Test host is not configured")
def test_client_data_source(veza_con):
    """ tests for client data source management code using live API """

    test_uuid = uuid.uuid4()
    provider_name = f"Pytest-{test_uuid}"
    created_provider = veza_con.create_provider(provider_name, "application")
    assert created_provider is not None
    assert created_provider.get("id") is not None

    provider_id = created_provider["id"]
    existing_data_sources = veza_con.get_data_sources(provider_id)
    # newly created provider should have no data sources
    assert existing_data_sources == []

    not_created = veza_con.get_data_source(name="not created", provider_id=provider_id)
    # expect none for a data source we know doesn't exist yet
    assert not_created is None

    data_source_1 = veza_con.create_data_source(name="data source 1", provider_id=provider_id)
    assert data_source_1 is not None
    assert data_source_1.get("name") == "data source 1"
    assert data_source_1.get("id") is not None

    data_source_2 = veza_con.create_data_source(name="data source 2", provider_id=provider_id)
    assert data_source_2 is not None
    assert data_source_2.get("name") == "data source 2"
    assert data_source_2.get("id") is not None

    assert data_source_1["id"] != data_source_2["id"]

    data_source_1_info = veza_con.get_data_source(name="data source 1", provider_id=provider_id)
    assert data_source_1_info is not None
    assert data_source_1_info.get("name") == "data source 1"
    assert data_source_1_info.get("status") == "PENDING"
    assert data_source_1_info.get("id") is not None

    data_source_list = veza_con.get_data_sources(provider_id)
    assert len(data_source_list) == 2

    # test delete
    delete_response = veza_con.delete_data_source(data_source_id=data_source_1["id"], provider_id=provider_id)
    assert isinstance(delete_response, dict)

    deleted = False
    deleted_datasource = veza_con.get_data_source(name="data source 1", provider_id=provider_id)
    if not deleted_datasource:
        # delete already succeeded
        deleted = True
    elif deleted_datasource["status"] == "DELETING":
        deleted = True

    assert deleted

    # delete provider for cleanup
    veza_con.delete_provider(provider_id)


@pytest.mark.parametrize("url",["https://noreply.vezacloud.com", "noreply.vezacloud.com", "noreply.vezacloud.com/", "https://noreply.vezacloud.com/"])
def test_url_formatter(url):
    test_api_key = "1234"
    with patch.object(OAAClient, "_test_connection", return_value=None):
        veza_con = OAAClient(url=url, token=test_api_key)

        assert veza_con.url == "https://noreply.vezacloud.com"

@patch.object(requests.Session, "request")
def test_api_get_error(mock_session_get):
    # Test that the correct OAAClient exception is raised on properly populated

    test_api_key = "1234"
    # patch _test_connection to instantiate a connection object
    with patch.object(OAAClient, "_test_connection", return_value=None):
        veza_con = OAAClient(url="https://noreply.vezacloud.com", token=test_api_key)


    mock_response = Response()
    mock_response.status_code = 400
    error_message = b"""
                    {
                        "code": "Internal",
                        "message": "Internal Server Error, please retry and if the error persists contact support at support@veza.com",
                        "request_id": "2271c08a9abd3b425c88a397b01bb351",
                        "timestamp": "2022-08-05T21:12:29.405153171Z",
                        "details": [
                            {
                                "@type": "type.googleapis.com/errorstatus.v1.UserFacingErrorInfo",
                                "reason": "INTERNAL",
                                "metadata": {},
                                "message": "Internal server error.",
                                "resolution": "Please retry and if the error persists contact support at support@veza.com"
                            }
                        ]
                    }
                    """
    mock_response._content = error_message
    mock_session_get.return_value = mock_response

    with pytest.raises(OAAClientError) as e:
        response = veza_con.api_get("/api/path")

    # test that the error is populated property
    assert e.value.error == "Internal"
    assert e.value.message == "Internal Server Error, please retry and if the error persists contact support at support@veza.com"
    assert e.value.status_code == 400
    assert len(e.value.details) == 1
    assert "Internal server error." in str(e.value.details)

@patch("urllib3.connectionpool.HTTPConnectionPool._get_conn")
def test_api_get_retry(mock_get_conn):
    # Test that the correct OAAClient exception is raised on properly populated

    # set total retry count lower to speed up tests
    os.environ.setdefault("OAA_API_RETRIES", "3")

    test_api_key = "1234"
    # patch _test_connection to instantiate a connection object
    with patch.object(OAAClient, "_test_connection", return_value=None):
        veza_con = OAAClient(url="https://noreply.vezacloud.com", token=test_api_key)

    url = "/api/should/fail"

    bad = MagicMock(status=500, msg=HTTPMessage(), response=Response())
    bad.create_autospec(HTTPResponse)
    # assert five bad raises exception


    # the mock_get_conn is patched urllib3.connectionpool.HTTPConnectionPool._get_conn
    # _get_conn returns a urllib3.HTTPConection
    # ensure that the side effect is bad for the total number of retries
    mock_get_conn.return_value.getresponse.side_effect = [bad] * (OAAClient.DEFAULT_RETRY_COUNT + 1)

    timeout_start = time.time()

    with pytest.raises(OAAConnectionError) as e:
        response = veza_con.api_get(url)

    retry_time = time.time() - timeout_start
    assert retry_time > 0.5  # three retries should take at least 0.6 retries, if scaling isn't working this would be faster

    # test that the error is populated property
    assert e.value.error == "ERROR"
    assert "Max retries exceeded" in e.value.message

    # test that retry to good works
    url = "/api/should/work"

    mock_get_conn.reset_mock()

    good = MagicMock(name="HttpResponse200")
    good.status = 200
    # in order to get urlib3 to populate the response content before returning it to requests you have to do a few things
    # set msg contains the headers, need to tell it that there is a response coming that is a chunked response
    good.msg = HTTPMessage()
    good.msg.add_header('Transfer-Encoding', 'chunked')
    good.msg.add_header('Content-Type', 'application/json')
    # in order to get urllib3 to read the content we need to pass it a size of chunks, this is from fp.readline
    good.fp.readline.side_effect = [b'1dc1\r\n', b'0\r\n', b'\r\n']
    # after it works out the sizes it makes "_safe_read" calls to get the actual content, we can just pass the value we want here
    good._safe_read.return_value = b'{"message": "ok"}'

    bad.reset_mock()
    mock_get_conn.return_value.getresponse.side_effect = [bad, bad, good]

    # test that the api get will retry to get to the good response
    response = veza_con.api_get(url)
    log.debug(response)
    assert response.get("message") == "ok"


@pytest.mark.skipif(not os.getenv("PYTEST_VEZA_HOST"), reason="Test host is not configured")
@patch("urllib3.connectionpool.HTTPConnectionPool._get_conn")
def test_api_get_retry_timeout(mock_get_conn):
    # Test to ensure full retry timeout exceeds 60 second target

    # ensure that the default isn't being overridden
    del os.environ["OAA_API_RETRIES"]

    test_api_key = "1234"
    # patch _test_connection to instantiate a connection object
    with patch.object(OAAClient, "_test_connection", return_value=None):
        veza_con = OAAClient(url="https://noreply.vezacloud.com", token=test_api_key)

    url = "/api/should/fail"

    bad = MagicMock(status=500, msg=HTTPMessage(), response=Response())
    bad.create_autospec(HTTPResponse)

    # the mock_get_conn is patched urllib3.connectionpool.HTTPConnectionPool._get_conn
    # _get_conn returns a urllib3.HTTPConection
    # ensure that the side effect is bad for the total number of retries
    mock_get_conn.return_value.getresponse.side_effect = [bad] * (OAAClient.DEFAULT_RETRY_COUNT + 1)

    timeout_start = time.time()

    with pytest.raises(OAAConnectionError) as e:
        response = veza_con.api_get(url)

    retry_time = time.time() - timeout_start
    assert 150 < retry_time < 200

    # test that the error is populated property
    assert e.value.error == "ERROR"
    assert "Max retries exceeded" in e.value.message

    return


@patch.object(requests.Session, "request")
def test_api_get_nonjson_error(mock_session_get):
    # Test that the OAAClient correctly handles a non-JSON respponse if error isn't coming from Veza stack

    test_api_key = "1234"
    url = "https://noreply.vezacloud.com"
    # patch _test_connection to instantiate a connection object
    with patch.object(OAAClient, "_test_connection", return_value=None):
        veza_con = OAAClient(url=url, token=test_api_key)

    # Mock a response with non-JSON data, will force a JSONDecodeError
    mock_response = Response()
    mock_response.status_code = 500
    mock_response._content = b"This is not json"
    mock_response.reason = "Error Reason"
    mock_response.url = url

    mock_session_get.return_value = mock_response

    with pytest.raises(OAAClientError) as e:
        veza_con.api_get("/api/path")

    # should recieve the generic error message
    assert e.value.error == "ERROR"
    assert "Error Reason" in e.value.message
    assert e.value.status_code == 500

@patch.object(requests.Session, "request")
def test_api_get_nonjson_success(mock_session_get):
    # Test that the OAAClient raises the correct error if somehow it gets a successful HTTP response that is not JSON

    test_api_key = "1234"
    url = "https://noreply.vezacloud.com"
    # patch _test_connection to instantiate a connection object
    with patch.object(OAAClient, "_test_connection", return_value=None):
        veza_con = OAAClient(url=url, token=test_api_key)

    # Mock a response with non-JSON data, will force a JSONDecodeError
    mock_response = Response()
    mock_response.status_code = 200
    mock_response._content = b"This is not json"
    mock_response.url = url

    mock_session_get.return_value = mock_response

    with pytest.raises(OAAClientError) as e:
        veza_con.api_get("/api/path")

    # should receive the generic error message
    assert e.value.error == "ERROR"
    assert e.value.message == "Response not JSON"
    assert e.value.status_code == 200

@patch.object(requests.Session, "request")
def test_api_post_error(mock_session_post):
    # Test that the correct OAAClient exception is raised on properly populated

    test_api_key = "1234"
    # patch _test_connection to instantiate a connection object
    with patch.object(OAAClient, "_test_connection", return_value=None):
        veza_con = OAAClient(url="https://noreply.vezacloud.com", token=test_api_key)


    mock_response = Response()
    mock_response.status_code = 400
    error_message = b"""
            {
                "code": "InvalidArgument",
                "message": "Invalid Arguments",
                "request_id": "1091d23a67ad44a63723fc050280e5ae",
                "timestamp": "2022-08-05T19:59:11.508388808Z",
                "details": [
                    {
                    "@type": "type.googleapis.com/google.rpc.BadRequest",
                    "field_violations": [
                        {
                        "field": "name",
                        "description": "Provider with the same name already exists"
                        }
                    ]
                    },
                    {
                    "@type": "type.googleapis.com/errorstatus.v1.UserFacingErrorInfo",
                    "reason": "INVALID_ARGUMENTS",
                    "metadata": {},
                    "message": "Request includes invalid arguments.",
                    "resolution": "Reference error details for the exact field violations."
                    }
                ]
            }
            """
    mock_response._content = error_message

    mock_session_post.return_value = mock_response

    with pytest.raises(OAAClientError) as e:
        veza_con.api_post("/api/path", data={})

    # test that the error is populated propery
    assert e.value.error == "InvalidArgument"
    assert e.value.message == "Invalid Arguments"
    assert e.value.status_code == 400
    assert e.value.details != []
    assert "Provider with the same name already exists" in str(e.value.details)

@patch.object(requests.Session, "request")
def test_api_post_nonjson_error(mock_session_post):
    # Test that the OAAClient correctly handles a non-JSON respponse if error isn't coming from Veza stack

    test_api_key = "1234"
    url = "https://noreply.vezacloud.com"
    # patch _test_connection to instantiate a connection object
    with patch.object(OAAClient, "_test_connection", return_value=None):
        veza_con = OAAClient(url=url, token=test_api_key)

    # Mock a response with non-JSON data, will force a JSONDecodeError
    mock_response = Response()
    mock_response.status_code = 500
    mock_response._content = b"This is not json"
    mock_response.reason = "Error Reason"
    mock_response.url = url

    mock_session_post.return_value = mock_response

    with pytest.raises(OAAClientError) as e:
        veza_con.api_post("/api/path", data={})

    # should recieve the generic error message
    assert e.value.error == "ERROR"
    assert "Error Reason" in e.value.message
    assert e.value.status_code == 500

@patch.object(requests.Session, "request")
def test_api_delete_error(mock_session_delete):
    # Test that the correct OAAClient exception is raised on properly populated

    test_api_key = "1234"
    # patch _test_connection to instantiate a connection object
    with patch.object(OAAClient, "_test_connection", return_value=None):
        veza_con = OAAClient(url="https://noreply.vezacloud.com", token=test_api_key)


    mock_response = Response()
    mock_response.status_code = 404
    error_message = b"""
            {
                "code": "NotFound",
                "message": "Not Found",
                "request_id": "1de5e43499c90f2036cdfe92ed76f58e",
                "timestamp": "2022-08-05T21:06:53.046972349Z",
                "details": [
                    {
                    "@type": "type.googleapis.com/errorstatus.v1.ResourceInfo",
                    "resource_type": "datasource",
                    "resource": "b1e654e7-2104-4180-9dee-2f76e2b52463"
                    },
                    {
                    "@type": "type.googleapis.com/errorstatus.v1.UserFacingErrorInfo",
                    "reason": "NOT_FOUND",
                    "metadata": {},
                    "message": "Requested resource was not found.",
                    "resolution": ""
                    }
                ]
            }
            """
    mock_response._content = error_message
    mock_session_delete.return_value = mock_response

    with pytest.raises(OAAClientError) as e:
        veza_con.api_delete("/api/path")

    # test that the error is populated propery
    assert e.value.error == "NotFound"
    assert e.value.message == "Not Found"
    assert e.value.status_code == 404
    assert e.value.details != []
    assert "Requested resource was not found." in str(e.value.details)

@patch.object(requests.Session, "request")
def test_api_post_delete_error(mock_session_delete):
    # Test that the OAAClient correctly handles a non-JSON response if error isn't coming from Veza stack

    test_api_key = "1234"
    url = "https://noreply.vezacloud.com"
    # patch _test_connection to instantiate a connection object
    with patch.object(OAAClient, "_test_connection", return_value=None):
        veza_con = OAAClient(url=url, token=test_api_key)

    # Mock a response with non-JSON data, will force a JSONDecodeError
    mock_response = Response()
    mock_response.status_code = 500
    mock_response._content = b"This is not json"
    mock_response.reason = "Error Reason"
    mock_response.url = url

    mock_session_delete.return_value = mock_response

    with pytest.raises(OAAClientError) as e:
        veza_con.api_delete("/api/path")

    # should receive the generic error message
    assert e.value.error == "ERROR"
    assert "Error Reason" in e.value.message
    assert e.value.status_code == 500


@patch('oaaclient.client.requests')
@patch.object(OAAClient, "get_provider", return_value={"id": "123"})
@patch.object(OAAClient, "get_data_source", return_value={"id": "123"})
def test_large_payload(mock_requests, mock_get_provider, mock_get_data_source):
    """Test large payload exception

    Assert that a payload that would be larger than 100MB will throw an exception

    """
    test_api_key = "1234"
    url = "https://noreply.vezacloud.com"

    mock_response = Response()
    mock_response.status_code = 200
    mock_response._content = b"""{"id": "123"}"""
    mock_response.url = url

    mock_requests.get.return_value = mock_response
    mock_requests.post.return_value = mock_response

    with patch.object(OAAClient, "_test_connection", return_value=None):
        veza_con = OAAClient(url=url, token=test_api_key)

    # disable compression to make it easier to create a large payload
    veza_con.enable_compression = False

    big = "=" * 100_000_001
    payload = {"data": big}
    with pytest.raises(OAAClientError) as e:
        veza_con.push_metadata("provider_name", "data_source_name", metadata=payload, save_json=False)

    assert e.value.error == "OVERSIZE"
    assert "Payload size exceeds maximum size of 100MB" in e.value.message


@patch('oaaclient.client.requests')
@patch.object(OAAClient, "get_provider", return_value={"id": "123"})
@patch.object(OAAClient, "get_data_source", return_value={"id": "123"})
def test_compression(mock_requests, mock_get_provider, mock_get_data_source):
    """Test large payload exception

    Assert that a payload that would be larger than 100MB will throw an exception

    """
    test_api_key = "1234"
    url = "https://noreply.vezacloud.com"

    mock_response = Response()
    mock_response.status_code = 200
    mock_response._content = b"""{"id": "123"}"""
    mock_response.url = url

    mock_requests.get.return_value = mock_response
    mock_requests.post.return_value = mock_response

    with patch.object(OAAClient, "_test_connection", return_value=None):
        veza_con = OAAClient(url=url, token=test_api_key)

    veza_con.enable_compression = True

    app = generate_app()

    with patch.object(veza_con, "api_post") as post_mock:
        veza_con.push_application("provider_name", "data_source_name", application_object=app, save_json=False)

    assert post_mock.called
    call = post_mock.mock_calls[0]

    # get the payload that was posted
    payload = call.args[1]
    # assert compression_type is set in the payload correctly
    assert payload['compression_type'] == "GZIP"
    # assert that the payload is base64 encoded by trying to decode
    assert base64.b64decode(payload['json_data'])


def test_request_exceptions():
    assert True
    return

def test_exception_hierarchy():
    """Test exception hierarchy

    Ensure that detailed exceptions are captured by the OAAClientError base exception
    """

    with pytest.raises(OAAClientError) as e:
        raise OAAResponseError("test error", message="test")

    assert e is not None
    assert isinstance(e.value, OAAClientError)
    assert isinstance(e.value, OAAResponseError)

    with pytest.raises(OAAClientError) as e:
        raise OAAConnectionError("connection error", message="test")

    assert e is not None
    assert isinstance(e.value, OAAClientError)
    assert isinstance(e.value, OAAConnectionError)


def test_connection_test():
    """Ensure that connection test fails fast with a bad URL

    Test should successfully fail faster than the timeout
    """

    with pytest.raises(OAAConnectionError) as e:
        con = OAAClient(url="https://host.invalid.com", api_key="test123=")

    assert isinstance(e.value, OAAConnectionError)
    # ensure that the connection test failed because of the DNS error
    assert e.value.error == "Unknown host"

@pytest.mark.skipif(not os.getenv("PYTEST_VEZA_HOST"), reason="Test host is not configured")
@pytest.mark.timeout(10)
def test_bad_api_key():
    """Ensure test fails with invalid API key

    Test should successfully fail faster than timeout
    """

    test_deployment = os.getenv("PYTEST_VEZA_HOST", "")
    test_api_key = os.getenv("VEZA_API_KEY", "")

    decoded = base64.b64decode(test_api_key)
    mangled = str(decoded[:4]) + "XXXX"
    test_api_key = base64.b64encode(decoded)
    # test_api_key = test_api_key.replace(test_api_key[:4], "XXXX")

    log.debug(f"Test bad API key value: {test_api_key=}")
    with pytest.raises(OAAClientError) as e:
        con = OAAClient(url=test_deployment, api_key=test_api_key)

    assert isinstance(e.value, OAAClientError)
    assert e.value.status_code == 401


@patch.object(requests.Session, "request")
def test_api_paging(mock_request):

    test_api_key = "1234"
    url = "https://noreply.vezacloud.com"

    with patch.object(OAAClient, "_test_connection", return_value=None):
        veza_con = OAAClient(url=url, token=test_api_key)

    # build some fake pages
    page_1 = b"""{"values": ["1", "2", "3"], "has_more": true, "next_page_token": "page2"}"""
    page_2 = b"""{"values": ["4", "5", "6"], "has_more": true, "next_page_token": "page3"}"""
    page_3 = b"""{"values": ["7", "8"], "has_more": false}"""

    responses = []

    for page in [page_1, page_2, page_3]:
        mock_response = Response()
        mock_response.status_code = 200
        mock_response._content = page
        mock_response.url = url

        responses.append(mock_response)

    mock_request.side_effect = responses

    providers = veza_con.get_provider_list()

    assert providers == ["1", "2", "3", "4", "5", "6", "7", "8"]

    # assert that it made three request calls to get through all the pages
    assert mock_request.call_count == 3

    # check that the page_token parame is set correctly on each of the three expected API calls
    call_1 = mock_request.call_args_list[0]
    assert "page_size" in call_1.kwargs.get("params")

    call_2 = mock_request.call_args_list[1]
    assert "page_token=page2" in call_2.kwargs.get("params")
    assert "page_size" in call_2.kwargs.get("params")

    call_3 = mock_request.call_args_list[0]
    assert "page_size" in call_3.kwargs.get("params")

def test_allowed_characters():

    test_api_key = "1234"
    url = "https://noreply.vezacloud.com"

    with patch.object(OAAClient, "_test_connection", return_value=None):
        veza_con = OAAClient(url=url, token=test_api_key)

    with pytest.raises(ValueError) as e:
        veza_con.create_provider("invalid/characters", "application")

    assert e.value is not None
    assert "Provider name contains invalid characters" in str(e.value)

    with pytest.raises(ValueError) as e:
        veza_con.create_data_source("invalid/characters", provider_id="1234")

    assert e.value is not None
    assert "Data source name contains invalid characters" in str(e.value)

    with patch.object(OAAClient, "api_post", return_value={}):
        provider = veza_con.create_provider("allowed 1234 @#$%&*:()!,_'\" =.-", "application")

    assert provider == {}