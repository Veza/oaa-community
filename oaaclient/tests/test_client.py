"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

from requests.exceptions import JSONDecodeError as RequestsJSONDecodeError
from requests.models import Response
from unittest.mock import MagicMock, patch
import base64
import json
import logging
import os
import pytest
import sys
import uuid

from oaaclient.client import OAAClient, OAAClientError
from generate_app import generate_app
from generate_idp import generate_idp

@pytest.fixture
def veza_con():
    test_deployment = os.getenv("PYTEST_VEZA_HOST")
    test_api_key = os.getenv("VEZA_API_KEY")
    assert test_api_key is not None

    veza_con = OAAClient(url=test_deployment, token=test_api_key)

    return veza_con

@pytest.mark.skipif(not os.getenv("PYTEST_VEZA_HOST"), reason="Test host is not configured")
def test_client_provider(veza_con):
    """ tests for client provider management code using live API """
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
    print(data_source_list)
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
    with patch.object(OAAClient, "get_provider_list", return_value=[]):
        veza_con = OAAClient(url=url, token=test_api_key)

        assert veza_con.url == "https://noreply.vezacloud.com"

@patch('oaaclient.client.requests')
def test_api_get_error(mock_requests):
    # Test that the correct OAAClient exception is raised on properly populated

    test_api_key = "1234"
    # patch get_provider_list to instantiate a connection object
    with patch.object(OAAClient, "get_provider_list", return_value=[]):
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
    mock_requests.get.return_value = mock_response

    with pytest.raises(OAAClientError) as e:
        veza_con.api_get("/api/path")

    # test that the error is populated propery
    assert e.value.error == "Internal"
    assert e.value.message == "Internal Server Error, please retry and if the error persists contact support at support@veza.com"
    assert e.value.status_code == 400
    assert len(e.value.details) == 1
    assert "Internal server error." in str(e.value.details)

@patch('oaaclient.client.requests')
def test_api_get_nonjson_error(mock_requests):
    # Test that the OAAClient correctly handles a non-JSON respponse if error isn't coming from Veza stack

    test_api_key = "1234"
    url = "https://noreply.vezacloud.com"
    # patch get_provider_list to instantiate a connection object
    with patch.object(OAAClient, "get_provider_list", return_value=[]):
        veza_con = OAAClient(url=url, token=test_api_key)

    # Mock a response with non-JSON data, will force a JSONDecodeError
    mock_response = Response()
    mock_response.status_code = 500
    mock_response._content = b"This is not json"
    mock_response.reason = "Error Reason"
    mock_response.url = url

    mock_requests.get.return_value = mock_response

    with pytest.raises(OAAClientError) as e:
        veza_con.api_get("/api/path")

    # should recieve the generic error message
    assert e.value.error == "ERROR"
    assert "Error Reason" in e.value.message
    assert e.value.status_code == 500


@patch('oaaclient.client.requests')
def test_api_post_error(mock_requests):
    # Test that the correct OAAClient exception is raised on properly populated

    test_api_key = "1234"
    # patch get_provider_list to instantiate a connection object
    with patch.object(OAAClient, "get_provider_list", return_value=[]):
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

    mock_requests.post.return_value = mock_response

    with pytest.raises(OAAClientError) as e:
        veza_con.api_post("/api/path", data={})

    # test that the error is populated propery
    assert e.value.error == "InvalidArgument"
    assert e.value.message == "Invalid Arguments"
    assert e.value.status_code == 400
    assert e.value.details != []
    assert "Provider with the same name already exists" in str(e.value.details)

@patch('oaaclient.client.requests')
def test_api_post_nonjson_error(mock_requests):
    # Test that the OAAClient correctly handles a non-JSON respponse if error isn't coming from Veza stack

    test_api_key = "1234"
    url = "https://noreply.vezacloud.com"
    # patch get_provider_list to instantiate a connection object
    with patch.object(OAAClient, "get_provider_list", return_value=[]):
        veza_con = OAAClient(url=url, token=test_api_key)

    # Mock a response with non-JSON data, will force a JSONDecodeError
    mock_response = Response()
    mock_response.status_code = 500
    mock_response._content = b"This is not json"
    mock_response.reason = "Error Reason"
    mock_response.url = url

    mock_requests.post.return_value = mock_response

    with pytest.raises(OAAClientError) as e:
        veza_con.api_post("/api/path", data={})

    # should recieve the generic error message
    assert e.value.error == "ERROR"
    assert "Error Reason" in e.value.message
    assert e.value.status_code == 500

@patch('oaaclient.client.requests')
def test_api_delete_error(mock_requests):
    # Test that the correct OAAClient exception is raised on properly populated

    test_api_key = "1234"
    # patch get_provider_list to instantiate a connection object
    with patch.object(OAAClient, "get_provider_list", return_value=[]):
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
    mock_requests.delete.return_value = mock_response

    with pytest.raises(OAAClientError) as e:
        veza_con.api_delete("/api/path")

    # test that the error is populated propery
    assert e.value.error == "NotFound"
    assert e.value.message == "Not Found"
    assert e.value.status_code == 404
    assert e.value.details != []
    assert "Requested resource was not found." in str(e.value.details)

@patch('oaaclient.client.requests')
def test_api_post_delete_error(mock_requests):
    # Test that the OAAClient correctly handles a non-JSON respponse if error isn't coming from Veza stack

    test_api_key = "1234"
    url = "https://noreply.vezacloud.com"
    # patch get_provider_list to instantiate a connection object
    with patch.object(OAAClient, "get_provider_list", return_value=[]):
        veza_con = OAAClient(url=url, token=test_api_key)

    # Mock a response with non-JSON data, will force a JSONDecodeError
    mock_response = Response()
    mock_response.status_code = 500
    mock_response._content = b"This is not json"
    mock_response.reason = "Error Reason"
    mock_response.url = url

    mock_requests.delete.return_value = mock_response

    with pytest.raises(OAAClientError) as e:
        veza_con.api_delete("/api/path")

    # should recieve the generic error message
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

    veza_con = OAAClient(url=url, api_key=test_api_key)

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

    veza_con = OAAClient(url=url, api_key=test_api_key)
    veza_con.enable_compression = True

    app = generate_app()

    with patch.object(veza_con, "_OAAClient__perform_post") as post_mock:
        veza_con.push_application("provider_name", "data_source_name", application_object=app, save_json=False)

    assert post_mock.called
    call = post_mock.mock_calls[0]

    # get the payload that was posted
    payload = call.args[1]
    # assert compression_type is set in the payload correctly
    assert payload['compression_type'] == "GZIP"
    # assert that the payload is base64 encoded by trying to decode
    assert base64.b64decode(payload['json_data'])


