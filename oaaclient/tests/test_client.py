"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by a the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

from requests import delete
from unittest.mock import patch
import os
import pytest
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


# @patch("oaaclient.client.get_provider_list")
@pytest.mark.parametrize("url",["https://noreply.vezacloud.com", "noreply.vezacloud.com", "noreply.vezacloud.com/", "https://noreply.vezacloud.com/"])
def test_url_formatter(url):
    test_api_key = "1234"
    with patch.object(OAAClient, "get_provider_list", return_value=[]):
        veza_con = OAAClient(url=url, token=test_api_key)

        assert veza_con.url == "https://noreply.vezacloud.com"
