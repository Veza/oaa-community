import pytest
import uuid
import os
from oaaclient.client import OAAClient, OAAClientError

@pytest.fixture(scope="module")
def veza_con():
    test_deployment = os.getenv("PYTEST_VEZA_HOST")
    test_api_key = os.getenv("VEZA_API_KEY")
    assert test_api_key is not None

    veza_con = OAAClient(url=test_deployment, token=test_api_key)

    yield veza_con

    del veza_con

@pytest.fixture(scope="module")
def app_provider(veza_con):
    """Custom Application Provider

    Yields a custom application provider that can be used for any test that push to an application,
    deletes the provider after yield

    Args:
        veza_con (_type_): _description_

    Yields:
        _type_: _description_
    """
    provider_name = f"Pytest Custom Apps {uuid.uuid4()}"
    provider = veza_con.create_provider(provider_name, "application")
    yield provider

    veza_con.delete_provider(provider["id"])

@pytest.fixture(scope="module")
def idp_provider(veza_con):
    """Custom Application Provider

    Yields a custom application provider that can be used for any test that push to an application,
    deletes the provider after yield

    Args:
        veza_con (_type_): _description_

    Yields:
        _type_: _description_
    """
    provider_name = f"Pytest IdP {uuid.uuid4()}"
    provider = veza_con.create_provider(provider_name, "identity_provider")
    yield provider

    veza_con.delete_provider(provider["id"])