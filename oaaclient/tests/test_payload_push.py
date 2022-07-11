import os
import pytest
import uuid
import time

from oaaclient.client import OAAClient, OAAClientError
import oaaclient.utils as utils

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
@pytest.mark.timeout(120)
def test_payload_push(veza_con):

    app = generate_app()
    provider_name = f"Pytest Custom Apps {uuid.uuid4()}"
    data_source_name = "pytest-test_payload_push"
    provider = veza_con.get_provider(provider_name)
    assert provider is None

    provider = veza_con.create_provider(provider_name, "application")

    b64_icon = utils.encode_icon_file("tests/oaa_icon.png")
    veza_con.update_provider_icon(provider_id=provider['id'], base64_icon=b64_icon)

    response = veza_con.push_application(provider_name,
                                           data_source_name=data_source_name,
                                           application_object=app
                                           )
    if not response:
        assert False

    # Veza API always returns the warnings key, the list may be empty, in this case we expect it not to be
    assert "warnings" in response
    # since our payload includes fake identities expect warnings about not matching identities
    assert response["warnings"] is not None
    for warning in response["warnings"]:
        assert warning['message'].startswith("Cannot find identity by names")

    data_source = veza_con.get_data_source(data_source_name, provider_id=provider["id"])
    print(data_source)
    while True:
        data_source = veza_con.get_data_source(data_source_name, provider_id=provider["id"])
        if data_source["status"] == "SUCCESS":
            break
        time.sleep(2)

    veza_con.delete_provider(provider["id"])

@pytest.mark.skipif(not os.getenv("PYTEST_VEZA_HOST"), reason="Test host is not configured")
def test_bad_payload(veza_con):

    app = generate_app()

    provider_name = f"Pytest Custom Apps {uuid.uuid4()}"

    provider = veza_con.get_provider(provider_name)
    assert provider is None
    provider = veza_con.create_provider(provider_name, "application")

    payload = app.get_payload()
    # break the payload so it will throw an error
    payload['applications'][0]["bad_property"] = "This will break things"

    with pytest.raises(OAAClientError) as e:
        response = veza_con.push_metadata(provider_name=provider_name, data_source_name="pytest-test_payload_push", metadata=payload)

    assert e.value.message is not None
    assert e.value.details is not None
    assert e.value.status_code == 400

    veza_con.delete_provider(provider["id"])

    return


@pytest.mark.skipif(not os.getenv("PYTEST_VEZA_HOST"), reason="Test host is not configured")
@pytest.mark.timeout(120)
def test_idp_payload_push(veza_con):

    idp = generate_idp()

    provider_name = f"Pytest Custom IdP {uuid.uuid4()}"
    data_source_name = "pytest-test_idp_push"
    provider = veza_con.get_provider(provider_name)
    if not provider:
        provider = veza_con.create_provider(provider_name, "identity_provider")

    response = veza_con.push_application(provider_name,
                                           data_source_name=data_source_name,
                                           application_object=idp
                                           )
    if not response:
        assert False

    # print out any warnigns from the push for debugging puproses, warnings are not a failure, warnings will include
    # being unable to find fake identities
    if response.get("warnings", None):
        print("Push warnings:")
        for e in response["warnings"]:
            print(f"  - {e}")

    while True:
        data_source = veza_con.get_data_source(data_source_name, provider_id=provider["id"])
        print(data_source)
        if data_source["status"] == "SUCCESS":
            break
        time.sleep(2)

    veza_con.delete_provider(provider["id"])

    return
