import pytest
import os

from oaaclient.client import OAAClient, OAAClientError
from generate_app import generate_app
from generate_idp import generate_idp


@pytest.mark.skipif(not os.getenv("PYTEST_VEZA_HOST"), reason="Test host is not configured")
def test_payload_push():
    test_deployment = os.getenv("PYTEST_VEZA_HOST")
    test_api_key = os.getenv("VEZA_API_KEY")
    assert test_api_key is not None

    app = generate_app()

    # print(json.dumps(payload, indent=2))
    # prepare for push
    veza_con = OAAClient(url=test_deployment, token=test_api_key)
    assert veza_con is not None

    provider_name = "Pytest Custom Apps"
    provider = veza_con.get_provider(provider_name)
    if not provider:
        provider = veza_con.create_provider(provider_name, "application")

    response = veza_con.push_application(provider_name,
                                           data_source_name="pytest-test_payload_push",
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

    payload = app.get_payload()
    # break the payload so it will throw an error
    payload['applications'][0]["bad_property"] = "This will break things"

    with pytest.raises(OAAClientError) as e:
        response = veza_con.push_metadata(provider_name=provider_name, data_source_name="pytest-test_payload_push", metadata=payload)

    assert e.value.message is not None
    assert e.value.details is not None
    assert e.value.status_code == 400

    return


@pytest.mark.skipif(not os.getenv("PYTEST_VEZA_HOST"), reason="Test host is not configured")
def test_idp_payload_push():
    test_deployment = os.getenv("PYTEST_VEZA_HOST")
    test_api_key = os.getenv("VEZA_API_KEY")
    assert test_api_key is not None

    idp = generate_idp()

    veza_con = OAAClient(url=test_deployment, token=test_api_key)
    assert veza_con is not None

    provider_name = "Pytest Custom IdP"
    provider = veza_con.get_provider(provider_name)
    if not provider:
        provider = veza_con.create_provider(provider_name, "identity_provider")

    response = veza_con.push_application(provider_name,
                                           data_source_name="pytest-test_idp_push",
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

    return
