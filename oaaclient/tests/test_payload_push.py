"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

import os
import pytest
import uuid
import time

from oaaclient.client import OAAClient, OAAClientError
import oaaclient.utils as utils

from generate_app import generate_app
from generate_idp import generate_idp
from generate_app_id_mapping import generate_app_id_mapping

# set the timeout for the push tests, if the the datasource does not parse
TEST_TIMEOUT = os.getenv("OAA_PUSH_TIMEOUT", 300)


@pytest.mark.skipif(not os.getenv("PYTEST_VEZA_HOST"), reason="Test host is not configured")
@pytest.mark.timeout(TEST_TIMEOUT)
def test_payload_push(veza_con, app_provider):
    # make sure compression is disabled
    veza_con.enable_compression = False
    app = generate_app()

    data_source_name = os.environ.get('PYTEST_CURRENT_TEST').replace("/", "-")

    b64_icon = utils.encode_icon_file("tests/oaa_icon.png")
    veza_con.update_provider_icon(provider_id=app_provider['id'], base64_icon=b64_icon)

    response = veza_con.push_application(app_provider['name'],
                                           data_source_name=data_source_name,
                                           application_object=app
                                           )
    if not response:
        assert False

    # Veza API always returns the warnings key, the list may be empty, in this case we expect it not to be
    assert "warnings" in response
    # since our payload includes fake identities expect warnings about not matching identities
    assert response["warnings"] is not None
    assert len(response["warnings"]) == 5
    for warning in response["warnings"]:
        if "Role is missing permission" in warning.get("message", ""):
            pass
        elif "Cannot find identity by names" in warning.get("message", ""):
            pass
        else:
            assert False, "Got unexpected warning from response"

    data_source = veza_con.get_data_source(data_source_name, provider_id=app_provider["id"])
    while True:
        data_source = veza_con.get_data_source(data_source_name, provider_id=app_provider["id"])
        if data_source["status"] == "PENDING":
            time.sleep(4)
        elif data_source["status"] == "SUCCESS":
            break
        else:
            print(data_source)
            assert False, "Datasource parsing failure"


@pytest.mark.skipif(not os.getenv("PYTEST_VEZA_HOST"), reason="Test host is not configured")
@pytest.mark.timeout(TEST_TIMEOUT)
def test_payload_push_compressed(veza_con, app_provider):
    # enable compression
    veza_con.enable_compression = True
    app = generate_app()
    data_source_name = os.environ.get('PYTEST_CURRENT_TEST').replace("/", "-")

    b64_icon = utils.encode_icon_file("tests/oaa_icon.png")
    veza_con.update_provider_icon(provider_id=app_provider['id'], base64_icon=b64_icon)

    response = veza_con.push_application(app_provider['name'],
                                           data_source_name=data_source_name,
                                           application_object=app
                                           )
    if not response:
        assert False

    # Veza API always returns the warnings key, the list may be empty, in this case we expect it not to be
    assert "warnings" in response
    # since our payload includes fake identities expect warnings about not matching identities
    assert response["warnings"] is not None
    assert len(response["warnings"]) == 5
    for warning in response["warnings"]:
        if "Role is missing permission" in warning.get("message", ""):
            pass
        elif "Cannot find identity by names" in warning.get("message", ""):
            pass
        else:
            assert False, "Got unexpected warning from response"

    data_source = veza_con.get_data_source(data_source_name, provider_id=app_provider["id"])
    while True:
        data_source = veza_con.get_data_source(data_source_name, provider_id=app_provider["id"])
        if data_source["status"] == "PENDING":
            time.sleep(4)
        elif data_source["status"] == "SUCCESS":
            break
        else:
            print(data_source)
            assert False, "Datasource parsing failure"



@pytest.mark.skipif(not os.getenv("PYTEST_VEZA_HOST"), reason="Test host is not configured")
@pytest.mark.timeout(TEST_TIMEOUT)
def test_payload_push_id_mapping(veza_con, app_provider):
    """ test for app payload where identities are mapped by id instead of name """

    app = generate_app_id_mapping()
    data_source_name = os.environ.get('PYTEST_CURRENT_TEST').replace("/", "-")

    b64_icon = utils.encode_icon_file("tests/oaa_icon.png")
    veza_con.update_provider_icon(provider_id=app_provider['id'], base64_icon=b64_icon)

    response = None
    try:
        response = veza_con.push_application(app_provider['name'],
                                            data_source_name=data_source_name,
                                            application_object=app
                                            )
    except OAAClientError as e:
        print(e)
        print(e.details)
        assert False

    if not response:
        assert False

    # Veza API always returns the warnings key, the list may be empty, in this case we expect it not to be
    assert "warnings" in response
    # since our payload includes fake identities expect warnings about not matching identities
    assert response["warnings"] is not None
    for warning in response["warnings"]:
        assert warning['message'].startswith("Cannot find identity by names")

    data_source = veza_con.get_data_source(data_source_name, provider_id=app_provider["id"])
    while True:
        data_source = veza_con.get_data_source(data_source_name, provider_id=app_provider["id"])
        if data_source["status"] == "PENDING":
            time.sleep(4)
        elif data_source["status"] == "SUCCESS":
            break
        else:
            print(data_source)
            assert False, "Datasource parsing failure"


@pytest.mark.skipif(not os.getenv("PYTEST_VEZA_HOST"), reason="Test host is not configured")
def test_bad_payload(veza_con, app_provider):

    app = generate_app()
    payload = app.get_payload()
    # break the payload so it will throw an error
    payload['applications'][0]["bad_property"] = "This will break things"

    data_source_name = os.environ.get('PYTEST_CURRENT_TEST').replace("/", "-")

    with pytest.raises(OAAClientError) as e:
        response = veza_con.push_metadata(provider_name=app_provider['name'], data_source_name=data_source_name, metadata=payload)

    assert e.value.message is not None
    assert e.value.details is not None
    assert e.value.status_code == 400

    return


@pytest.mark.skipif(not os.getenv("PYTEST_VEZA_HOST"), reason="Test host is not configured")
@pytest.mark.timeout(TEST_TIMEOUT)
def test_idp_payload_push(veza_con, idp_provider):

    idp = generate_idp()

    data_source_name = os.environ.get('PYTEST_CURRENT_TEST').replace("/", "-")
    response = veza_con.push_application(idp_provider['name'],
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
        data_source = veza_con.get_data_source(data_source_name, provider_id=idp_provider["id"])
        if data_source["status"] == "PENDING":
            time.sleep(2)
        elif data_source["status"] == "SUCCESS":
            break
        else:
            print(data_source)
            assert False, "Datasource parsing failure"

    return
