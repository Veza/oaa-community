"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

import pytest
import json

from oaaclient.templates import CustomIdPProvider, OAATemplateException
from generate_idp import generate_idp, GENERATED_IDP_PAYLOAD


def test_custom_idp():
    idp_name = "test"
    idp_type = "test_idp"
    idp = CustomIdPProvider(idp_name, idp_type, "pytest test IdP")

    # create some users
    user001 = idp.add_user("user001")
    user001.department = "Quality Assurance"
    user001.department = "Quality Assurance"
    user001.manager_id = "user003_identity"
    user002 = idp.add_user("user002")
    user003 = idp.add_user("user003", identity="user003_identity")
    user004 = idp.add_user("user004")

    user003.is_guest = False
    user004.is_guest = True

    # create groups
    idp.add_group("group001")
    idp.add_group("group002")
    idp.add_group("group003", identity="group003_identity")

    # add users to groups
    user001.add_groups(["group001"])
    user002.add_groups(["group002"])
    idp.users["user003"].add_groups(["group001", "group002"])

    user001.add_assumed_role_arns(["arn:aws:iam::123456789012:role/role001", "arn:aws:iam::123456789012:role/role002"])
    # test adding a role multiple times is deduplicated property
    user001.add_assumed_role_arns(["arn:aws:iam::123456789012:role/role001"])
    user002.add_assumed_role_arns(["arn:aws:iam::123456789012:role/role001"])

    payload = idp.get_payload()
    print(json.dumps(payload, indent=2))

    expected_result = json.loads(TEST_CUSTOM_IDP_RESULT)
    assert payload == expected_result


def test_generate_idp():
    idp = generate_idp()
    payload = idp.get_payload()
    print(json.dumps(payload, indent=2))

    assert payload == json.loads(GENERATED_IDP_PAYLOAD)


def test_custom_idp_exceptions():
    idp_name = "test"
    idp_type = "test_idp"
    idp = CustomIdPProvider(idp_name, idp_type, "pytest test IdP")

    # assert duplicate user raises exception
    user_name = "duplicate001"
    idp.add_user(user_name)
    with pytest.raises(OAATemplateException) as e:
        idp.add_user(user_name)
    assert user_name in e.value.message

    # asert duplicate group raises exception
    group_name = "dupgroup"
    idp.add_group(group_name)
    with pytest.raises(OAATemplateException) as e:
        idp.add_group(group_name)
    assert group_name in e.value.message

    # assert add_assumed_role_arns enforces list
    test_user = idp.add_user("test001")
    with pytest.raises(OAATemplateException) as e:
        test_user.add_assumed_role_arns("arn:aws:iam::123456789012:role/role001")
    assert e.value.message == "arns must be of type list"

    with pytest.raises(OAATemplateException) as e:
        test_user.add_groups("group01")
    assert e.value.message == "group_identities must be list"

    with pytest.raises(OAATemplateException) as e:
        test_user.set_source_identity("bob", "somestring")
    assert e.value.message == "provider_type must be IdPProviderType enum"


# expected paylods
TEST_CUSTOM_IDP_RESULT = """
{
  "custom_property_definition": {
    "domain_properties": {},
    "user_properties": {},
    "group_properties": {}
  },
  "name": "test",
  "idp_type": "test_idp",
  "domains": [
    {
      "name": "pytest test IdP",
      "tags": [],
      "custom_properties": {}
    }
  ],
  "users": [
    {
      "name": "user001",
      "email": null,
      "identity": "user001",
      "full_name": null,
      "department": "Quality Assurance",
      "is_active": null,
      "is_guest": null,
      "manager_id": "user003_identity",
      "groups": [
        {
          "identity": "group001"
        }
      ],
      "assumed_role_arns": [
        {
          "identity": "arn:aws:iam::123456789012:role/role001"
        },
        {
          "identity": "arn:aws:iam::123456789012:role/role002"
        }
      ],
      "source_identity": null,
      "tags": [],
      "custom_properties": {}
    },
    {
      "name": "user002",
      "email": null,
      "identity": "user002",
      "full_name": null,
      "department": null,
      "is_active": null,
      "is_guest": null,
      "manager_id": null,
      "groups": [
        {
          "identity": "group002"
        }
      ],
      "assumed_role_arns": [
        {
          "identity": "arn:aws:iam::123456789012:role/role001"
        }
      ],
      "source_identity": null,
      "tags": [],
      "custom_properties": {}
    },
    {
      "name": "user003",
      "email": null,
      "identity": "user003_identity",
      "full_name": null,
      "department": null,
      "is_active": null,
      "is_guest": false,
      "manager_id": null,
      "groups": [
        {
          "identity": "group001"
        },
        {
          "identity": "group002"
        }
      ],
      "assumed_role_arns": [],
      "source_identity": null,
      "tags": [],
      "custom_properties": {}
    },
    {
      "name": "user004",
      "email": null,
      "identity": "user004",
      "full_name": null,
      "department": null,
      "is_active": null,
      "is_guest": true,
      "manager_id": null,
      "groups": [],
      "assumed_role_arns": [],
      "source_identity": null,
      "tags": [],
      "custom_properties": {}
    }
  ],
  "groups": [
    {
      "name": "group001",
      "identity": "group001",
      "full_name": null,
      "is_security_group": null,
      "assumed_role_arns": [],
      "tags": [],
      "custom_properties": {}
    },
    {
      "name": "group002",
      "identity": "group002",
      "full_name": null,
      "is_security_group": null,
      "assumed_role_arns": [],
      "tags": [],
      "custom_properties": {}
    },
    {
      "name": "group003",
      "identity": "group003_identity",
      "full_name": null,
      "is_security_group": null,
      "assumed_role_arns": [],
      "tags": [],
      "custom_properties": {}
    }
  ]
}
"""
