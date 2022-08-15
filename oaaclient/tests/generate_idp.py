"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

from oaaclient.templates import CustomIdPProvider, OAAPropertyType, IdPProviderType


def generate_idp():
    """ generates a complete OAA custom IDP app """

    idp = CustomIdPProvider("Pytest IdP", idp_type="pytest", domain="example.com", description="Pytest Test IdP")

    idp.property_definitions.define_user_property("contractor", OAAPropertyType.BOOLEAN)
    idp.property_definitions.define_user_property("parking_spaces", OAAPropertyType.NUMBER)
    idp.property_definitions.define_user_property("cube_number", OAAPropertyType.STRING)
    idp.property_definitions.define_user_property("nick_names", OAAPropertyType.STRING_LIST)
    idp.property_definitions.define_user_property("birthday", OAAPropertyType.TIMESTAMP)

    idp.property_definitions.define_group_property("owner", OAAPropertyType.STRING)

    idp.property_definitions.define_domain_property("region", OAAPropertyType.STRING)

    idp.domain.set_property("region", "US")

    user0001 = idp.add_user("user0001", "User 0001", "user001@example.com", "0001")
    user0002 = idp.add_user("user0002", "User 0002", "user002@example.com", "0002")
    idp.add_user("user0003", "User 0003", "user003@example.com", "0003")
    idp.add_user("user0004", "User 0004", "user004@example.com", "0004")
    idp.add_user("user0005", "User 0005", "user005@example.com", "0005")
    idp.add_user("user0006", "User 0006", "user006@example.com", "0006")

    user0001.department = "Quality Assurance"
    user0001.is_active = True
    user0001.is_guest = False
    user0001.manager_id = "0003"
    user0001.set_property("contractor", False)
    user0001.set_property("parking_spaces", 1)
    user0001.set_property("cube_number", "East-224")
    user0001.set_property("nick_names", ["The One", "One Dude"])
    user0001.set_property("birthday", "2001-01-01T01:01:01.001Z")
    user0001.set_source_identity("user0001@corp.example.com", IdPProviderType.OKTA)
    user0001.add_assumed_role_arns(["arn:aws:iam::123456789:role/BackEnd"])

    user0002.department = "Sales"
    user0002.is_active = False
    user0002.is_guest = True
    user0002.set_source_identity("user0002@corp.example.com", IdPProviderType.AZURE_AD)

    group001 = idp.add_group("group001", "Group 001", "g001")
    group001.set_property("owner", "somebody")
    group001.add_assumed_role_arns(["arn:aws:iam::123456789:role/Group001"])

    idp.add_group("group002", "Group 002", "g002")
    idp.add_group("group003", "Group 003", "g003")
    idp.add_group("group004", "Group 004", "g004")

    idp.users["user0001"].add_groups(["g001"])
    idp.users["user0002"].add_groups(["g001", "g002"])
    idp.users["user0003"].add_groups(["g002", "g003"])
    idp.users["user0004"].add_groups(["g002"])
    idp.users["user0005"].add_groups(["g003"])

    return idp


GENERATED_IDP_PAYLOAD = """
{
  "custom_property_definition": {
    "domain_properties": {
      "region": "STRING"
    },
    "user_properties": {
      "contractor": "BOOLEAN",
      "parking_spaces": "NUMBER",
      "cube_number": "STRING",
      "nick_names": "STRING_LIST",
      "birthday": "TIMESTAMP"
    },
    "group_properties": {
      "owner": "STRING"
    }
  },
  "name": "Pytest IdP",
  "idp_type": "pytest",
  "domains": [
    {
      "name": "example.com",
      "tags": [],
      "custom_properties": {
        "region": "US"
      }
    }
  ],
  "users": [
    {
      "name": "user0001",
      "email": "user001@example.com",
      "identity": "0001",
      "full_name": "User 0001",
      "department": "Quality Assurance",
      "is_active": true,
      "is_guest": false,
      "manager_id": "0003",
      "groups": [
        {
          "identity": "g001"
        }
      ],
      "assumed_role_arns": [
        {
          "identity": "arn:aws:iam::123456789:role/BackEnd"
        }
      ],
      "source_identity": {
        "identity": "user0001@corp.example.com",
        "provider_type": "okta"
      },
      "tags": [],
      "custom_properties": {
        "contractor": false,
        "parking_spaces": 1,
        "cube_number": "East-224",
        "nick_names": [
          "The One",
          "One Dude"
        ],
        "birthday": "2001-01-01T01:01:01.001Z"
      }
    },
    {
      "name": "user0002",
      "email": "user002@example.com",
      "identity": "0002",
      "full_name": "User 0002",
      "department": "Sales",
      "is_active": false,
      "is_guest": true,
      "manager_id": null,
      "groups": [
        {
          "identity": "g001"
        },
        {
          "identity": "g002"
        }
      ],
      "assumed_role_arns": [],
      "source_identity": {
        "identity": "user0002@corp.example.com",
        "provider_type": "azure_ad"
      },
      "tags": [],
      "custom_properties": {}
    },
    {
      "name": "user0003",
      "email": "user003@example.com",
      "identity": "0003",
      "full_name": "User 0003",
      "department": null,
      "is_active": null,
      "is_guest": null,
      "manager_id": null,
      "groups": [
        {
          "identity": "g002"
        },
        {
          "identity": "g003"
        }
      ],
      "assumed_role_arns": [],
      "source_identity": null,
      "tags": [],
      "custom_properties": {}
    },
    {
      "name": "user0004",
      "email": "user004@example.com",
      "identity": "0004",
      "full_name": "User 0004",
      "department": null,
      "is_active": null,
      "is_guest": null,
      "manager_id": null,
      "groups": [
        {
          "identity": "g002"
        }
      ],
      "assumed_role_arns": [],
      "source_identity": null,
      "tags": [],
      "custom_properties": {}
    },
    {
      "name": "user0005",
      "email": "user005@example.com",
      "identity": "0005",
      "full_name": "User 0005",
      "department": null,
      "is_active": null,
      "is_guest": null,
      "manager_id": null,
      "groups": [
        {
          "identity": "g003"
        }
      ],
      "assumed_role_arns": [],
      "source_identity": null,
      "tags": [],
      "custom_properties": {}
    },
    {
      "name": "user0006",
      "email": "user006@example.com",
      "identity": "0006",
      "full_name": "User 0006",
      "department": null,
      "is_active": null,
      "is_guest": null,
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
      "identity": "g001",
      "full_name": "Group 001",
      "is_security_group": null,
      "assumed_role_arns": [
        {
          "identity": "arn:aws:iam::123456789:role/Group001"
        }
      ],
      "tags": [],
      "custom_properties": {
        "owner": "somebody"
      }
    },
    {
      "name": "group002",
      "identity": "g002",
      "full_name": "Group 002",
      "is_security_group": null,
      "assumed_role_arns": [],
      "tags": [],
      "custom_properties": {}
    },
    {
      "name": "group003",
      "identity": "g003",
      "full_name": "Group 003",
      "assumed_role_arns": [],
      "is_security_group": null,
      "tags": [],
      "custom_properties": {}
    },
    {
      "name": "group004",
      "identity": "g004",
      "full_name": "Group 004",
      "is_security_group": null,
      "assumed_role_arns": [],
      "tags": [],
      "custom_properties": {}
    }
  ]
}
"""
