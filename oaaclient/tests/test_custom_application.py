"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

import pytest
import json
import os

from oaaclient.templates import CustomApplication, CustomPermission, OAAPermission, OAAIdentityType, OAATemplateException, Tag, OAAPropertyType
from generate_app import generate_app, GENERATED_APP_PAYLOAD
from generate_app_id_mapping import generate_app_id_mapping, GENERATED_APP_ID_MAPPINGS_PAYLOAD


def test_instantiate():
    custom_app = CustomApplication(name="testapp", application_type="pytest", description="This is a test")
    custom_app.define_custom_permission(CustomPermission("write", [OAAPermission.DataWrite]))
    assert custom_app is not None

    payload = custom_app.get_payload()
    assert isinstance(payload['applications'], list)
    assert len(payload['applications']) == 1
    app_dict = payload['applications'][0]
    assert isinstance(app_dict, dict)
    assert "name" in app_dict and app_dict["name"] == "testapp"
    assert "application_type" in app_dict and app_dict["application_type"] == "pytest"
    assert "custom_properties" in app_dict and isinstance(app_dict["custom_properties"], dict)
    assert "local_groups" in app_dict and isinstance(app_dict["local_groups"], list)
    assert "local_users" in app_dict and isinstance(app_dict["local_users"], list)
    assert "resources" in app_dict and isinstance(app_dict["resources"], list)

    assert isinstance(payload['permissions'], list)

    assert isinstance(payload['identity_to_permissions'], list)


def test_simple_app():
    custom_app = CustomApplication(name="testapp", application_type="pytest", description="This is a test")

    # add resources
    custom_resources = [{"name": "resource1", "resource_type": "rtype1", "description": "First resource"},
                        {"name": "resource2", "resource_type": "rtype1", "description": "Second resource"},
                        {"name": "resource3", "resource_type": "rtype1", "description": "Third resource"},
                        {"name": "resource4", "resource_type": "rtype1", "description": None}
                        ]

    for resource in custom_resources:
        custom_app.add_resource(name=resource['name'], resource_type=resource['resource_type'], description=resource['description'])

    custom_app.add_tag("AppTag", value="test")

    # create custom permissions
    custom_app.define_custom_permission(CustomPermission("read", [OAAPermission.DataRead, OAAPermission.MetadataRead]))
    custom_app.define_custom_permission(CustomPermission("write", [OAAPermission.DataWrite, OAAPermission.MetadataWrite]))
    custom_app.define_custom_permission(CustomPermission("meta", [OAAPermission.NonData, OAAPermission.MetadataRead]))

    # add users, groups, roles
    custom_app.add_local_user(name="user1")
    custom_app.local_users['user1'].add_tag("mytag")
    custom_app.local_users['user1'].add_tag("mytag")  # test tag deduplication
    custom_app.add_local_user(name="user2", identities="user2@pytest.com")

    custom_app.add_local_group("group1")
    custom_app.local_groups["group1"].add_tag("tag1")
    custom_app.add_local_group("group2")
    custom_app.add_local_user(name="user3", groups="group1")
    custom_app.add_local_user(name="user4", groups=["group1", "group2"])

    custom_app.add_local_user(name="user5")

    custom_app.add_idp_identity("okta_user1")

    # define local role
    custom_app.add_local_role("admin")
    custom_app.local_roles["admin"].add_permissions(["read", "write", "meta"])
    custom_app.add_local_role("viewer", ["read"])

    # add permission to resource
    custom_app.add_access("user1", OAAIdentityType.LocalUser, "write", "resource1")
    custom_app.local_users["user1"].add_permission("read", [custom_app.resources["resource1"]])
    custom_app.add_access("user2", OAAIdentityType.LocalUser, "meta", custom_app.resources["resource1"])
    custom_app.add_access("group1", OAAIdentityType.LocalGroup, "read", custom_app.resources["resource2"])

    custom_app.idp_identities["okta_user1"].add_permission("write", [custom_app.resources["resource1"]])
    # create sub-resources
    custom_app.resources["resource1"].add_sub_resource("sub1", "subtype1", "subtype 1 subresources")
    custom_app.local_users["user1"].add_permission("read", resources=[custom_app.resources["resource1"].sub_resources["sub1"]])

    # convert app class to dictionary in preperation for JSON upload
    payload = custom_app.get_payload()
    app_payload = payload['applications'][0]

    # test application tag is present
    assert "tags" in app_payload
    assert {'key': 'AppTag', 'value': 'test'} in app_payload['tags']

    # for resource in app_dict['resources']:
    for expected in custom_resources:
        found = False
        for resource in app_payload['resources']:
            if resource['name'] == expected['name']:
                found = True
                assert resource["resource_type"] == expected["resource_type"]
                if expected.get("description"):
                  assert resource["description"] == expected["description"]
                break

        assert found

    for resource in app_payload['resources']:
        if resource["name"] == "resource1":
            assert resource["sub_resources"] is not None
            sub_resource = resource["sub_resources"][0]
            assert sub_resource["name"] == "sub1"
            assert sub_resource["resource_type"] == "subtype1"
            assert sub_resource["description"] == "subtype 1 subresources"

    for user in app_payload['local_users']:
        if user['name'] == "user1":
            assert user.get("identities") is None
            assert user.get("groups") is None
            assert len(user.get("tags")) == 1
            assert {'key': 'mytag', 'value': ''} in user['tags']
        elif user['name'] == "user2":
            assert user['identities'] == ["user2@pytest.com"]
            assert user.get("groups") is None
        elif user['name'] == "user3":
            assert user.get("identities") is None
            assert user['groups'] == ["group1"]
        elif user['name'] == "user4":
            assert user.get("identities") is None
            assert user['groups'] == ["group1", "group2"]

    permissions = payload['permissions']
    assert len(permissions) != 0
    matches = [p for p in permissions if p['name'] == "read"]
    assert len(matches) == 1  # should not be multiple entries with name read
    read_permission = matches[0]
    assert read_permission["permission_type"] is not None
    assert OAAPermission.DataRead in read_permission["permission_type"]
    assert OAAPermission.MetadataRead in read_permission["permission_type"]
    assert json.dumps(read_permission)

    identity_to_permissions = payload['identity_to_permissions']

    matches = [e for e in identity_to_permissions if e['identity'] == "user1"]
    assert len(matches) == 1  # should not be multiple entries with same username
    user1_permissions = matches[0]
    assert user1_permissions['identity_type'] == "local_user"

    # test the expected permissions are present
    assert len(user1_permissions['application_permissions']) == 3
    assert {'application': 'testapp', 'permission': 'write', 'apply_to_application': True} in user1_permissions['application_permissions']
    assert {'application': 'testapp', 'resources': ['resource1'], 'permission': 'write'} in user1_permissions['application_permissions']
    assert {'application': 'testapp', 'resources': ['resource1', 'resource1.sub1'], 'permission': 'read'} in user1_permissions['application_permissions']

    matches = [e for e in identity_to_permissions if e['identity'] == "group1"]
    assert len(matches) == 1  # should not be multiple entries with same username
    group1_permissions = matches[0]
    assert group1_permissions['identity_type'] == "local_group"

    assert len(group1_permissions['application_permissions']) == 2
    assert {'application': 'testapp', 'permission': 'read', 'apply_to_application': True} in group1_permissions['application_permissions']
    assert {'application': 'testapp', 'resources': ['resource2'], 'permission': 'read'} in group1_permissions['application_permissions']

    # test whole thing can be serialized to json
    assert json.dumps(payload)


def test_role_assignments():
    custom_app = CustomApplication(name="testapp", application_type="pytest", description="This is a test")

    user = custom_app.add_local_user("test01")
    thing1 = custom_app.add_resource("Thing01", "thing")
    custom_app.define_custom_permission(CustomPermission("write", [OAAPermission.DataWrite]))
    custom_app.add_local_role("admin", ["write"])

    # assign user role on application and assert that model has role assigned to application
    user.add_role("admin", apply_to_application=True)
    assert user.role_assignments["admin"]["apply_to_application"] is True

    # assign user a role to a resource without passing `apply_to_application` and assert user stil has role on appliction
    user.add_role("admin", resources=[thing1])
    assert user.role_assignments["admin"]["apply_to_application"] is True
    assert "Thing01" in user.role_assignments["admin"]["resources"]

    # assert that explicitly unsetting the application role works
    # user.add_role("admin", resources=[thing1], apply_to_application=False)
    user.add_role("admin", apply_to_application=False)
    assert user.role_assignments["admin"]["apply_to_application"] is False


def test_exceptions():
    custom_app = CustomApplication(name="testapp", application_type="pytest", description="This is a test")

    custom_app.add_local_user("test01")
    custom_app.add_resource("Thing01", "thing")
    custom_app.add_custom_permission("write", [OAAPermission.DataWrite])

    with pytest.raises(OAATemplateException) as e:
        custom_app.add_custom_permission("write", [OAAPermission.DataWrite])
    assert e.value.message == "Custom permission write already exists"

    # test invalid name
    with pytest.raises(OAATemplateException) as e:
        custom_app.add_local_user("test01")

    assert "test01" in e.value.message

    with pytest.raises(OAATemplateException) as e:
        custom_app.local_users["test01"].add_permission("write", "thing01")

    assert "resources must be list" in e.value.message

    with pytest.raises(OAATemplateException) as e:
        custom_app.local_users["test01"].add_permission("write", ["thing01"])

    assert "resources must be of a type CustomResource" in e.value.message

    with pytest.raises(OAATemplateException) as e:
        custom_app.local_users["test01"].add_permission("write", [custom_app.resources["Thing01"], "thing01"])

    assert "resources must be of a type CustomResource" in e.value.message

    group01 = custom_app.add_local_group("group01")
    with pytest.raises(OAATemplateException) as e:
        group01.add_group("group01")

    assert e.value.message == "Cannot add group to self"


def test_generate_app():
    app = generate_app()
    payload = app.get_payload()

    # ensure the app is as we expect
    assert payload == json.loads(GENERATED_APP_PAYLOAD)

def test_generate_app_id_mapping():
    app = generate_app_id_mapping()
    payload = app.get_payload()

    assert payload == json.loads(GENERATED_APP_ID_MAPPINGS_PAYLOAD)

def test_custom_properties():
    app = CustomApplication(name="testapp", application_type="pytest", description="This is a test")
    app.add_custom_permission("Admin", [OAAPermission.DataWrite])

    # define and set some application properties
    app.property_definitions.define_application_property("contact", OAAPropertyType.STRING)
    app.property_definitions.define_application_property("version", OAAPropertyType.STRING)

    app.properties["contact"] = "billy"
    app.set_property("version", "2022.1.1")

    # validate that an exception is thrown when trying to set an undefined property
    with pytest.raises(OAATemplateException):
        app.set_property("not_set", "something")

    # assert define throws an exception when type is not OAAPropertyType enum
    with pytest.raises(OAATemplateException):
        app.property_definitions.define_application_property("contact", "string")

    # define and set properties for user, group and role
    app.property_definitions.define_local_user_property("guest", OAAPropertyType.BOOLEAN)
    bob = app.add_local_user("bob")
    bob.set_property("guest", True)

    # test getting exception when setting undefined property
    with pytest.raises(OAATemplateException) as e:
        bob.set_property("unset", "booo")
    assert "unset" in e.value.message

    sue = app.add_local_user("sue")

    app.property_definitions.define_local_group_property("group_email", OAAPropertyType.STRING)
    admins = app.add_local_group("admins")
    admins.set_property("group_email", "admins@example.com")

    app.property_definitions.define_local_role_property("built_in", OAAPropertyType.BOOLEAN)
    operators = app.add_local_role("operators")
    operators.set_property("built_in", True)

    thing1 = app.add_resource("thing1", "thing", "test description")
    app.property_definitions.define_resource_property("thing", "owner", OAAPropertyType.STRING)
    app.property_definitions.define_resource_property("thing", "private", OAAPropertyType.BOOLEAN)
    thing1.set_property("owner", "jim")

    sub_thing = thing1.add_sub_resource("sub_thing", "thing")
    sub_thing.set_property("owner", "bob")

    cog1 = app.add_resource("cog1", "cog")

    # assert error when no properties are set for resource type at all
    with pytest.raises(OAATemplateException) as e:
        cog1.set_property("unset", "anything")
    assert e.value.message == "No custom properties defined for resource type cog"

    # assert exception when resource has properties, not not the one being set
    with pytest.raises(OAATemplateException) as e:
        thing1.set_property("unset", "nothing")
    assert "unknown property name unset" == e.value.message

    # get payload and validate all expected properties and blocks are present
    payload = app.get_payload()
    assert "custom_property_definition" in payload
    assert "applications" in payload["custom_property_definition"]

    app_payload = payload["applications"][0]
    assert "custom_properties" in app_payload
    assert app_payload["custom_properties"]["contact"] == "billy"
    assert app_payload["custom_properties"]["version"] == "2022.1.1"

    bob_payload = None
    for user in app_payload["local_users"]:
        if user["name"] == "bob":
            bob_payload = user
            break
    assert bob_payload["custom_properties"]["guest"] is True

    admins_payload = None
    for group in app_payload["local_groups"]:
        if group["name"] == "admins":
            admins_payload = group
            break
    assert admins_payload["custom_properties"]["group_email"] == "admins@example.com"

    operators_payload = None
    for role in app_payload["local_roles"]:
        if role["name"] == "operators":
            operators_payload = role
            break
    assert operators_payload["custom_properties"]["built_in"] is True

    print(json.dumps(payload, indent=2))
    assert payload == json.loads(CUSTOM_PROPERTIES_PAYLOAD)


# Test Payloads
CUSTOM_PROPERTIES_PAYLOAD = """
{
  "custom_property_definition": {
    "applications": [
      {
        "application_type": "pytest",
        "application_properties": {
          "contact": "STRING",
          "version": "STRING"
        },
        "local_user_properties": {
          "guest": "BOOLEAN"
        },
        "local_group_properties": {
          "group_email": "STRING"
        },
        "local_role_properties": {
          "built_in": "BOOLEAN"
        },
        "resources": [
          {
            "resource_type": "thing",
            "properties": {
              "owner": "STRING",
              "private": "BOOLEAN"
            }
          }
        ]
      }
    ]
  },
  "applications": [
    {
      "name": "testapp",
      "application_type": "pytest",
      "description": "This is a test",
      "local_users": [
        {
          "name": "bob",
          "custom_properties": {
            "guest": true
          }
        },
        {
          "name": "sue"
        }
      ],
      "local_groups": [
        {
          "name": "admins",
          "custom_properties": {
            "group_email": "admins@example.com"
          }
        }
      ],
      "local_roles": [
        {
          "name": "operators",
          "permissions": [],
          "tags": [],
          "custom_properties": {
            "built_in": true
          }
        }
      ],
      "tags": [],
      "custom_properties": {
        "contact": "billy",
        "version": "2022.1.1"
      },
      "resources": [
        {
          "name": "thing1",
          "resource_type": "thing",
          "description": "test description",
          "sub_resources": [
            {
              "name": "sub_thing",
              "resource_type": "thing",
              "custom_properties": {
                "owner": "bob"
              }
            }
          ],
          "custom_properties": {
            "owner": "jim"
          }
        },
        {
          "name": "cog1",
          "resource_type": "cog"
        }
      ]
    }
  ],
  "permissions": [
    {
      "name": "Admin",
      "permission_type": [
        "DataWrite"
      ],
      "apply_to_sub_resources": false
    }
  ],
  "identity_to_permissions": [
    {
      "identity": "bob",
      "identity_type": "local_user"
    },
    {
      "identity": "sue",
      "identity_type": "local_user"
    },
    {
      "identity": "admins",
      "identity_type": "local_group"
    }
  ]
}
"""
