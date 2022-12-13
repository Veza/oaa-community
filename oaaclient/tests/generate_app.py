"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

from oaaclient.templates import CustomApplication, Tag, OAAPermission, OAAPropertyType


def generate_app():
    """ generates a complete OAA custom application payload """

    app = CustomApplication(name="pytest generated app", application_type="pytest", description="This is a test")

    app.property_definitions.define_application_property("version", OAAPropertyType.STRING)
    app.set_property("version", "2022.2.2")

    app.add_custom_permission("all", [OAAPermission.DataRead,
                                      OAAPermission.DataWrite,
                                      OAAPermission.DataCreate,
                                      OAAPermission.DataDelete,
                                      OAAPermission.MetadataRead,
                                      OAAPermission.MetadataWrite,
                                      OAAPermission.MetadataCreate,
                                      OAAPermission.MetadataDelete,
                                      OAAPermission.NonData
                                      ]
                              )
    app.add_custom_permission("Admin", [OAAPermission.DataRead,
                                        OAAPermission.DataWrite,
                                        OAAPermission.MetadataRead,
                                        OAAPermission.MetadataWrite,
                                        OAAPermission.NonData
                                        ],
                              apply_to_sub_resources=True
                              )
    app.add_custom_permission("Manage", [OAAPermission.DataRead,
                                         OAAPermission.DataWrite,
                                         OAAPermission.MetadataRead,
                                         OAAPermission.MetadataWrite,
                                         OAAPermission.NonData
                                        ]
                              )
    app.add_custom_permission("View", [OAAPermission.DataRead,
                                       OAAPermission.MetadataRead,
                                      ]
                              )

    app.add_custom_permission("Manage_Thing", [OAAPermission.DataRead,
                                               OAAPermission.DataWrite,
                                              ],
                              resource_types=["thing"])

    # define one property of every type
    app.property_definitions.define_local_user_property("is_guest", OAAPropertyType.BOOLEAN)
    app.property_definitions.define_local_user_property("user_id", OAAPropertyType.NUMBER)
    app.property_definitions.define_local_user_property("NAME", OAAPropertyType.STRING)
    app.property_definitions.define_local_user_property("peers", OAAPropertyType.STRING_LIST)
    app.property_definitions.define_local_user_property("birthday", OAAPropertyType.TIMESTAMP)

    username_list = ["bob", "marry", "sue", "rob"]
    for username in username_list:
        user = app.add_local_user(username)
        user.add_identity(f"{username}@example.com")
        # set all the properties to something
        user.is_active = True
        user.created_at = "2001-01-01T00:00:00.000Z"
        user.last_login_at = "2002-02-01T00:00:00.000Z"
        user.deactivated_at = "2003-03-01T00:00:00.000Z"
        user.password_last_changed_at = "2004-04-01T00:00:00.000Z"
        user.set_property("is_guest", False)
        user.set_property("user_id", username_list.index(username))
        user.set_property("NAME", username.swapcase())
        user.set_property("peers", username_list)
        user.set_property("birthday", "2000-01-01T00:00:00.000Z")

    app.local_users["marry"].is_active = False

    # groups
    app.property_definitions.define_local_group_property("group_id", OAAPropertyType.NUMBER)
    group1 = app.add_local_group("group1")
    group1.created_ad = "2001-01-01T00:00:00.000Z"
    group1.set_property("group_id", 1)

    app.local_users["bob"].add_group("group1")
    app.local_users["marry"].add_group("group1")

    group2 = app.add_local_group("group2")
    group2.created_ad = "2001-01-01T00:00:00.000Z"
    group2.set_property("group_id", 2)

    app.local_users["bob"].add_group("group2")
    app.local_users["marry"].add_group("group2")

    group3 = app.add_local_group("group3")
    group3.add_group("group1")
    group3.add_group("group2")
    app.local_users["rob"].add_group("group3")

    # roles
    app.property_definitions.define_local_role_property("role_id", OAAPropertyType.NUMBER)
    app.property_definitions.define_local_role_property("custom", OAAPropertyType.BOOLEAN)

    role1 = app.add_local_role("role1", ["all", "Admin", "Manage_Thing"])
    role1.set_property("role_id", 1)
    role1.set_property("custom", False)

    role2 = app.add_local_role("role2")
    role2.add_permissions(["view"])
    role2.set_property("role_id", 1)
    role1.set_property("custom", True)

    app.add_local_role("empty_role")

    # resources
    app.property_definitions.define_resource_property("thing", "private", OAAPropertyType.BOOLEAN)
    app.property_definitions.define_resource_property("thing", "unique_id", OAAPropertyType.NUMBER)
    app.property_definitions.define_resource_property("thing", "hair_color", OAAPropertyType.STRING)
    app.property_definitions.define_resource_property("thing", "peers", OAAPropertyType.STRING_LIST)
    app.property_definitions.define_resource_property("thing", "publish_date", OAAPropertyType.TIMESTAMP)

    thing1 = app.add_resource("thing1", resource_type="thing", description="thing1")
    thing1.set_property("private", False)
    thing1.set_property("unique_id", 1)
    thing1.set_property("hair_color", "blue")
    thing1.set_property("peers", ["thing2", "thing3"])
    thing1.set_property("publish_date", "1959-03-12T00:00:00.000Z")
    thing1.add_tag("A tag1", value="This is a value @,-_.")

    thing2 = app.add_resource("thing2", resource_type="thing")
    thing2.set_property("private", False)
    thing2.set_property("unique_id", 2)
    thing2.set_property("hair_color", "blue")
    thing2.set_property("peers", ["thing2", "thing3"])
    thing2.set_property("publish_date", "1959-03-12T00:00:00.000Z")

    cog1 = thing2.add_sub_resource("cog1", resource_type="cog")
    cog1.add_resource_connection("service_account@some-project.iam.gserviceaccount.com", "GoogleCloudServiceAccount")

    # authorizations
    app.local_users["bob"].add_role("role1", apply_to_application=True)
    app.local_groups["group2"].add_role("role2", resources=[thing1])
    app.local_users["marry"].add_permission("view", resources=[thing2, cog1])
    app.local_users["rob"].add_permission("manage", resources=[thing1], apply_to_application=True)

    return app


# Full App payload as string
GENERATED_APP_PAYLOAD = """
{
  "custom_property_definition": {
    "applications": [
      {
        "application_type": "pytest",
        "application_properties": {
          "version": "STRING"
        },
        "local_user_properties": {
          "is_guest": "BOOLEAN",
          "user_id": "NUMBER",
          "NAME": "STRING",
          "peers": "STRING_LIST",
          "birthday": "TIMESTAMP"
        },
        "local_group_properties": {
          "group_id": "NUMBER"
        },
        "local_role_properties": {
          "role_id": "NUMBER",
          "custom": "BOOLEAN"
        },
        "resources": [
          {
            "resource_type": "thing",
            "properties": {
              "private": "BOOLEAN",
              "unique_id": "NUMBER",
              "hair_color": "STRING",
              "peers": "STRING_LIST",
              "publish_date": "TIMESTAMP"
            }
          }
        ]
      }
    ]
  },
  "applications": [
    {
      "name": "pytest generated app",
      "application_type": "pytest",
      "description": "This is a test",
      "local_users": [
        {
          "name": "bob",
          "identities": [
            "bob@example.com"
          ],
          "groups": [
            "group1",
            "group2"
          ],
          "is_active": true,
          "created_at": "2001-01-01T00:00:00.000Z",
          "last_login_at": "2002-02-01T00:00:00.000Z",
          "deactivated_at": "2003-03-01T00:00:00.000Z",
          "password_last_changed_at": "2004-04-01T00:00:00.000Z",
          "custom_properties": {
            "is_guest": false,
            "user_id": 0,
            "NAME": "BOB",
            "peers": [
              "bob",
              "marry",
              "sue",
              "rob"
            ],
            "birthday": "2000-01-01T00:00:00.000Z"
          }
        },
        {
          "name": "marry",
          "identities": [
            "marry@example.com"
          ],
          "groups": [
            "group1",
            "group2"
          ],
          "is_active": false,
          "created_at": "2001-01-01T00:00:00.000Z",
          "last_login_at": "2002-02-01T00:00:00.000Z",
          "deactivated_at": "2003-03-01T00:00:00.000Z",
          "password_last_changed_at": "2004-04-01T00:00:00.000Z",
          "custom_properties": {
            "is_guest": false,
            "user_id": 1,
            "NAME": "MARRY",
            "peers": [
              "bob",
              "marry",
              "sue",
              "rob"
            ],
            "birthday": "2000-01-01T00:00:00.000Z"
          }
        },
        {
          "name": "sue",
          "identities": [
            "sue@example.com"
          ],
          "is_active": true,
          "created_at": "2001-01-01T00:00:00.000Z",
          "last_login_at": "2002-02-01T00:00:00.000Z",
          "deactivated_at": "2003-03-01T00:00:00.000Z",
          "password_last_changed_at": "2004-04-01T00:00:00.000Z",
          "custom_properties": {
            "is_guest": false,
            "user_id": 2,
            "NAME": "SUE",
            "peers": [
              "bob",
              "marry",
              "sue",
              "rob"
            ],
            "birthday": "2000-01-01T00:00:00.000Z"
          }
        },
        {
          "name": "rob",
          "identities": [
            "rob@example.com"
          ],
          "groups": [
            "group3"
          ],
          "is_active": true,
          "created_at": "2001-01-01T00:00:00.000Z",
          "last_login_at": "2002-02-01T00:00:00.000Z",
          "deactivated_at": "2003-03-01T00:00:00.000Z",
          "password_last_changed_at": "2004-04-01T00:00:00.000Z",
          "custom_properties": {
            "is_guest": false,
            "user_id": 3,
            "NAME": "ROB",
            "peers": [
              "bob",
              "marry",
              "sue",
              "rob"
            ],
            "birthday": "2000-01-01T00:00:00.000Z"
          }
        }
      ],
      "local_groups": [
        {
          "name": "group1",
          "custom_properties": {
            "group_id": 1
          }
        },
        {
          "name": "group2",
          "custom_properties": {
            "group_id": 2
          }
        },
        {
          "name": "group3",
          "groups": [
            "group1",
            "group2"
          ]
        }
      ],
      "local_roles": [
        {
          "name": "role1",
          "permissions": [
            "all",
            "Admin",
            "Manage_Thing"
          ],
          "tags": [],
          "custom_properties": {
            "role_id": 1,
            "custom": true
          }
        },
        {
          "name": "role2",
          "permissions": [
            "view"
          ],
          "tags": [],
          "custom_properties": {
            "role_id": 1
          }
        },
        {
          "name": "empty_role",
          "permissions": [],
          "tags": [],
          "custom_properties": {}
        }
      ],
      "tags": [],
      "custom_properties": {
        "version": "2022.2.2"
      },
      "resources": [
        {
          "name": "thing1",
          "resource_type": "thing",
          "description": "thing1",
          "custom_properties": {
            "private": false,
            "unique_id": 1,
            "hair_color": "blue",
            "peers": [
              "thing2",
              "thing3"
            ],
            "publish_date": "1959-03-12T00:00:00.000Z"
          },
          "tags": [
            {
              "key": "A tag1",
              "value": "This is a value @,-_."
            }
          ]
        },
        {
          "name": "thing2",
          "resource_type": "thing",
          "sub_resources": [
            {
              "name": "cog1",
              "resource_type": "cog",
              "connections": [
                {
                  "id": "service_account@some-project.iam.gserviceaccount.com",
                  "node_type": "GoogleCloudServiceAccount"
                }
              ]
            }
          ],
          "custom_properties": {
            "private": false,
            "unique_id": 2,
            "hair_color": "blue",
            "peers": [
              "thing2",
              "thing3"
            ],
            "publish_date": "1959-03-12T00:00:00.000Z"
          }
        }
      ]
    }
  ],
  "permissions": [
    {
      "name": "all",
      "permission_type": [
        "DataRead",
        "DataWrite",
        "DataCreate",
        "DataDelete",
        "MetadataRead",
        "MetadataWrite",
        "MetadataCreate",
        "MetadataDelete",
        "NonData"
      ],
      "apply_to_sub_resources": false,
      "resource_types": []
    },
    {
      "name": "Admin",
      "permission_type": [
        "DataRead",
        "DataWrite",
        "MetadataRead",
        "MetadataWrite",
        "NonData"
      ],
      "apply_to_sub_resources": true,
      "resource_types": []
    },
    {
      "name": "Manage",
      "permission_type": [
        "DataRead",
        "DataWrite",
        "MetadataRead",
        "MetadataWrite",
        "NonData"
      ],
      "apply_to_sub_resources": false,
      "resource_types": []
    },
    {
      "name": "View",
      "permission_type": [
        "DataRead",
        "MetadataRead"
      ],
      "apply_to_sub_resources": false,
      "resource_types": []
    },
    {
      "name": "Manage_Thing",
      "permission_type": [
        "DataRead",
        "DataWrite"
      ],
      "apply_to_sub_resources": false,
      "resource_types": ["thing"]
    }
  ],
  "identity_to_permissions": [
    {
      "identity": "bob",
      "identity_type": "local_user",
      "role_assignments": [
        {
          "application": "pytest generated app",
          "role": "role1",
          "apply_to_application": true,
          "resources": []
        }
      ]
    },
    {
      "identity": "marry",
      "identity_type": "local_user",
      "application_permissions": [
        {
          "application": "pytest generated app",
          "resources": [
            "thing2",
            "thing2.cog1"
          ],
          "permission": "view"
        }
      ]
    },
    {
      "identity": "rob",
      "identity_type": "local_user",
      "application_permissions": [
        {
          "application": "pytest generated app",
          "permission": "manage",
          "apply_to_application": true
        },
        {
          "application": "pytest generated app",
          "resources": [
            "thing1"
          ],
          "permission": "manage"
        }
      ]
    },
    {
      "identity": "group2",
      "identity_type": "local_group",
      "role_assignments": [
        {
          "application": "pytest generated app",
          "role": "role2",
          "apply_to_application": false,
          "resources": [
            "thing1"
          ]
        }
      ]
    }
  ]
}
"""
