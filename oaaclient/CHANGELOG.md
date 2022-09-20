# OAA Client Change Log

## 2022/09/20

* Increase timeout on delete API operations

## 2022/08/16

* Payload compression is now enabled by default. Added more detailed logging and exception when prepared payload size will exceed 100MB.
* Added support for setting resource type list on `CustomPermission`. When permission is part of a role the permission will only be used when the role is applied if resource type is in this list. The resource type list can be specified when the permissions is created:
  ```
  CustomApplication.add_custom_permission(self, name: str, permissions: list[OAAPermission], apply_to_sub_resources: bool = False, resource_types: list = None)
  ```
* Update the tag and tag validation regex

## 2022/08/15

* Update required requests package minimum version to `2.27`

## 2022/08/11

* `custom_app.add_idp_idententiy` is now `custom_app.add_idp_identity`
* Docstring and README improvements

## 2022/08/05

* Improvements to OAAClientError exceptions raised when API returns errors and additional test cases

## 2022/07/27

* Changes to reduce OAA payload size during transfer.
  * Removed unset/default values from payload
  * Option to enable GZIP compression of payload
  * Structure for identity to resource permissions

## 2022/07/25

* Automatically trim trailing slashes from Veza URL for `Client` connection

## 2022/07/14

* Users, groups and roles can now be created and referenced by a unique identifier separate from `name`.
  * `add_local_user`, `add_local_group` and `add_local_role` functions all have new optional property `unique_id`
  * When `unique_id` is passed the entity will be created with the unique identifier in addition to name
  * When using unique identifiers the `unique_id` value will be used as the key in the `local_users`, `local_groups` and `local_roles` dictionaries
  * Must use unique identifier for references between entities such as `add_group` and `add_role`
  * To use `unique_id` all local users, local groups and local roles must have a unique identifier in addition to name

## 2022/07/01

* Added support for setting OAA Provider Icons via `Client.update_provider_icon` function.
* Added `utils.encode_icon_file()` function to assist with base64 encoding icon files

## 2022/06/23

* Added `OAAClient.delete_provider()` and `OAAClient.delete_data_source()` functions

## 2022/05/25

* Added support to CustomApplication template for nested groups, local groups can be added to another local group with `.add_group(group: str)` operation
* Added support to CustomIdP for groups to have a list of AWS roles that members can assume. Role can be added to a group with `.add_assumed_role_arns([arns])`
* Added support to CustomApplication resources and sub-resources for connections to outside entities in the graph.
* Extended supported characters for Tag values to include letters, numbers and specials characters `.,_@`
* Updated client `get_provider()` and `get_data_source()` operations to perform case insensitive search of existing entities

## 2022/05/03

* Moved `OAAPermission` and `OAAIdentityType` enums to `templates`, any import statements will need to be updated

## 2022/04/26

* Added `CustomIdPUser.set_source_identity` for setting the source identity of a user. Also added new enum
    `IdPProviderType` for supported IdP providers.

## 2022/4/18

* `CookiePermission` has been renamed to `OAAPermission`, any references will need to be updated.
* `CookieIdentityType` has been renamed to `OAAIdentityType`, any references will need to be updated.
* `OAAClient.__init__` now takes in `api_key` as authorization parameter, `token` remains as an optional parameter for backwards compatibility. Raises `OAAClientError` if neither `api_key` or `token` are set.

## 2022/4/6

* Added `templates.CustomIdPProvider` to support OAA Custom Identity Provider template. See Samples directory for example.

## 2022/3/22

* The `CustomApplication` class now supports custom entity properties introduced in Veza `2022.2.2`.
  * Any applications that utilized `dynamic_properties` (`One`, `Two`, `Three` etc.) will need to be updated to use the latest SDK

  Old method:

  ```python
  app_instance.local_users['username'].property["One"] = "id:123"
  ```

  Updated method:

  ```python
  # first define custom property
  app_instance.property_definitions.define_local_user_property("id", OAAPropertyType.NUMBER)
  # set property on user
  app_instance.local_users['username'].set_property("id", 123)
  ```

  Available property types:
  * BOOLEAN
  * NUMBER
  * STRING
  * STRING_LIST
  * TIMESTAMP (RFC3339 formatted string)
