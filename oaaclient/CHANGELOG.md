# OAA Client Change Log

## 2022/05/25
* Added support to CustomApplication template for nested groups, local groups can be added to another local group with `.add_group(group: str)` operation
* Added support to CustomIdP for groups to have a list of AWS roles that members can assume. Role can be added to a group with `.add_assumed_role_arns([arns])`
* Added support to CustomApplication resources and sub-resources for connections to outside entities in the graph. 
* Extended supported characters for Tag values to include letters, numbers and specials characters `.,_@`
* Updated client `get_provier()` and `get_data_source()` operations to perform case insensitive search of existing entities

## 2022/05/03
* Moved `OAAPermission` and `OAAIdentityType` enums to `templates`, any import statements will need to be updated

## 2022/04/26
*   Added `CustomIdPUser.set_source_identity` for setting the source identity of a user. Also added new enum
    `IdPProviderType` for supported IdP providers.

## 2022/4/18
* `CookiePermission` has been renamed to `OAAPermission`, any references will need to be updated.
* `CookieIdentityType` has been renamed to `OAAIdentityType`, any references will need to be updated.
* `OAAClient.__init__` now takes in `api_key` as authorization parameter, `token` remains as an optional parameter for backwards compatibility. Raises `OAAClientError` if neither `api_key` or `token` are set.

## 2022/4/6
* Added `templates.CustomIdPProvider` to support OAA Custom Identity Provider template. See Samples directory for example.

## 2022/3/22
* The `CustomApplication` class now supports [custom entity properties](https://docs.veza.com/api/oaa/custom-properties) introduced in Veza `2022.2.2`.
  - Any applications that utilized `dynamic_properties` (`One`, `Two`, `Three` etc.) will need to be updated to use the latest SDK

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
