#!env python3
"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by a the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.

Example of using the `CustomApplication` class to model a typical application where users and groups are assigned
permissions to the application or resources.

If you want to run the code you will need to export environment variables for the Veza URL, user and API keys.

```
export OAA_TOKEN="xxxxxxx"
export VEZA_URL="https://myveza.vezacloud.com"
./sample-app.py
```

"""

from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, OAAPermission
import os
import sys


def main():

    # OAA requires an API token, which you can generate from your Veza user profile
    # Export the API token, and Veza URL as environment variables
    # Making them available to your connector in this way keeps credentials out of the source code
    veza_api_key = os.getenv('VEZA_API_KEY')
    veza_url = os.getenv('VEZA_URL')
    if None in (veza_url, veza_api_key):
        print("Unable to local all environemnt variables")
        sys.exit(1)

    # Instantiates a client connection. The client will confirm the credentials and Veza URL are valid
    # Checking this early helps prevents connection failures in the final stage
    veza_con = OAAClient(url=veza_url, api_key=veza_api_key)

    # Create an instance of the OAA CustomApplication class, modeling the application name and type
    # `name` will be displayed in the Veza UI
    # `application_type` should be a short key reflecting the source application authroization is being modeled for
    # You can use the same type for multiple applications
    custom_app = CustomApplication(name="Sample App", application_type="sample")

    # In the OAA payload, each permission native to the custom app is mapped to the Veza effective permission (data/nondata C/R/U/D).
    # Permissions must be defined before they can be referenced, as they are discovered or ahead of time.
    # For each custom application permission, bind them to the Veza permissions using the `OAAPermission` enum:
    custom_app.add_custom_permission("admin", [OAAPermission.DataRead, OAAPermission.DataWrite])
    custom_app.add_custom_permission("operator", [OAAPermission.DataRead])

    # Create resources and sub-resource to model the entities in the application
    # To Veza, an application can be a single entity or can contain resources and sub-resources
    # Utilizing resources enables tracking of authorizations to specific components of the system being modeled
    # Setting a `resource_type` can help group entities of the same type for reporting/queries
    entity1 = custom_app.add_resource(name="Entity1", resource_type="thing", description="Some entity in the application")
    entity2 = custom_app.add_resource(name="Entity2", resource_type="thing", description="Another entity in the application")
    other = custom_app.add_resource(name="Other", resource_type="other", description="Something totally different")

    # Sub-resources can be added to any resource (including other sub-resources)
    child1 = entity1.add_sub_resource(name="Child 1", resource_type="child", description="My information about resource")
    child1.add_sub_resource(name="Grandchild 1", resource_type="grandchild", description="My information about resource")

    # Any users and groups local to the application can be defined.
    # IdP users can be mapped directly without defining them in the OAA application (see below)
    custom_app.add_local_user("bob")
    # A local user can be associated with an IdP user by adding an identity to the user:
    custom_app.local_users["bob"].add_identity("bob@example.com")
    # Identities, groups and roles can be assigned to local users at creation or after (groups and roles must exist):
    jane = custom_app.add_local_user("jane", identities="jane@example.com")

    # when adding a user the new user is returned and can updated if needed, there are multiple built in properties that can be set for a user
    jane.is_active = False
    jane.created_at = "2022-01-26T20:48:12.460Z"

    # Define a local group and add a user to it
    custom_app.add_local_group("admins")
    custom_app.local_users["jane"].add_group("admins")

    # adding local users and groups requires that the name not already exist
    if "yan" not in custom_app.local_users:
        custom_app.add_local_user("yan")

    # For each Identity (user, group, IdP) assign permissions to the application or resource.
    # The identities (users, groups) permissions and resources must already be defined

    # To add a permision directly to the application use `apply_to_application=True`
    custom_app.local_users["bob"].add_permission(permission="operator", apply_to_application=True)
    custom_app.local_groups["admins"].add_permission(permission="admin",  apply_to_application=True)

    # You can describe specific permissions to invidivual resources or subresources:
    custom_app.local_users["yan"].add_permission(permission="operator", resources=[entity1, child1])

    # Authorization can also be created directly for an IdP identity
    custom_app.add_idp_idententiy("user_identity@example.com")
    # resources can also be referenced by name from the application model
    custom_app.idp_identities["user_identity@example.com"].add_permission(permission="admin", resources=[custom_app.resources['Entity1']])

    # Once all authorizations have been mapped, the final step is to publish the app to Veza
    # Connect to the API to Push to Veza, define the provider and create if necessary:

    provider_name = "Sample"
    provider = veza_con.get_provider(provider_name)
    if provider:
        print("-- Found existing provider")
    else:
        print(f"++ Creating Provider {provider_name}")
        provider = veza_con.create_provider(provider_name, "application")
    print(f"-- Provider: {provider['name']} ({provider['id']})")

    # Push the metadata payload:

    try:
        response = veza_con.push_application(provider_name,
                                               data_source_name=f"{custom_app.name} ({custom_app.application_type})",
                                               application_object=custom_app,
                                               save_json=False
                                               )
        if response.get("warnings", None):
            # Veza may return warnings on a succesfull uploads. These are informational warnings that did not stop the processing
            # of the OAA data but may be important. Specifically identities that cannot be resolved will be returned here.
            print("-- Push succeeded with warnings:")
            for e in response["warnings"]:
                print(f"  - {e}")
    except OAAClientError as e:
        print(f"-- Error: {e.error}: {e.message} ({e.status_code})", file=sys.stderr)
        if hasattr(e, "details"):
            for d in e.details:
                print(f"  -- {d}", file=sys.stderr)
    return


if __name__ == '__main__':
    main()
