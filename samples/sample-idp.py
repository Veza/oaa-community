#!env python3
"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by a the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.

Example of using the `CustomIdPProvider` class to model an identity provider as a source of users.

If you want to run the code you will need to export environment variables for the Veza URL, user and API keys.

```
export VEZA_API_KEY="xxxxxxx"
export VEZA_URL="https://myveza.vezacloud.com"
./sample-idp.py
```

Since the example includes fake AWS ARNs that Veza will not have discovered the expected output will
contain warning like "Cannot find IAM role by names ..."
"""

from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomIdPProvider, OAAPropertyType
import os
import sys


def main():

    # OAA requires a Veza API key, which you can generate from Administration > API Keys
    # Export the API key, and Veza URL as environment variables
    # Making them available to your connector in this way keeps credentials out of the source code
    veza_api_key = os.getenv("VEZA_API_KEY")
    veza_url = os.getenv("VEZA_URL")
    if not veza_api_key or not veza_url:
        print("Unable to load VEZA_API_KEY and VEZA_URL from OS")
        sys.exit(1)

    # Instantiates a client connection. The client will confirm the credentials and Veza URL are valid
    # Checking this early helps prevents connection failures in the final stage
    veza_con = OAAClient(url=veza_url, api_key=veza_api_key)

    # create a CustomIdPProvider to represent your IdP. This can be named generically or specific to the environment if you have
    # multiple namespaces to model. idp_type will typically be the technology/vendor for the provider.
    idp = CustomIdPProvider("My IdP", domain="example.com", idp_type="custom_idp")

    # add users to the idp, properties for users can be set during creation or updated after
    idp.add_user("mrichardson", full_name="Michelle Richardson", email="mrichardson@example.com")

    evargas_user = idp.add_user("evargas")
    evargas_user.full_name = "Elizabeth Vargas"
    evargas_user.email = "evargas@example.com"

    # users and groups can have optional identity property. The identity serves as the unique reference identifier across
    # Veza. If omitted CustomIdPProvider will automatically populate the identity with the name
    idp.add_user("willis", email="willis@example.com", identity="cwilliams")

    # OAA can support custom properties for users to track additional metadata unique to the environment
    # to use custom properties the property must first be defined and given a type, then can be set for the individual entity
    idp.property_definitions.define_user_property("region", OAAPropertyType.STRING)
    idp.property_definitions.define_user_property("is_contractor", OAAPropertyType.BOOLEAN)

    idp.users['willis'].set_property("region", "NorthAmerica")
    idp.users['willis'].set_property("is_contractor", True)

    # Create Groups
    idp.add_group("developers")
    idp.add_group("sec-ops")
    idp.add_group("everyone", full_name="All Company Employees")

    # users can be added to groups using the add_group function, users can be added to multiple groups in a single call
    for username in idp.users:
        idp.users[username].add_groups(["everyone"])

    evargas_user.add_groups(["developers", "sec-ops"])
    idp.users["mrichardson"].add_groups(["developers"])

    # Veza CustomIdP supports tracking the AWS Roles a user can assume. For users who can assume roles Veza can calculate
    # their effective permissions to AWS resources based on the role(s)
    # roles are added by ARN
    idp.users["mrichardson"].add_assumed_role_arns(["arn:aws:iam::123456789012:role/role001", "arn:aws:iam::123456789012:role/role002"])

    # After adding users and groups, the IdP information is pushed to Veza using the OAA API
    provider_name = "Sample-IdP"
    provider = veza_con.get_provider(provider_name)
    if provider:
        print("-- Found existing provider")
    else:
        print(f"++ Creating Provider {provider_name}")
        provider = veza_con.create_provider(provider_name, "identity_provider")
    print(f"-- Provider: {provider['name']} ({provider['id']})")

    # Push the metadata payload:
    try:
        response = veza_con.push_application(provider_name,
                                               data_source_name=f"{idp.name} ({idp.idp_type})",
                                               application_object=idp,
                                               save_json=True
                                               )
        if response.get("warnings", None):
            # Veza may return warnings on a successful uploads. These are informational warnings that did not stop the processing
            # of the OAA data but may be important, for example: AWS role ARNs assigned to users that Veza has not discovered
            print("-- Push succeeded with warnings:")
            for e in response["warnings"]:
                print(f"  - {e}")
    except OAAClientError as e:
        print(f"-- Error: {e.error}: {e.message} ({e.status_code})", file=sys.stderr)
        if hasattr(e, "details"):
            for d in e.details:
                print(f"  -- {d}", file=sys.stderr)


if __name__ == '__main__':
    main()
