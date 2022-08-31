#!env python3
"""Example of using `oaaclient` to import users from a CSV file.

Reads user properties from the input file, populates an OAA payload,
and creates a new OAA identity provider containing the imported users.

Expected CSV headers are `identity,name,full_name,is_active,is_guest,manager_id`
Can be updated to match custom column headings or apply custom properties.

Example:
    ```
    export VEZA_URL=<Veza URL>
    export VEZA_API_KEY=<Veza API key>
    ./idp-importer-csv.py --provider MyIdpProvider --datasource MyDatasource  ./my-users.csv

    ```

Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.

"""

from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomIdPProvider
import click
import csv
import logging
import os
import sys


logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
log = logging.getLogger()


def load_users(idp: CustomIdPProvider, source: str) -> None:
    """Populate the idp with user from the source csv file"""

    log.info(f"Loading users from {source}")
    with open(source) as f:
        for r in csv.DictReader(f):
            # get the identity, name, full_name and email
            try:
                identity = r["identity"]
                name = r["name"]
                full_name = r["full_name"]
                email = r["email"]
            except KeyError as e:
                log.error(f"Incorrect CSV column headers, missing column {e}")
                sys.exit(1)

            # create a new IDP user
            new_user = idp.add_user(name=name, full_name=full_name, email=email, identity=identity)

            # set the user to active and guest or not, look for strings like true/false or yes/no
            if r.get("active"):
                active_string = r["active"].lower()
                if active_string in ["true", "yes"]:
                    new_user.is_active = True
                elif active_string in ["false", "no"]:
                    new_user.is_active = False

            if r.get("is_guest"):
                guest_string = r["is_guest"].lower()
                if guest_string in ["true", "yes"]:
                    new_user.is_guest = True
                elif guest_string in ["false", "no"]:
                    new_user.is_guest = False

            # if the manager id column is filled in, set the new users manager
            if r.get("manager_id"):
                new_user.manager_id = r.get("manager_id")

    return

@click.command()
@click.option("--provider", required=True)
@click.option("--datasource", required=True)
@click.option("--save-json", is_flag=True)
@click.argument("file", required=True)
def main(provider, datasource, save_json, file):

    # load the Veza URL and API key from the environment
    veza_url = os.getenv("VEZA_URL")
    veza_api_key = os.getenv("VEZA_API_KEY")

    if not (veza_url or veza_api_key):
        log.error("Must set VEZA_URL and VEZA_API_KEY")
        sys.exit(1)

    try:
        log.info("Testing Veza credentials")
        veza_con = OAAClient(url=veza_url, api_key=veza_api_key)
    except OAAClientError as e:
        log.error("Unable to connect to Veza API")
        log.error(e)
        sys.exit(1)

    # create a new provider if the provider doesn't already exist
    if not veza_con.get_provider(provider):
        log.info(f"Creating new provider {provider}")
        veza_con.create_provider(provider, "identity_provider")

    # Configure the Custom IdP
    idp = CustomIdPProvider("Custom IdP", idp_type="custom_idp", domain="example.com", description=None)

    # load the user from
    load_users(idp, file)

    try:
        # push the IdP to Veza, log and errors or warnings
        log.info("Sending to Veza")
        response = veza_con.push_application(provider, datasource, idp, save_json=save_json)
        if response.get("warnings", None):
            log.warning("Push succeeded with warnings")
            for w in response['warnings']:
                log.warning(w)
        log.info("Success")
    except OAAClientError as e:
        log.error(f"Error during push {e.message} {e.status_code}")
        if e.details:
            log.error(e.details)
        sys.exit(1)

    return

if __name__ == "__main__":
    main()
