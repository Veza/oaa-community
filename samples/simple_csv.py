#!/usr/bin/env python3
"""
Example of how to import a simple CSV to an OAA Custom Application

Code can be updated to fit the specific format of the CSV by editing the column names referenced in the code,
parsing additional rows and adding custom properties as needed.

Code assumes that `ROLE` column contains the name of a role that the user is assigned and users will appear
multiple times in the list if they have multiple roles. Code creates a Local Role for the application with
Uncategorized permissions.

For more detailed examples of how to populate roles with specific permissions see
the `app-csv-import` sample that loads data from multiple sources

Example column headers
USER_ID,USER_NAME,EMAIL,IS_ACTIVE,LAST_LOGIN,ROLE
10001,Adam Thompson,athompson@example.com,1,2023-10-20 13:05:34,Admin
10001,Adam Thompson,athompson@example,1,2023-10-20 13:05:34,User
10003,Bob Smith,bsmith@example,0,2023-03-20 03:34:23,User
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import re
import sys
from datetime import datetime

from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, OAAPermission, OAAPropertyType, LocalUser

# Update the below values for your specific application
PROVIDER_NAME="Demo"
DATASOURCE_NAME="Demo Data"
APP_NAME="App Name"
APP_TYPE= "Demo"

# Optional icon for Veza to display with entities. APP_ICON should be a base64 encoded string of a SVG or PNG and must be less that 64KB
APP_ICON=""""""

# Depending on how the CSV files were exported, the encoding may need to be updated
CSV_ENCODING="utf-8-sig"
# CSV_ENCODING="windows-1252"


# base logger
logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG)
log = logging.getLogger(__name__)


def load_csv(csv_path: str, encoding=CSV_ENCODING) -> list:
    """Read CSV file to list

    Reads a CSV file with a header row into a list of dictionaries
    Args:
        csv_path (str): Path of CSV file to import
        encoding (str): Encoding for reading file, defaults to the global CSV_ENCODING

    Returns:
        list: List of dictionaries for rows
    """

    log.info(f"Reading source file {csv_path}")
    result = []
    with open(csv_path, encoding=encoding, errors="replace") as f:
        data = csv.DictReader(f, skipinitialspace=True)
        for row in data:
            result.append(row)

    length = len(result)
    log.info(f"Finished reading, rows: {length}")
    return result


def process_users_file(app: CustomApplication, csv_file: str) -> None:
    """Process the CSV file to add users and roles

    Args:
        app (CustomApplication): instance of the OAA CustomApplication
        csv_file (str): path to CSV file to read
    """

    # define optional custom properties
    app.property_definitions.define_local_user_property("email", OAAPropertyType.STRING)

    log.info(f"Processing users file: {csv_file}")
    report = load_csv(csv_file)

    for row in report:
        local_user = add_user(app, row)
        if not local_user:
            log.warning("Issue encountered processing user information for row")
            log.warning(row)
            continue

        # Assign role to user
        role_name = row["ROLE"]
        if not role_name:
            # user has no role
            continue

        # create the role if it doesn't already exist
        if role_name not in app.local_roles:
            create_role(app, role_name)

        # assign the user to the role
        local_user.add_role(role_name, apply_to_application=True)

    log.info("Finished processing file")
    return

def add_user(app: CustomApplication, user_info: dict) -> LocalUser|None:
    user_id = user_info["USER_ID"]
    name = user_info["USER_NAME"]

    if not user_id:
        return None

    if user_id in app.local_users:
        return app.local_users[user_id]

    if not name:
        name = user_id

    new_user = app.add_local_user(name=name, unique_id=user_id)

    # email can be used for an identity to connect the local users to IdP Users in Veza
    if user_info.get("EMAIL"):
        new_user.set_property("email", user_info.get("EMAIL"))
        new_user.add_identity(user_info.get("EMAIL"))

    # Interpret the CSV's boolean
    if user_info.get("IS_ACTIVE") == "1":
        new_user.is_active = True
    else:
        new_user.is_active = False

    # example of processing
    last_login_str = user_info.get("LAST_LOGIN")
    if last_login_str:
        try:
            created_at_datetime = datetime.strptime(last_login_str, "%Y-%m-%d %H:%M:%S")
            # Veza expects the timezone info to be added
            new_user.created_at = f"{created_at_datetime.isoformat()}Z"
        except ValueError as e:
            log.error(f"Unable to process created_at date for user: {user_id}, {last_login_str}")

    return new_user

def create_role(app: CustomApplication, role_name: str) -> None:
    """Create a local role from the role name

    Creates a local role. Role is created with a single permission that is the same as the role name
    since we do not have the details of permissions associated with the role.

    Args:
        app (CustomApplication): App object to populate
        role_name (str): name for role
    """


    if not role_name in app.custom_permissions:
        app.add_custom_permission(role_name, permissions=[OAAPermission.Uncategorized])

    app.add_local_role(role_name, unique_id=role_name, permissions=[role_name])

    return


def main():
    parser = argparse.ArgumentParser(description="Simple CSV importer for OAA Application from single file")
    parser.add_argument("--veza-url", required=False, default=os.getenv("VEZA_URL"), help="Hostname for Veza instance")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug output")
    parser.add_argument("--save-json", action="store_true", help="Save OAA JSON payload to file")
    parser.add_argument("source_csv", help="Source CSV file")

    args = parser.parse_args()

    # Ensure all the parameters are supplied and the source file exists
    source_csv = args.source_csv
    if not dir or not os.path.isfile(source_csv):
        log.error(f"Unable to locate source CSV file ")
        log.error("exiting")
        sys.exit(1)

    veza_url = args.veza_url
    if not veza_url:
        log.error("Must supply Veza URL with --veza-url or VEZA_URL environment variable")
        log.error("exiting")
        sys.exit(1)

    veza_api_key = os.getenv("VEZA_API_KEY")
    if not veza_api_key:
        log.error("Unable to load Veza API key from VEZA_API_KEY environment variable")
        log.error("exiting")
        sys.exit(2)

    # Create a instance of the OAAClient to use for making API calls
    try:
        veza_con = OAAClient(url=veza_url, api_key=veza_api_key)
    except OAAClientError as e:
        log.error("Error connecting to Veza tenant")
        log.error(e)
        sys.exit(1)

    # Create a custom application, provide a name and type
    app = CustomApplication(name=APP_NAME, application_type=APP_TYPE)

    # process the CSV file
    process_users_file(app, source_csv)

    # Create provider if necessary
    provider = veza_con.get_provider(PROVIDER_NAME)
    if provider:
        log.info("Found existing provider")
    else:
        log.info("Creating Provider {PROVIDER_NAME}")
        provider = veza_con.create_provider(PROVIDER_NAME, app.TEMPLATE)
    log.info(f"Provider: {provider['name']} ({provider['id']})")

    log.info("Starting push to Veza")
    try:
        if APP_ICON:
            veza_con.update_provider_icon(provider['id'], APP_ICON)
        response = veza_con.push_application(provider['name'], data_source_name=DATASOURCE_NAME, application_object=app, save_json=True)
        if response.get("warnings", None):
            log.warning("Push succeeded with warnings")
            for e in response["warnings"]:
                log.warning(e)
        else:
            log.info("Success")
    except OAAClientError as e:
        log.error(f"{e.error}: {e.message} ({e.status_code})")
        if hasattr(e, "details"):
            for d in e.details:
                log.error(d)
        sys.exit(3)

    log.info("Complete")

if __name__ == "__main__":
    main()
