#!env python3
"""
The HRIS CSV Import sample demonstrates how to populate an OAA Human Resources Information System (HRIS)
template with employee data loaded from a CSV. It can be adapted to support a different CSV schema, additional
columns, or as a basis for processing an API response of employee data.

Dependencies are included in `requirements.txt`

Copyright 2023 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import HRISProvider, OAAPropertyType, IdPProviderType
import click
import csv
import logging
import os
import sys
from datetime import datetime
from dotenv import load_dotenv


logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
log = logging.getLogger()

load_dotenv(dotenv_path="../../.env")

# Update the name of the HRIS Vendor to an appropriate value
HRIS_VENDOR="CSVExample"
# Update the URL to the HRIS Portal URL
HRIS_VENDOR_URL="https://hris.example.com"
# Set the Provider Type to link HRIS employees to. This should be the type of the primary IdP for the environment
IDP_PROVIDER_TYPE=IdPProviderType.OKTA
# Provide a base64 encoded string for the icon. Icon should either be SVG or PNG and less than 64KB
HRIS_ICON_B64 = """
PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxOTIuMjMgMTk4LjY3Ij48ZGVmcz48c3R5bGU+LmNscy0xLC5j
bHMtMntmaWxsOm5vbmU7c3Ryb2tlOiMxNjAwMmQ7c3Ryb2tlLW1pdGVybGltaXQ6MTA7c3Ryb2tlLXdpZHRoOjdweDt9LmNscy0ye3N0cm9rZS1saW5lY2Fw
OnJvdW5kO30uY2xzLTN7ZmlsbDojMTYwMDJkO308L3N0eWxlPjwvZGVmcz48ZyBpZD0iTGF5ZXJfMiIgZGF0YS1uYW1lPSJMYXllciAyIj48ZyBpZD0iTGF5
ZXJfMS0yIiBkYXRhLW5hbWU9IkxheWVyIDEiPjxwYXRoIGNsYXNzPSJjbHMtMSIgZD0iTTM2LjksMTY3LjMzcS0zLjQzLTIuODUtNi41OS02QTkyLjYxLDky
LjYxLDAsMSwxLDE1NSwxNjcuNTgiLz48cGF0aCBjbGFzcz0iY2xzLTEiIGQ9Ik0xMjUuNzQsMTU5LjkzSDE1N2ExLjUsMS41LDAsMCwxLDEuNSwxLjV2MTcu
NjZhMTAsMTAsMCwwLDEtMTAsMTBoLTE0LjNhMTAsMTAsMCwwLDEtMTAtMTBWMTYxLjQzYTEuNSwxLjUsMCwwLDEsMS41LTEuNVoiIHRyYW5zZm9ybT0idHJh
bnNsYXRlKDI1LjQxIDM2Ni44Mykgcm90YXRlKC0xMDkuODkpIi8+PHBhdGggY2xhc3M9ImNscy0xIiBkPSJNNDMuNjksMTU5LjkzSDU4YTEwLDEwLDAsMCwx
LDEwLDEwdjE3LjY2YTEuNSwxLjUsMCwwLDEtMS41LDEuNUgzNS4xOWExLjUsMS41LDAsMCwxLTEuNS0xLjVWMTY5LjkzYTEwLDEwLDAsMCwxLDEwLTEwWiIg
dHJhbnNmb3JtPSJ0cmFuc2xhdGUoLTEzMC41NSAxNjIuOTQpIHJvdGF0ZSgtNzAuMTEpIi8+PGxpbmUgY2xhc3M9ImNscy0yIiB4MT0iMTIxLjg0IiB5MT0i
MTczLjMiIHgyPSIxMDYuNDEiIHkyPSIxNzguNDQiLz48bGluZSBjbGFzcz0iY2xzLTIiIHgxPSIxMjYuOTkiIHkxPSIxODguNzMiIHgyPSIxMTEuNTUiIHky
PSIxOTMuODgiLz48cG9seWdvbiBjbGFzcz0iY2xzLTMiIHBvaW50cz0iNDYuMDkgOTIuMDMgNjEuMjUgMTMxLjYzIDc5Ljk1IDEzMS42MyA2NC43OCA5Mi4w
MyA0Ni4wOSA5Mi4wMyIvPjxyZWN0IGNsYXNzPSJjbHMtMyIgeD0iODYuNzciIHk9IjcxLjE4IiB3aWR0aD0iMTguNyIgaGVpZ2h0PSI2MC40NCIvPjxwb2x5
Z29uIGNsYXNzPSJjbHMtMyIgcG9pbnRzPSIxMTIuMTEgMTMxLjYzIDEzMC44MSAxMzEuNjMgMTQ2LjE1IDkyLjAzIDEyNy40NCA5Mi4wMyAxMTIuMTEgMTMx
LjYzIi8+PGNpcmNsZSBjbGFzcz0iY2xzLTMiIGN4PSI5Ni4xMiIgY3k9IjQ5LjIxIiByPSIxMC45OSIvPjxjaXJjbGUgY2xhc3M9ImNscy0zIiBjeD0iNjgu
OTciIGN5PSI3MS4xOCIgcj0iMTAuOTkiLz48Y2lyY2xlIGNsYXNzPSJjbHMtMyIgY3g9IjEyMy4xIiBjeT0iNzEuMTgiIHI9IjEwLjk5Ii8+PC9nPjwvZz48
L3N2Zz4=
"""

def format_date(date_string: str) -> str:
    # Date strings from the CSV may require some special handling
    # See the below link for format code help to convert the string
    # https://docs.python.org/3/library/datetime.html#strftime-and-strptime-format-codes

    date_obj = datetime.strptime(date_string, "%Y-%m-%d")
    formatted = f"{date_obj.isoformat()}Z"

    return formatted


def load_users(hris: HRISProvider, source: str) -> None:
    """Populate the idp with user from the source csv file"""

    # additional custom properties can be defined and added to employees as needed. Properties must be defined before being set.
    hris.property_definitions.define_employee_property("tshirt_size", OAAPropertyType.STRING)

    log.info(f"Loading users from {source}")
    with open(source) as f:
        for r in csv.DictReader(f):
            # example.csv column headings:
            # employee_number,account,first_name,last_name,display_name,preferred_name,work_email,employment_status,active,title,department,manager,start_date,date_terminated,employment_type
            try:
                employee_number = r["employee_number"]
                display_name = r.get("display_name", "")
                first_name = r["first_name"]
                last_name = r["last_name"]
                is_active_str = r["active"]
                employment_status = r["employment_status"]
            except KeyError as e:
                log.error(f"Incorrect CSV column headers, missing column {e}")
                sys.exit(1)

            if employee_number in hris.employees:
                log.error(f"Employee entry with employee number already processed, employee numbers must be unique. employee_number {employee_number}")
                log.error("skipping row")
                continue

            # Convert the CSV's representation of boolean to Python True/False
            is_active = False
            if is_active_str == "1":
                is_active = True

            employee = hris.add_employee(unique_id=employee_number,
                                         name=display_name,
                                         employee_number=employee_number,
                                         first_name=first_name,
                                         last_name=last_name,
                                         is_active=is_active,
                                         employment_status=employment_status
                                        )

            employee.username = r.get("account", "")
            employee.display_full_name = r.get("display_name", "")
            employee.email = r.get("work_email", "")
            employee.preferred_name = r.get("preferred_name", "")
            employee.job_title = r.get("title", "")

            employment_type = r.get("employment_type")
            if employment_type:
                employee.employment_types.append(employment_type)

            # employee departments must be a group, check that the group exists first then assign
            department = r.get("department")
            if department and department not in hris.groups:
                hris.add_group(unique_id=department, name=department, group_type="Department")
            if department:
                employee.department = department

            manager_id = r.get("manager")
            if manager_id:
                employee.add_manager(manager_id)

            # Date strings from the CSV may require some special handling
            start_date_str = r.get("start_date", "")
            termination_date_str = r.get("date_terminated", "")

            try:
                if start_date_str:
                    employee.start_date = format_date(start_date_str)
                if termination_date_str:
                    employee.start_date = format_date(termination_date_str)
            except ValueError as e:
                log.error(f"Error converting date string, employee number: {employee_number}, error: {e}")

            # Additional employee properties available but not in the example CSV
            employee.company = r.get("company", "")
            employee.canonical_name = r.get("canonical_name", "")
            employee.idp_id = r.get("idp_id", "")
            employee.personal_email = r.get("personal_email", "")
            employee.home_location = r.get("home_location", "")
            employee.work_location = r.get("work_location", "")
            employee.cost_center = r.get("cost_center", "")
            employee.primary_time_zone = r.get("primary_time_zone", "")

            # custom properties are set using the `set_property` method with the name of the property and value
            employee.set_property("tshirt_size", r.get("tshirt_size", ""))

    total_users = len(hris.employees)
    log.info(f"Finished loading users. Users loaded: {total_users}")
    return

@click.command()
@click.option("--veza-url", required=False)
@click.option("--provider-name", required=False)
@click.option("--datasource-name", required=False)
@click.option("--save-json", is_flag=True)
@click.argument("file", required=True)
def main(veza_url, provider_name, datasource_name, save_json, file):

    # load the Veza URL and API key from the environment
    if not veza_url:
        veza_url = os.getenv("VEZA_URL")
    veza_api_key = os.getenv("VEZA_API_KEY")

    if not (veza_url or veza_api_key):
        log.error("Must set VEZA_URL and VEZA_API_KEY")
        sys.exit(1)

    try:
        log.info(f"Testing Veza credentials for {veza_url}")
        veza_con = OAAClient(url=veza_url, api_key=veza_api_key)
        log.info("Connected to Veza tenant")
    except OAAClientError as e:
        log.error("Unable to connect to Veza API")
        log.error(e)
        sys.exit(1)

    # Configure the Custom IdP
    log.info(f"Creating HRIS for {HRIS_VENDOR}")
    hris = HRISProvider(name=HRIS_VENDOR, hris_type=HRIS_VENDOR, url=HRIS_VENDOR_URL)

    # HRIS employees can be automatically linked to IdP users, setting the IdP provider type to use for matching
    # Multiple types can be added by running `add_idp_type` multiple times with different IdPProviderType enums
    hris.system.add_idp_type(IDP_PROVIDER_TYPE)

    # load the user from
    load_users(hris, file)

    if not provider_name:
        provider_name = HRIS_VENDOR
    if not datasource_name:
        datasource_name = f"{HRIS_VENDOR} Datasource"

    log.info(f"Starting submission, provider name {provider_name}")
    provider = veza_con.get_provider(provider_name)
    # create a new provider if the provider doesn't already exist
    if not provider:
        log.info(f"Creating new provider {provider_name}")
        provider = veza_con.create_provider(provider_name, hris.TEMPLATE)

    if HRIS_ICON_B64:
        log.info("Updating provider icon")
        try:
            veza_con.update_provider_icon(provider["id"], HRIS_ICON_B64)
        except OAAClientError as e:
            log.error(f"Error setting icon {e.message} {e.status_code}")
            if e.details:
                log.error(e.details)
            pass

    try:
        # push the IdP to Veza, log and errors or warnings
        log.info("Sending to Veza")
        response = veza_con.push_application(provider_name, datasource_name, hris, save_json=save_json)
        if response.get("warnings", None):
            log.warning("Push succeeded with warnings")
            for w in response['warnings']:
                log.warning(w)
        log.info("Success")
    except OAAClientError as e:
        log.error(f"Error during push {e.message} {e.status_code}")
        if e.details:
            log.error(e.details)
        log.error("exiting with error")
        sys.exit(1)

    return

if __name__ == "__main__":
    main()
