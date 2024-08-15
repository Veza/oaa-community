#!/usr/bin/env python3

import argparse
import csv
import logging
import os
import sys

import oaaclient.utils as oaautils

from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, CustomPermission, OAAPermission, OAAPropertyType, LocalRole

from dotenv import load_dotenv

# Depending on how the CSV files were exported, the encoding may need to be updated
CSV_ENCODING="utf-8-sig"
# CSV_ENCODING="windows-1252"

logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)

load_dotenv(dotenv_path="../../.env")

# a map of strings to OAAPermission types
PERMISSIONS_MAP = {
    "datadelete": [OAAPermission.DataDelete],
    "dataread": [OAAPermission.DataRead],
    "datawrite": [OAAPermission.DataWrite],
    "metadataread": [OAAPermission.MetadataRead],
    "metadatawrite": [OAAPermission.MetadataWrite],
    "nondata": [OAAPermission.NonData],
    "read": [OAAPermission.DataRead],
    "view": [OAAPermission.MetadataRead],
    "write": [OAAPermission.DataWrite]
}

# pre-defined common role names
DEFAULT_ROLE_PERMISSIONS = {
    "admin": ["datadelete", "dataread", "datawrite", "metadataread", "metadatawrite"],
    "viewer": ["view"]
}


def validate_csv(headers: list[str], entries: list[dict[str, str]], path: str) -> bool:
    """Validate CSV Headers

    Ensures that required headers exist in the data read from CSV

    Args:
        headers (list[str]): a list of headers to validate
        entry (dict[str, str]): an entry in the processed CSV file
        path (str): the path to the CSV file
    """
    # return False if there are no entries in the CSV (to avoid iterating)
    if len(entries) == 0:
        return False
    else:
        entry = entries[0]
        for header in headers:
            if not header in entry:
                log.error(f"cannot find required header {header} in csv {path}")
                sys.exit(1)

    # entries exist and headers are valid
    return True


def read_csv(path: str, encoding=CSV_ENCODING) -> list:
    """Read CSV Helper

    Args:
        path (str): path to CSV file
        encoding (str): Encoding for reading file, defaults to the global CSV_ENCODING

    Returns:
        list: list of rows as dictionaries
    """

    result = []

    try:
        with open(path, encoding=encoding, errors="replace") as f:
            for r in csv.DictReader(f):
                result.append(r)
    except OSError as e:
        log.error(f"Error reading from csv file: {path}")
        log.error(e)
        sys.exit(1)

    return result


def create_role(app: CustomApplication, role_name: str, permissions: list = None) -> LocalRole:
    """Create a role

    If no permissions provided for the role, create a single permission with the same name as the role
    as the role for the role to have

    Args:
        app (CustomApplication): OAA Custom Application object
        role_name (str): Name of role
        permissions (list): Optional list of permission names. Defaults to None.

    Returns:
        LocalRole: New OAA Local Role
    """

    # the role already exists; return it
    if role_name in app.local_roles:
        return app.local_roles.get(role_name)

    # create a permission with the same name as the role
    if not role_name in app.custom_permissions:
        app.add_custom_permission(role_name, permissions=[OAAPermission.NonData])

    # create the role and return it
    new_role = app.add_local_role(role_name, unique_id=role_name, permissions=[role_name])
    return new_role


def load_groups(app: CustomApplication, group_csv_path: str) -> None:
    """Load group assignments

    Assigns users to groups based on entries in the CSV file, will create the groups
    as it goes the first time it sees a group ID.

    Args:
        app (CustomApplication): OAA Custom Application object
        group_csv_path (str): path to CSV containing group assignments
    """

    # check if file exists
    if not os.path.isfile(group_csv_path):
        log.warning(f"no groups file found, skipping groups: {group_csv_path}")
        return

    # load the csv data into a dict
    log.info(f"Loading groups from {group_csv_path}")
    group_entries = read_csv(group_csv_path)

    # validate header columns and file data
    if validate_csv(["group_id", "user_name"], group_entries, group_csv_path):

        # add groups to CustomApplication
        for group_entry in group_entries:
            group_id = group_entry.get("group_id")

            # group hasn't been created yet, create before assigning user
            if group_id not in app.local_groups:

                # get the group_name, use the group_id as name if not present
                group_name = group_entry.get("group_name", group_id)

                # create the new group
                app.add_local_group(name = group_name, unique_id = group_id)

            user_name = group_entry.get("user_name")

            # add the group to the user entity
            if user_name in app.local_users:
                app.local_users[user_name].add_group(group_id)
            else:
                log.warning(f"Group assigned to unknown user: {group_entry}; skipping")

        log.info("finished loading groups")
    else:
        log.warning(f"groups file {group_csv_path} empty; skipping")

    return


def load_permissions(app: CustomApplication, permissions_csv_path: str) -> None:
    """Load Permissions definitions

    Creates custom permissions to map app-defined permissions to Veza canonical permissions

    Args:
        app (CustomApplication): OAA Custom Application object
        permissions_csv_path (str): path to CSV containing permissions

    CSV Columns:
        permission (required): the name of the application-defined permission
        oaapermission (required): the OAA permission type to map to
    """

    if not os.path.isfile(permissions_csv_path):
        log.warning(f"no permissions file found; skipping custom permissions: {permissions_csv_path}")
        return


    # load pre-defined permissions
    log.info(f"loading permissions from {permissions_csv_path}")
    permission_entries = read_csv(permissions_csv_path)

    # validate header columns and file data
    if validate_csv(["permission", "oaapermission"], permission_entries, permissions_csv_path):

        # add csv-defined permissions to the DEFAULT_PERMISSIONS dictionary
        for permission in permission_entries:
            # get OAAPermission type from CSV string data
            permission_name = permission.get("permission")
            canonical_permission = PERMISSIONS_MAP.get(permission.get("oaapermission"))
        if canonical_permission:
            app.define_custom_permission(CustomPermission(permission_name, canonical_permission))
        else:
            log.warning(f"permission {permission}: {permission_entries[permission]} could not be mapped to Veza canonical permission type; setting to NonData")
            app.define_custom_permission(CustomPermission(permission, [OAAPermission.NonData]))
    else:
        log.warning(f"permissions file {permissions_csv_path} empty; skipping")

    # add default permissions
    for permission in PERMISSIONS_MAP:
        app.define_custom_permission(CustomPermission(permission, PERMISSIONS_MAP[permission]))

    return None


def load_role_permissions(app: CustomApplication, role_permissions_csv_path: str) -> None:
    """Load Role permissions

    Args:
        app (CustomApplication): OAA Custom Application object
        role_permissions_csv_path (str): path to CSV containing role permissions

    CSV Columns:
        permission (required): the name of the application-defined permission
        role_name (required): the name of the role
    """

    # check if file exists
    if not os.path.isfile(role_permissions_csv_path):
        log.warning(f"no role permissions mapping file found at {role_permissions_csv_path}")
        log.warning("roles will not have detailed permissions")
        return

    # load the csv data into a dict
    log.info(f"loading roles and permissions from {role_permissions_csv_path}")
    permission_entries = read_csv(role_permissions_csv_path)

    # validate header columns and file data
    if validate_csv(["role_name", "permission"], permission_entries, role_permissions_csv_path):

        # add csv-defined permissions to local roles
        for permission_entry in permission_entries:
            role_name = permission_entry.get("role_name")

            # create the role if it doesn't exist
            if role_name not in app.local_roles:
                role = app.add_local_role(name=role_name, unique_id = role_name, permissions=[])
            else:
                role = app.local_roles.get(role_name)

            permission = permission_entry.get("permission")
            role.add_permissions([permission])

        log.info("finished loading roles and permissions from csv")
    else:
        log.warning(f"role permissions file {role_permissions_csv_path} empty; skipping")

    # load default role permissions
    log.info("loading default role permissions")
    for role in DEFAULT_ROLE_PERMISSIONS:
        # only apply default role permissions if the role name isn't explicitly defined in csv
        if role not in app.local_roles:
            app.add_local_role(name = role, unique_id = role, permissions = DEFAULT_ROLE_PERMISSIONS[role])
        else:
            log.info(f"role {role_name} explicitly defined in CSV; skipping default permissions assignment")
    return


def load_roles(app: CustomApplication, roles_csv_path: str) -> None:
    """Load Role assignments

    Args:
        app (CustomApplication): OAA Custom Application object
        roles_csv_path (str): path to CSV containing role assignments

    CSV Columns:
        role_name (required): the name of the role
        group_id (optional): the group id to which the role is assigned
        user_name (optional): the user to which the role is assigned
    """

    # check if file exists
    if not os.path.isfile(roles_csv_path):
        log.error(f"unable to locate required roles csv file at path {roles_csv_path}")
        sys.exit(1)

    # load the csv data into a dict
    log.info(f"Loading role assignments from {roles_csv_path}")
    role_assignments = read_csv(roles_csv_path)

    # validate header columns and file data
    if validate_csv(["role_name"], role_assignments, roles_csv_path):

        # add roles to the CustomApplication
        for role_assignment in role_assignments:
            role_name = role_assignment.get("role_name")
            if not role_name in app.local_roles:
                create_role(app, role_name)

            # roles can be assigned to users or groups; attempt to get both now
            group_id = role_assignment.get("group_id")
            user_name = role_assignment.get("user_name")

            # ensure that the role is assigned to a user or group
            if not group_id and not user_name:
                log.warning(f"no group_id or user_name assignment defined for role {role_name}; skipping")
                continue

            # apply the role to the group if found
            if group_id:
                if group_id in app.local_groups:
                    app.local_groups[group_id].add_role(role_name, apply_to_application = True)
                else:
                    log.warning(f"group {group_id} not found in application; skipping role assignment")

            # add the role to the user if found
            if user_name:
                if user_name in app.local_users:
                    app.local_users[user_name].add_role(role_name, apply_to_application = True)
                else:
                    log.warning(f"user {user_name} not found in application; skipping role assignment")

        log.info("finished loading roles")
    else:
        log.warning(f"roles file {roles_csv_path} empty; skipping")
    return


def load_users(app: CustomApplication, users_csv_path: str) -> None:
    """Load Users

    Creates OAA Local users from the information in the provided CSV file

    Args:
        app (CustomApplication): OAA Custom Application object
        users_csv_path (str): path to CSV containing users

    CSV Columns:
        user_name (required): the username of the user
        full_name (optional): the full name of the user
        email (optional): the email address of the user
        created_at (optional): the timestamp at which the user was created
        last_login (optional): the timestamp of the user's last login
        is_active (optional): "true" or "false" denoting if the user account is active
    """

    # check if file exists
    if not os.path.isfile(users_csv_path):
        log.error(f"unable to locate required users csv file at path {users_csv_path}")
        sys.exit(1)

    # load the csv data into a dict
    log.info(f"Loading users from {users_csv_path}")
    user_entries = read_csv(users_csv_path)

    # Define any necessary custom properties
    app.property_definitions.define_local_user_property("email", OAAPropertyType.STRING)

    # validate header columns and file data
    if validate_csv(["user_name"], user_entries, users_csv_path):

        # add users to CustomApplication
        for user_entry in user_entries:
            user_name = user_entry.get("user_name")
            if not user_name:
                # no user_name defined; likely an empty row - skip
                continue

            full_name = user_entry.get("full_name")
            if not full_name:
                # if no full name, use the user_name as the full name
                full_name = user_name

            # add the user to the CustomApplication
            new_user = app.add_local_user(name=full_name, unique_id=user_name)

            # if there is an email, add it to the user as an identity
            if user_entry.get("email"):
                new_user.add_identity(user_entry["email"])
                new_user.set_property("email", user_entry["email"])

            # populate created_at and last_login timestamps if found
            created_at = user_entry.get("created_at")
            if created_at:
                new_user.created_at = created_at
            last_login = user_entry.get("last_login")
            if last_login:
                new_user.last_login_at = last_login

            # set is_active based on the strings "true" and "false" from the csv
            if user_entry.get("is_active") == "true":
                new_user.is_active = True
            elif user_entry.get("is_active") == "false":
                new_user.is_active = False

        log.info("finished loading users")
    else:
        log.error(f"users csv file {users_csv_path} empty; aborting")
        sys.exit(1)
    return


# def run(veza_url: str, veza_api_key: str, provider_name: str, datasource_name: str, save_json: bool = False, debug: bool = False) -> None:
def run(veza_url: str, veza_api_key: str, application_name: str, save_json: bool, debug: bool = False) -> None:
    if debug:
        log.setLevel(logging.DEBUG)
        log.debug("Debug logging enabled")

    veza_con = OAAClient(veza_url, api_key=veza_api_key)

    app = CustomApplication(name= application_name, application_type="OAA CSV App")

    load_permissions(app, permissions_csv_path = "permissions.csv")
    load_role_permissions(app, role_permissions_csv_path="role_permissions.csv")
    load_users(app, users_csv_path="users.csv")
    load_groups(app, group_csv_path="groups.csv")
    load_roles(app, roles_csv_path="roles.csv")

    # provider = veza_con.get_provider(provider_name)
    provider = veza_con.get_provider(application_name)
    if provider:
        log.info("Found existing provider")
    else:
        log.info("Creating Provider {provider_name}")
        provider = veza_con.create_provider(application_name, "application", base64_icon=OAA_ICON_B64)
    log.info(f"Provider: {provider['name']} ({provider['id']})")

    #push data
    log.info("Starting push to Veza")
    #print(app.local_roles)
    a = True
    if a:
        try:
            response = veza_con.push_application(provider['name'], data_source_name=application_name, application_object=app, save_json=save_json)
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

    return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--application-name", required = True, help = "Name for the custom application")
    parser.add_argument("--debug", action = "store_true", help = "Enable verbose debug output")
    parser.add_argument("--save-json", action = "store_true", help = "Save OAA JSON payload to file")
    parser.add_argument("--veza-url", required = False, default = os.getenv("VEZA_URL"), help = "Hostname for Veza instance")
    args = parser.parse_args()

    veza_url = args.veza_url
    veza_api_key = os.getenv('VEZA_API_KEY', "")
    if not veza_url:
        oaautils.log_arg_error(log, "--veza-url", "VEZA_URL")
    if not veza_api_key:
        oaautils.log_arg_error(log, env="VEZA_API_KEY")

    if None in [veza_url, veza_api_key]:
        log.error("Missing one or more required parameters")
        sys.exit(1)

    run(veza_url=veza_url, veza_api_key=veza_api_key, application_name = args.application_name, save_json=args.save_json, debug=args.debug)

    return

# base64-encoded icon for display on the Veza platform
OAA_ICON_B64="""
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
"""

if __name__ == "__main__":
    main()