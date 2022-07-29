#!env python3
"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by a the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

from dateutil import parser as dateutil_parser
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, OAAPermission, OAAPropertyType
from requests.exceptions import HTTPError
from urllib.parse import urlparse
import argparse
import json
import logging
import os
import re
import requests
import sys

# set up logging
log = logging.getLogger(__name__)

# set a validated minimum supported salesforce version
MINIMUM_SFDC_VERSION = 29.0

class OAA_SFDC_LightningAPI():
    def __init__(self, client_id, client_secret, password, username):
        """
        configure the Lightning API client for data requests
        """
        base_url, oauth_token = self.authenticate(client_id, client_secret, password, username)

        self.base_url = f"{base_url}/services/data"
        self.oauth_token = oauth_token
        self.request_headers = self.set_oauth_headers()
        self.sfdc_version = self.set_api_version()
        self.base_url = f"{self.base_url}/v{self.sfdc_version}"

        self.app = CustomApplication(f"Salesforce.com", "Salesforce")
        self.app.property_definitions.define_local_user_property("user_type", OAAPropertyType.STRING)
        self._objects_filter = []
        self.discover_all_users = False
        # user map
        self.users = {}

        # populate OAA permissions
        self.__populate_permissions()

    def authenticate(self, client_id, client_secret, password, username):
        """
        use username-password authentication to retrieve an Oauth2 token
        """
        login_url = "https://login.salesforce.com/services/oauth2/token"
        login_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "password",
            "password": password,
            "username": username
        }

        log.debug(f"authenticating via password authentication to {login_url}")
        response = requests.post(login_url, data = login_data)

        # process login response
        if not response.ok:
            raise HTTPError(response.text, response = response)
        body = response.json()
        if not "access_token" in body:
            log.error(f"could not authenticate to salesforce")
            log.error(json.dumps(response.json()))
            sys.exit(1)
        else:
            access_token = body.get("access_token")
            instance_url = body.get("instance_url")
            return (instance_url, access_token)

    def update_objects_filter(self, objects_filter: list) -> None:
        self._objects_filter = [o.lower() for o in objects_filter]
        return

    def discover(self):
        """
        run the OAA discovery against the Salesforce instance
        """
        log.info("starting salesforce.com discovery")
        self.discover_users()
        self.discover_permissions_sets()
        self.discover_object_types()
        return


    def discover_object_types(self):
        """
        discover Salesforce object types and assign OAA permissions to permissions sets
        """
        log.info("discovering salesforce.com object types")
        object_types = self.list_object_types_and_permissions()

        for object_name in object_types:
            object_type = object_types.get(object_name)
            if self._objects_filter and object_name.lower() not in self._objects_filter:
                continue
            object_resource = self.app.add_resource(object_name, "object_type")

            # iterate object_type permissions and translate them to displayed permissions
            for permissions_set_id in object_type.get("permissions"):
                translated_permissions = self.__translate_permissions(object_type.get("permissions").get(permissions_set_id))
                if permissions_set_id not in self.permissions_sets:
                    log.warning(f"Permission set id not found in discovered permission sets, id {permissions_set_id}")
                    continue

                permissions_set_name = self.permissions_sets[permissions_set_id].get("name")

                if re.match(r"^\w00", permissions_set_name):
                    # profile-based (X00...) permissions set; apply permissions to OAA users
                    assignees = self.permissions_sets.get(permissions_set_id).get("users")

                    # iterate translated permissions and apply them
                    for permission in translated_permissions:
                        for assignee_id in assignees:
                            if assignee_id not in self.users:
                                log.warning(f"Unknown user assigned to permission, permission: '{permission}', user_id: {assignee_id}")
                                continue

                            username = self.users.get(assignee_id).get("Username")
                            self.app.local_users[username].add_permission(permission, resources = [object_resource], apply_to_application = False)
                else:
                    # non-profile-based permissions set; apply permissions to OAA group
                    for permission in translated_permissions:
                        if permissions_set_name not in self.app.local_groups:
                            log.warning(f"local group for permission set did not exists. {permissions_set_name}")
                            continue
                        self.app.local_groups[permissions_set_name].add_permission(permission, resources = [object_resource], apply_to_application = False)


    def discover_permissions_sets(self):
        """
        discover Salesforce permissions sets and create OAA groups from them
        """
        log.info("discovering salesforce.com permissions sets")
        self.permissions_sets = self.list_permissions_sets_with_assignments()
        for permissions_set_id in self.permissions_sets:
            permissions_set = self.permissions_sets.get(permissions_set_id)
            permission_set_name = permissions_set.get("name")

            # don't create OAA groups for "X00..." profile-based permissions sets
            if re.match(r"^\w00", permission_set_name):
                continue

            self.app.add_local_group(permission_set_name)

            # add assignees to local_group
            for user_id in permissions_set.get("users"):
                user = self.users.get(user_id)
                if not user:
                    log.warning(f"Unknown user assigned to permission set, permission set: '{permission_set_name}', user_id: {user_id}")
                    continue
                self.app.local_users[user.get("Username")].add_group(permission_set_name)

        return


    def discover_users(self):
        """
        discover Salesforce users
        """
        log.info("discovering salesforce.com users")
        all_users = self.list_users()
        for user in all_users:
            username = user["Username"]
            user_id = user["Id"]
            email = user["Id"]
            is_active = user["IsActive"]
            last_login_at = user["LastLoginDate"]
            user_type = user["UserType"]

            # add user name reference to user map
            self.users[user_id] = {"Username": username}

            new_user = self.app.add_local_user(username, identities = [username])
            new_user.is_active = is_active

            if last_login_at:
                # convert last_login to RFC3339 format
                new_user.last_login_at = dateutil_parser.parse(last_login_at).isoformat()

            new_user.set_property("user_type", user_type)
            # new_user.set_property("email", email)

        discovered_count = len(self.users)
        log.debug(f"Discovered number of users: {discovered_count}")


    def list_object_types_and_permissions(self):
        """
        list object types and attached permissions sets
        """
        object_types = {}

        response = self.__soql_query_all(object="ObjectPermissions", fields=["Id", "Parent.Id", "SobjectType", "PermissionsCreate", "PermissionsDelete", "PermissionsEdit", "PermissionsModifyAllRecords", "PermissionsRead", "PermissionsViewAllRecords"])
        for item in response:
            # build a dict of permissions in the permissions set
            permissions = {
                "PermissionsCreate": item.get("PermissionsCreate"), "PermissionsDelete": item.get("PermissionsDelete"),
                "PermissionsEdit": item.get("PermissionsEdit"), "PermissionsModifyAllRecords": item.get("PermissionsModifyAllRecords"),
                "PermissionsRead": item.get("PermissionsRead"), "PermissionsViewAllRecords": item.get("PermissionsViewAllRecords")
            }

            if object_types.get(item.get("SobjectType")):
                object_types[item.get("SobjectType")].get("permissions")[item.get("Parent").get("Id")] = permissions
            else:
                object_types[item.get("SobjectType")] = {
                    "permissions": {item.get("Parent").get("Id"): permissions}
                }

        return object_types


    def list_permissions_sets_with_assignments(self):
        """
        list permissions sets with user assignments
        """
        permissions_sets = {}

        response = self.__soql_query_all(object="PermissionSet", fields=["name", "Id", "(SELECT AssigneeId FROM Assignments)"])
        for permissions_set in response:
            assignments = permissions_set.get("Assignments")
            if assignments:
                users = []
                for assignee in assignments.get("records"):
                    users.append(assignee.get("AssigneeId"))

                permissions_sets[permissions_set.get("Id")] = {
                    "name": permissions_set.get("Name"),
                    "users": users
                }
            else:
                permissions_sets[permissions_set.get("Id")] = {
                    "name": permissions_set.get("Name"),
                    "users": []
                }

        return permissions_sets


    def list_roles(self):
        """
        list salesforce roles
        TODO: unused
        """
        roles = {}

        response = self.__soql_query_all(object="name", fields=["id", "name"],)
        for role in response:
            roles[role.get("Id")] = {
                "name": role.get("Name")
            }

        return roles


    def list_users(self):
        """
        list salesforce users
        """
        users = {}

        fields = ["id", "username", "email", "isActive", "LastLoginDate", "UserRoleId", "UserType"]
        if self.discover_all_users:
            filters = []
        else:
            filters = ["UserType='standard'"]
        response = self.__soql_query_all(object="user", fields=fields, filters=filters)

        return response


    def __populate_permissions(self):
        """
        map Salesforce permissions to OAA canonical permissions
        """
        permissions = {
            "Create": [OAAPermission.DataCreate, OAAPermission.MetadataCreate],
            "Delete": [OAAPermission.DataDelete, OAAPermission.MetadataDelete],
            "Edit": [OAAPermission.DataWrite, OAAPermission.MetadataWrite],
            "ModifyAllRecords": [OAAPermission.DataWrite, OAAPermission.MetadataWrite],
            "Read": [OAAPermission.DataRead, OAAPermission.MetadataRead],
            "ViewAllRecords": [OAAPermission.DataRead, OAAPermission.MetadataRead]
        }

        for permission in permissions:
            self.app.add_custom_permission(permission, permissions[permission])


    def __soql_query_all(self, object: str, fields: list, filters: list = None):
        """
        make an API GET request to the salesforce endpoint
        manually aggregate paginated results
        """
        result = []

        if not any(["id" == f.lower() for f in fields]):
            # if id not in the list of fields add it
            fields.append("id")

        limit = 2_000

        fields_str = ", ".join(fields)
        if not filters:
            filters_str = ""
        elif len(filters) == 1:
            filters_str = f"WHERE {filters[0]}"
        else:
            filters_str = f"WHERE {filters[0]} " + "AND ".join(filters[1:-1] + filters[-1])

        query = f"SELECT {fields_str} FROM {object} {filters_str} ORDER BY id ASC LIMIT {limit}"

        while True:
            api_path = f"{self.base_url}/queryAll/?q={query}"
            log.debug(f"query string: '{query}'")
            response = requests.get(api_path, headers = self.request_headers)

            if not response.ok:
                raise HTTPError(response.text, response=response)

            body = response.json()

            if "records" in body:
                records = body["records"]
                if not records:
                    # no more records
                    break

                result.extend(records)
                last_record = records[-1]

                if filters_str:
                    next_filters_str = f"{filters_str} AND id > '{last_record['Id']}'"
                else:
                    next_filters_str = f"WHERE id > '{last_record['Id']}'"

                query = f"SELECT {fields_str} FROM {object} {next_filters_str} ORDER BY id ASC LIMIT {limit}"

            else:
                log.warning(f"unexpected HTTP GET response")
                log.warning(body)

        return result


    def set_api_version(self):
        """
        verify that the salesforce instance is at or above minimum supported version
        """
        log.debug(f"verifying {self.base_url} is at or above version {MINIMUM_SFDC_VERSION}")
        response = requests.get(self.base_url, headers = self.request_headers)

        # process response
        if not response.ok:
            raise HTTPError(response.text, response=response)
        body = response.json()

        if type(body) is list:
            try:
                latest_version = float(body[-1].get("version"))

                if latest_version >= MINIMUM_SFDC_VERSION:
                    return str(MINIMUM_SFDC_VERSION)
                else:
                    log.error(f"version {latest_version} is below minimum supported version {MINIMUM_SFDC_VERSION}")
                    sys.exit(1)

            except Exception as e:
                log.error(f"unexpected response from salesforce API - {e}")
                log.error(body)
                sys.exit(1)
        else:
            log.error("unexpected response from salesforce API version query")
            sys.exit(1)


    def set_oauth_headers(self):
        """
        set headers for Bearer authentication after retreiving a token
        """
        if self.oauth_token:
            return {"accept": "application/json", "authorization": f"Bearer {self.oauth_token}"}
        else:
            log.error("attempted to set request headers without authenticating")
            sys.exit(1)


    def __translate_permissions(self, permissions):
        """
        translate salesforce object type permissions into OAA permissions
        """
        oaa_permissions = []

        if permissions.get("PermissionsCreate"):
            oaa_permissions.append("Create")

        if permissions.get("PermissionsDelete"):
            oaa_permissions.append("Delete")

        if permissions.get("PermissionsEdit"):
            oaa_permissions.append("Edit")

        if permissions.get("PermissionsModifyAllRecords"):
            oaa_permissions.append("ModifyAllRecords")

        if permissions.get("PermissionsRead"):
            oaa_permissions.append("Read")

        if permissions.get("PermissionsViewAllRecords"):
            oaa_permissions.append("ViewAllRecords")

        return oaa_permissions


def log_arg_error(arg = None, env = None):
    """
    log missing arguments and environmental variables
    """
    if arg and env:
        log.error(f"Unable to load required parameter; must supply {arg} or set OS environment variable {env}")
    elif arg and not env:
        log.error(f"Unable to load required parameter; must supply {arg}")
    elif env:
        log.error(f"Unable to load required parameter; must set OS environment variable {env}")
    else:
        raise Exception("Must provide arg or env to include in error message")
    return


def run(veza_api_key, veza_url, sfdc_client_id, sfdc_client_secret, sfdc_password, sfdc_user, objects_filter = None, discover_all_users = False, save_json = False):
    """
    run full OAA process; discover Salesforce entities, prepare OAA template, and push metadata to Veza
    """
    try:
        conn = OAAClient(url = veza_url, api_key = veza_api_key)
    except OAAClientError as error:
        log.error(f"Unable to connect to Veza {veza_url}")
        log.error(error.message)
        raise error

    salesforce_app = OAA_SFDC_LightningAPI(sfdc_client_id, sfdc_client_secret, sfdc_password, sfdc_user)

    if objects_filter:
        salesforce_app.update_objects_filter(objects_filter)

    salesforce_app.discover_all_users = discover_all_users
    try:
        salesforce_app.discover()
    except HTTPError as error:
        log.error(f"Error during discovery: Salesforce API returned error: {error.response.status_code} for {error.response.url}")
        log.error(error)
        raise error

    provider_name = "Salesforce"
    provider = conn.get_provider(provider_name)

    if provider:
        log.info("found existing provider")
    else:
        log.info(f"creating provider {provider_name}")
        provider = conn.create_provider(provider_name, "application")
    log.info(f"provider: {provider['name']} ({provider['id']})")

    # push data to Veza
    data_source_name = urlparse(salesforce_app.base_url).netloc
    try:
        log.debug("Updating Provider logo")
        conn.update_provider_icon(provider["id"], SFDC_SVG_B64)
        log.info("uploading custom application data")
        conn.push_application(
            provider_name,
            data_source_name = data_source_name,
            application_object = salesforce_app.app,
            save_json = save_json
        )
        log.info("success")
    except OAAClientError as error:
        log.error(f"{error.error}: {error.message} ({error.status_code})")
        if hasattr(error, "details"):
            for detail in error.details:
                log.error(f"  {detail}")
        raise error

def main():
    """
    process comand line and OS environment variables, then call `run`
    """
    parser = argparse.ArgumentParser(description = "OAA Salesforce Connector")
    parser.add_argument("--veza_url", default = os.getenv("VEZA_URL"), help = "the URL of the Veza instance")
    parser.add_argument("--debug", action = "store_true", help = "set the log level to debug")
    parser.add_argument("--save_json", action = "store_true", help = "save OAA JSON payload to file")
    parser.add_argument("--sfdc_client_id", default = os.getenv("SFDC_CLIENT_ID"), help = "the client ID used to authenticate to salesforce.com")
    parser.add_argument("--sfdc_user", default = os.getenv("SFDC_USER"), help = "the username with which to authenticate to salesforce.com")
    parser.add_argument("--filter_objects", nargs="*", help="Optional list of SFDC object types to limit discovery to" )
    parser.add_argument("--all_users", action = "store_true", help="Discover all user of all types, default is to only collect standard users")
    args = parser.parse_args()

    veza_api_key = os.getenv("VEZA_API_KEY")
    veza_url = args.veza_url
    save_json = args.save_json
    sfdc_client_id = os.getenv("SFDC_CLIENT_ID")
    sfdc_client_secret = os.getenv("SFDC_CLIENT_SECRET")
    sfdc_password = os.getenv("SFDC_PASSWORD")
    sfdc_user = args.sfdc_user

    # configure the log level
    if args.debug:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    if not veza_api_key:
        log_arg_error(None, "VEZA_API_KEY")
    if not veza_url:
        log_arg_error("--veza_url", "VEZA_URL")
    if not sfdc_client_id:
        log_arg_error("--sfdc_client_id", "SFDC_CLIENT_ID")
    if not sfdc_client_secret:
        log_arg_error(None, "SFDC_CLIENT_SECRET")
    if not sfdc_password:
        log_arg_error(None, "SFDC_PASSWORD")
    if not sfdc_user:
        log_arg_error("--sfc_user", "SFDC_USER")

    objets_filter = args.filter_objects
    discover_all_users = args.all_users
    # ensure required variables are provided
    if None in [veza_api_key, veza_url, sfdc_client_id, sfdc_client_secret, sfdc_password, sfdc_user]:
        log.error(f"missing one or more required parameters")
        sys.exit(1)

    try:
        run(veza_api_key, veza_url, sfdc_client_id, sfdc_client_secret, sfdc_password, sfdc_user, objets_filter, discover_all_users, save_json)
    except OAAClientError:
        log.error("Exiting with error")
        sys.exit(1)
    except HTTPError:
        log.error("Exiting with error")
        sys.exit(1)

SFDC_SVG_B64="""
PHN2ZyB2ZXJzaW9uPSIxLjEiIHZpZXdCb3g9IjAgMCAyNzMgMTkxIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOmNjPSJodHRw
Oi8vY3JlYXRpdmVjb21tb25zLm9yZy9ucyMiIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1sbnM6cmRmPSJodHRwOi8v
d3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI+Cjx0aXRsZT5T
YWxlc2ZvcmNlLmNvbSBsb2dvPC90aXRsZT4KPGRlc2M+QSBjbG91ZCBjb21wdXRpbmcgY29tcGFueSBiYXNlZCBpbiBTYW4gRnJhbmNpc2NvLCBDYWxpZm9y
bmlhLCBVbml0ZWQgU3RhdGVzPC9kZXNjPgogPG1ldGFkYXRhPgogIDxyZGY6UkRGPgogICA8Y2M6V29yayByZGY6YWJvdXQ9IiI+CiAgICA8ZGM6Zm9ybWF0
PmltYWdlL3N2Zyt4bWw8L2RjOmZvcm1hdD4KICAgIDxkYzp0eXBlIHJkZjpyZXNvdXJjZT0iaHR0cDovL3B1cmwub3JnL2RjL2RjbWl0eXBlL1N0aWxsSW1h
Z2UiLz4KICAgIDxkYzp0aXRsZS8+CiAgIDwvY2M6V29yaz4KICA8L3JkZjpSREY+CiA8L21ldGFkYXRhPgogPGRlZnM+CiAgPHBhdGggaWQ9ImEiIGQ9Im0w
LjA2IDAuNWgyNzJ2MTkwaC0yNzJ6Ii8+CiA8L2RlZnM+CiA8ZyBmaWxsLXJ1bGU9ImV2ZW5vZGQiPgogIDxtYXNrIGlkPSJiIiBmaWxsPSIjZmZmIj4KICAg
PHVzZSB4bGluazpocmVmPSIjYSIvPgogIDwvbWFzaz4KICA8cGF0aCBkPSJtMTEzIDIxLjNjOC43OC05LjE0IDIxLTE0LjggMzQuNS0xNC44IDE4IDAgMzMu
NiAxMCA0MiAyNC45YTU4IDU4IDAgMCAxIDIzLjctNS4wNWMzMi40IDAgNTguNyAyNi41IDU4LjcgNTkuMnMtMjYuMyA1OS4yLTU4LjcgNTkuMmMtMy45NiAw
LTcuODItMC4zOTgtMTEuNi0xLjE1LTcuMzUgMTMuMS0yMS40IDIyLTM3LjQgMjJhNDIuNyA0Mi43IDAgMCAxLTE4LjgtNC4zMmMtNy40NSAxNy41LTI0Ljgg
MjkuOC00NSAyOS44LTIxLjEgMC0zOS0xMy4zLTQ1LjktMzJhNDUuMSA0NS4xIDAgMCAxLTkuMzQgMC45NzJjLTI1LjEgMC00NS40LTIwLjYtNDUuNC00NS45
IDAtMTcgOS4xNC0zMS44IDIyLjctMzkuOGE1Mi42IDUyLjYgMCAwIDEtNC4zNS0yMWMwLTI5LjIgMjMuNy01Mi44IDUyLjktNTIuOCAxNy4xIDAgMzIuNCA4
LjE1IDQyIDIwLjgiIGZpbGw9IiMwMEExRTAiIG1hc2s9InVybCgjYikiLz4KICA8cGF0aCBkPSJtMzkuNCA5OS4zYy0wLjE3MSAwLjQ0NiAwLjA2MSAwLjUz
OSAwLjExNiAwLjYxOCAwLjUxMSAwLjM3IDEuMDMgMC42MzggMS41NSAwLjkzOSAyLjc4IDEuNDcgNS40IDEuOSA4LjE0IDEuOSA1LjU4IDAgOS4wNS0yLjk3
IDkuMDUtNy43NXYtMC4wOTRjMC00LjQyLTMuOTItNi4wMy03LjU4LTcuMThsLTAuNDc5LTAuMTU1Yy0yLjc3LTAuODk4LTUuMTYtMS42OC01LjE2LTMuNXYt
MC4wOTNjMC0xLjU2IDEuNC0yLjcxIDMuNTYtMi43MSAyLjQgMCA1LjI2IDAuNzk5IDcuMDkgMS44MSAwIDAgMC41NDIgMC4zNSAwLjczOS0wLjE3MyAwLjEw
Ny0wLjI4MyAxLjA0LTIuNzggMS4xNC0zLjA2IDAuMTA2LTAuMjkzLTAuMDgtMC41MTQtMC4yNzEtMC42MjgtMi4xLTEuMjgtNS0yLjE1LTgtMi4xNWwtMC41
NTcgMmUtM2MtNS4xMSAwLTguNjggMy4wOS04LjY4IDcuNTF2MC4wOTVjMCA0LjY2IDMuOTQgNi4xOCA3LjYyIDcuMjNsMC41OTIgMC4xODRjMi42OCAwLjgy
NCA1IDEuNTQgNSAzLjQydjAuMDk0YzAgMS43My0xLjUxIDMuMDItMy45MyAzLjAyLTAuOTQxIDAtMy45NC0wLjAxNi03LjE5LTIuMDctMC4zOTMtMC4yMjkt
MC42MTctMC4zOTQtMC45Mi0wLjU3OS0wLjE2LTAuMDk3LTAuNTYtMC4yNzItMC43MzQgMC4yNTJsLTEuMSAzLjA2bTgxLjcgMGMtMC4xNzEgMC40NDYgMC4w
NjEgMC41MzkgMC4xMTggMC42MTggMC41MDkgMC4zNyAxLjAzIDAuNjM4IDEuNTUgMC45MzkgMi43OCAxLjQ3IDUuNCAxLjkgOC4xNCAxLjkgNS41OCAwIDku
MDUtMi45NyA5LjA1LTcuNzV2LTAuMDk0YzAtNC40Mi0zLjkxLTYuMDMtNy41OC03LjE4bC0wLjQ3OS0wLjE1NWMtMi43Ny0wLjg5OC01LjE2LTEuNjgtNS4x
Ni0zLjV2LTAuMDkzYzAtMS41NiAxLjQtMi43MSAzLjU2LTIuNzEgMi40IDAgNS4yNSAwLjc5OSA3LjA5IDEuODEgMCAwIDAuNTQyIDAuMzUgMC43NC0wLjE3
MyAwLjEwNi0wLjI4MyAxLjA0LTIuNzggMS4xMy0zLjA2IDAuMTA3LTAuMjkzLTAuMDgtMC41MTQtMC4yNy0wLjYyOC0yLjEtMS4yOC01LTIuMTUtOC0yLjE1
bC0wLjU1OCAyZS0zYy01LjExIDAtOC42OCAzLjA5LTguNjggNy41MXYwLjA5NWMwIDQuNjYgMy45NCA2LjE4IDcuNjIgNy4yM2wwLjU5MSAwLjE4NGMyLjY5
IDAuODI0IDUgMS41NCA1IDMuNDJ2MC4wOTRjMCAxLjczLTEuNTEgMy4wMi0zLjkzIDMuMDItMC45NDMgMC0zLjk1LTAuMDE2LTcuMTktMi4wNy0wLjM5My0w
LjIyOS0wLjYyMy0wLjM4Ny0wLjkyMS0wLjU3OS0wLjEwMS0wLjA2NC0wLjU3Mi0wLjI0OC0wLjczMyAwLjI1MmwtMS4xIDMuMDZtNTUuOC05LjM2YzAgMi43
LTAuNTA0IDQuODMtMS40OSA2LjM0LTAuOTg0IDEuNDktMi40NyAyLjIyLTQuNTQgMi4yMnMtMy41NS0wLjcyNC00LjUyLTIuMjFjLTAuOTc3LTEuNS0xLjQ3
LTMuNjQtMS40Ny02LjM0IDAtMi43IDAuNDk2LTQuODIgMS40Ny02LjMxIDAuOTY4LTEuNDggMi40NC0yLjE5IDQuNTItMi4xOXMzLjU2IDAuNzE3IDQuNTQg
Mi4xOWMwLjk5MiAxLjQ5IDEuNDkgMy42MSAxLjQ5IDYuMzFtNC42Ni01LjAxYy0wLjQ1OS0xLjU1LTEuMTctMi45MS0yLjEyLTQuMDUtMC45NTEtMS4xNC0y
LjE1LTIuMDYtMy41OC0yLjcyLTEuNDItMC42NjUtMy4xLTEtNS0xcy0zLjU3IDAuMzM3LTUgMWMtMS40MiAwLjY2NC0yLjYzIDEuNTgtMy41OCAyLjcyLTAu
OTQ4IDEuMTQtMS42NiAyLjUtMi4xMiA0LjA1LTAuNDU1IDEuNTQtMC42ODYgMy4yMi0wLjY4NiA1LjAxIDAgMS43OSAwLjIzMSAzLjQ3IDAuNjg2IDUuMDEg
MC40NTcgMS41NSAxLjE3IDIuOTEgMi4xMiA0LjA1IDAuOTUxIDEuMTQgMi4xNiAyLjA1IDMuNTggMi43IDEuNDMgMC42NDggMy4xMSAwLjk3OCA1IDAuOTc4
IDEuODkgMCAzLjU3LTAuMzMgNC45OS0wLjk3OCAxLjQyLTAuNjQ4IDIuNjMtMS41NiAzLjU4LTIuNyAwLjk0OS0xLjE0IDEuNjYtMi41IDIuMTItNC4wNSAw
LjQ1NC0xLjU0IDAuNjg1LTMuMjIgMC42ODUtNS4wMSAwLTEuNzgtMC4yMzEtMy40Ny0wLjY4NS01LjAxbTM4LjMgMTIuOGMtMC4xNTMtMC40NTMtMC41OTUt
MC4yODItMC41OTUtMC4yODItMC42NzcgMC4yNTktMS40IDAuNDk5LTIuMTcgMC42MTktMC43NzYgMC4xMjItMS42NCAwLjE4My0yLjU1IDAuMTgzLTIuMjUg
MC00LjA1LTAuNjcxLTUuMzMtMi0xLjI5LTEuMzMtMi4wMS0zLjQ3LTItNi4zNyA3ZS0zIC0yLjY0IDAuNjQ1LTQuNjIgMS43OS02LjE0IDEuMTMtMS41IDIu
ODctMi4yOCA1LjE3LTIuMjggMS45MiAwIDMuMzkgMC4yMjMgNC45MyAwLjcwNSAwIDAgMC4zNjUgMC4xNTkgMC41NC0wLjMyMiAwLjQwOS0xLjEzIDAuNzEx
LTEuOTQgMS4xNS0zLjE4IDAuMTI0LTAuMzU1LTAuMTgtMC41MDUtMC4yOTEtMC41NDgtMC42MDQtMC4yMzYtMi4wMy0wLjYyMy0zLjExLTAuNzg2LTEuMDEt
MC4xNTQtMi4xOC0wLjIzNC0zLjUtMC4yMzQtMS45NiAwLTMuNyAwLjMzNS01LjE5IDAuOTk5LTEuNDkgMC42NjMtMi43NSAxLjU4LTMuNzUgMi43Mi0xIDEu
MTQtMS43NiAyLjUtMi4yNyA0LjA1LTAuNTA1IDEuNTQtMC43NiAzLjIzLTAuNzYgNS4wMiAwIDMuODYgMS4wNCA2Ljk5IDMuMSA5LjI4IDIuMDYgMi4zIDUu
MTYgMy40NiA5LjIgMy40NiAyLjM5IDAgNC44NC0wLjQ4MyA2LjYtMS4xOCAwIDAgMC4zMzYtMC4xNjIgMC4xOS0wLjU1NGwtMS4xNS0zLjE2bTguMTUtMTAu
NGMwLjIyMy0xLjUgMC42MzQtMi43NSAxLjI4LTMuNzIgMC45NjctMS40OCAyLjQ0LTIuMjkgNC41MS0yLjI5IDIuMDcgMCAzLjQ0IDAuODE0IDQuNDIgMi4y
OSAwLjY1IDAuOTc1IDAuOTM0IDIuMjcgMS4wNCAzLjcybC0xMS4zLTJlLTN6bTE1LjctMy4zYy0wLjM5Ny0xLjQ5LTEuMzgtMy0yLjAyLTMuNjktMS4wMi0x
LjA5LTIuMDEtMS44Ni0zLTIuMjhhMTEuNSAxMS41IDAgMCAwLTQuNTItMC45MTdjLTEuOTcgMC0zLjc2IDAuMzMzLTUuMjEgMS4wMS0xLjQ1IDAuNjgyLTIu
NjcgMS42MS0zLjYzIDIuNzctMC45NTkgMS4xNi0xLjY4IDIuNTMtMi4xNCA0LjEtMC40NiAxLjU1LTAuNjkyIDMuMjUtMC42OTIgNS4wMyAwIDEuODIgMC4y
NDEgMy41MSAwLjcxNSA1LjA0IDAuNDc5IDEuNTQgMS4yNSAyLjg5IDIuMjkgNC4wMSAxLjA0IDEuMTMgMi4zNyAyLjAxIDMuOTcgMi42MyAxLjU5IDAuNjE1
IDMuNTIgMC45MzQgNS43MyAwLjkyNyA0LjU2LTAuMDE1IDYuOTYtMS4wMyA3Ljk0LTEuNTggMC4xNzUtMC4wOTggMC4zNC0wLjI2NyAwLjEzNC0wLjc1NGwt
MS4wMy0yLjg5Yy0wLjE1OC0wLjQzMS0wLjU5NC0wLjI3NS0wLjU5NC0wLjI3NS0xLjEzIDAuNDIyLTIuNzMgMS4xOC02LjQ4IDEuMTctMi40NS00ZS0zIC00
LjI2LTAuNzI3LTUuNC0xLjg2LTEuMTYtMS4xNi0xLjc0LTIuODUtMS44My01LjI1bDE1LjggMC4wMTJzMC40MTYtNGUtMyAwLjQ1OS0wLjQxYzAuMDE3LTAu
MTY4IDAuNTQxLTMuMjQtMC40NzEtNi43OXptLTE0MiAzLjNjMC4yMjMtMS41IDAuNjM1LTIuNzUgMS4yOC0zLjcyIDAuOTY4LTEuNDggMi40NC0yLjI5IDQu
NTEtMi4yOSAyLjA3IDAgMy40NCAwLjgxNCA0LjQyIDIuMjkgMC42NDkgMC45NzUgMC45MzMgMi4yNyAxLjA0IDMuNzJsLTExLjMtMmUtM3ptMTUuNy0zLjNj
LTAuMzk2LTEuNDktMS4zOC0zLTIuMDItMy42OS0xLjAyLTEuMDktMi4wMS0xLjg2LTMtMi4yOGExMS41IDExLjUgMCAwIDAtNC41Mi0wLjkxN2MtMS45NyAw
LTMuNzYgMC4zMzMtNS4yMSAxLjAxLTEuNDUgMC42ODItMi42NyAxLjYxLTMuNjMgMi43Ny0wLjk1NyAxLjE2LTEuNjggMi41My0yLjE0IDQuMS0wLjQ1OSAx
LjU1LTAuNjkgMy4yNS0wLjY5IDUuMDMgMCAxLjgyIDAuMjM5IDMuNTEgMC43MTYgNS4wNCAwLjQ3OCAxLjU0IDEuMjUgMi44OSAyLjI4IDQuMDEgMS4wNCAx
LjEzIDIuMzcgMi4wMSAzLjk3IDIuNjMgMS41OSAwLjYxNSAzLjUxIDAuOTM0IDUuNzMgMC45MjcgNC41Ni0wLjAxNSA2Ljk2LTEuMDMgNy45NC0xLjU4IDAu
MTc0LTAuMDk4IDAuMzQtMC4yNjcgMC4xMzMtMC43NTRsLTEuMDMtMi44OWMtMC4xNTktMC40MzEtMC41OTUtMC4yNzUtMC41OTUtMC4yNzUtMS4xMyAwLjQy
Mi0yLjczIDEuMTgtNi40OCAxLjE3LTIuNDQtNGUtMyAtNC4yNi0wLjcyNy01LjQtMS44Ni0xLjE2LTEuMTYtMS43NC0yLjg1LTEuODMtNS4yNWwxNS44IDAu
MDEyczAuNDE2LTRlLTMgMC40NTktMC40MWMwLjAxNy0wLjE2OCAwLjU0MS0zLjI0LTAuNDcyLTYuNzl6bS00OS44IDEzLjZjLTAuNjE5LTAuNDk0LTAuNzA1
LTAuNjE1LTAuOTEtMC45MzYtMC4zMTMtMC40ODMtMC40NzMtMS4xNy0wLjQ3My0yLjA1IDAtMS4zOCAwLjQ2LTIuMzggMS40MS0zLjA1LTAuMDEgMmUtMyAx
LjM2LTEuMTggNC41OC0xLjE0YTMyIDMyIDAgMCAxIDQuMjggMC4zNjV2Ny4xN2gyZS0zcy0yIDAuNDMxLTQuMjYgMC41NjdjLTMuMjEgMC4xOTMtNC42My0w
LjkyNC00LjYyLTAuOTIxem02LjI4LTExLjFjLTAuNjQtMC4wNDctMS40Ny0wLjA3LTIuNDYtMC4wNy0xLjM1IDAtMi42NiAwLjE2OC0zLjg4IDAuNDk4LTEu
MjMgMC4zMzItMi4zNCAwLjg0Ni0zLjI5IDEuNTNhNy42MyA3LjYzIDAgMCAwLTIuMjkgMi42Yy0wLjU1OSAxLjA0LTAuODQ0IDIuMjYtMC44NDQgMy42NCAw
IDEuNCAwLjI0MyAyLjYxIDAuNzIzIDMuNmE2LjU0IDYuNTQgMCAwIDAgMi4wNiAyLjQ3YzAuODc3IDAuNjM4IDEuOTYgMS4xMSAzLjIxIDEuMzkgMS4yNCAw
LjI4MyAyLjY0IDAuNDI2IDQuMTggMC40MjYgMS42MiAwIDMuMjMtMC4xMzYgNC43OS0wLjM5OWE5NS4xIDk1LjEgMCAwIDAgMy45Ny0wLjc3MmMwLjUyNi0w
LjEyMSAxLjExLTAuMjggMS4xMS0wLjI4IDAuMzktMC4wOTkgMC4zNi0wLjUxNiAwLjM2LTAuNTE2bC05ZS0zIC0xNC40YzAtMy4xNi0wLjg0NC01LjUxLTIu
NTEtNi45Ni0xLjY2LTEuNDUtNC4wOS0yLjE4LTcuMjQtMi4xOC0xLjE4IDAtMy4wOSAwLjE2LTQuMjMgMC4zODkgMCAwLTMuNDQgMC42NjgtNC44NiAxLjc4
IDAgMC0wLjMxMiAwLjE5Mi0wLjE0MiAwLjYyN2wxLjEyIDNjMC4xMzkgMC4zODkgMC41MTggMC4yNTYgMC41MTggMC4yNTZzMC4xMTktMC4wNDcgMC4yNTkt
MC4xM2MzLjAzLTEuNjUgNi44Ny0xLjYgNi44Ny0xLjYgMS43IDAgMy4wMiAwLjM0NSAzLjkgMS4wMiAwLjg2MSAwLjY2MSAxLjMgMS42NiAxLjMgMy43NnYw
LjY2N2MtMS4zNS0wLjE5Ni0yLjYtMC4zMDktMi42LTAuMzA5em0xMjctOC4xM2EwLjQyOCAwLjQyOCAwIDAgMC0wLjIzNy0wLjU2OGMtMC4yNjktMC4xMDIt
MS42MS0wLjM4NS0yLjY0LTAuNDQ5LTEuOTgtMC4xMjQtMy4wOCAwLjIxLTQuMDcgMC42NTQtMC45NzggMC40NDEtMi4wNiAxLjE1LTIuNjYgMS45N2wtMmUt
MyAtMS45MmMwLTAuMjY0LTAuMTg3LTAuNDc3LTAuNDUzLTAuNDc3aC00LjA0Yy0wLjI2MiAwLTAuNDUyIDAuMjEzLTAuNDUyIDAuNDc3djIzLjVhMC40OCAw
LjQ4IDAgMCAwIDAuNDc5IDAuNDc5aDQuMTRhMC40NzkgMC40NzkgMCAwIDAgMC40NzgtMC40Nzl2LTExLjhjMC0xLjU4IDAuMTc0LTMuMTUgMC41MjEtNC4x
NCAwLjM0Mi0wLjk3OSAwLjgwNy0xLjc2IDEuMzgtMi4zMmE0Ljc5IDQuNzkgMCAwIDEgMS45NS0xLjE3IDcuNjggNy42OCAwIDAgMSAyLjEyLTAuMjk4YzAu
ODI1IDAgMS43MyAwLjIxMiAxLjczIDAuMjEyIDAuMzA0IDAuMDM0IDAuNDczLTAuMTUyIDAuNTc2LTAuNDI2IDAuMjcxLTAuNzIxIDEuMDQtMi44OCAxLjE5
LTMuMzEiIGZpbGw9IiNGRkZGRkUiLz4KICA8cGF0aCBkPSJNMTYyLjIwMSA2Ny41NDhhMTMuMjU4IDEzLjI1OCAwIDAgMC0xLjU1OS0uMzcgMTIuMjE3IDEy
LjIxNyAwIDAgMC0yLjE0NC0uMTY2Yy0yLjg1MyAwLTUuMTAyLjgwNi02LjY4MSAyLjM5OC0xLjU2OCAxLjU4LTIuNjM1IDMuOTg3LTMuMTcgNy4xNTRsLS4x
OTMgMS4wNjloLTMuNTgxcy0uNDM3LS4wMTgtLjUyOS40NTlsLS41ODggMy4yOGMtLjA0MS4zMTQuMDk0LjUxLjUxNC41MDhoMy40ODZsLTMuNTM3IDE5Ljc0
M2MtLjI3NyAxLjU5LS41OTQgMi44OTgtLjk0NSAzLjg4OS0uMzQ2Ljk3OC0uNjg0IDEuNzExLTEuMSAyLjI0My0uNDAzLjUxNS0uNzg1Ljg5NC0xLjQ0NCAx
LjExNS0uNTQ0LjE4My0xLjE3LjI2Ny0xLjg1Ni4yNjctLjM4MiAwLS44OS0uMDY0LTEuMjY1LS4xMzktLjM3NS0uMDc0LS41Ny0uMTU4LS44NTEtLjI3NiAw
IDAtLjQwOS0uMTU2LS41Ny4yNTQtLjEzMS4zMzUtMS4wNiAyLjg5LTEuMTcgMy4yMDYtLjExMi4zMTIuMDQ1LjU1OC4yNDMuNjI5LjQ2NC4xNjYuODA5LjI3
MiAxLjQ0MS40MjEuODc4LjIwNyAxLjYxOC4yMiAyLjMxMS4yMiAxLjQ1MiAwIDIuNzc1LS4yMDQgMy44NzItLjYgMS4xMDQtLjM5OSAyLjA2NS0xLjA5NCAy
LjkxNS0yLjAzNS45MTktMS4wMTUgMS40OTctMi4wNzggMi4wNS0zLjUyOC41NDctMS40MzcgMS4wMTMtMy4yMjEgMS4zODYtNS4zbDMuNTU0LTIwLjEwOWg1
LjE5NnMuNDM4LjAxNi41MjktLjQ1OWwuNTg4LTMuMjhjLjA0MS0uMzE0LS4wOTMtLjUxLS41MTUtLjUwOGgtNS4wNDNjLjAyNS0uMTE0LjI1NC0xLjg4OC44
MzMtMy41NTguMjQ3LS43MTMuNzEyLTEuMjg4IDEuMTA2LTEuNjgzYTMuMjczIDMuMjczIDAgMCAxIDEuMzIxLS44MjIgNS40OCA1LjQ4IDAgMCAxIDEuNjkz
LS4yNDRjLjQ3NSAwIC45NDEuMDU3IDEuMjk2LjEzMS40ODkuMTA0LjY3OS4xNTkuODA3LjE5Ny41MTQuMTU3LjU4My4wMDUuNjg0LS4yNDRsMS4yMDYtMy4z
MTJjLjEyNC0uMzU2LS4xNzgtLjUwNi0uMjktLjU1bS03MC40NzQgMzQuMTE3YzAgLjI2NC0uMTg4LjQ3OS0uNDUyLjQ3OWgtNC4xODNjLS4yNjUgMC0uNDUz
LS4yMTUtLjQ1My0uNDc5VjY3Ljk5N2MwLS4yNjMuMTg4LS40NzYuNDUzLS40NzZoNC4xODNjLjI2NCAwIC40NTIuMjEzLjQ1Mi40NzZ2MzMuNjY4IiBmaWxs
PSIjRkZGRkZFIi8+CiA8L2c+Cjwvc3ZnPgo=
"""

if __name__ == "__main__":
    # replace the log with the root logger if running as main
    log = logging.getLogger()
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)

    main()
