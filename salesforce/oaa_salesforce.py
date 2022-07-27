#!env python3
"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by a the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, OAAPermission
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
log = logging.getLogger()
handler = logging.StreamHandler()
formatter = logging.Formatter('%(levelname)s: %(message)s')
handler.setFormatter(formatter)

# set a validated minimum supported salesforce version
MINIMUM_SFDC_VERSION = 29.0

class OAA_SFDC_LightningAPI():
    def __init__(self, client_id, client_secret, password, username):
        """
        configure the Lightning API client for data requests
        """
        base_url, oauth_token = self.authenticate(client_id, client_secret, password, username)

        self.app = CustomApplication(f"Salesforce.com", "Salesforce")
        self.base_url = f"{base_url}/services/data"
        self.oauth_token = oauth_token
        self.request_headers = self.set_oauth_headers()
        self.sfdc_version = self.set_api_version()
        self.base_url = f"{self.base_url}/v{self.sfdc_version}"

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
            self.app.add_resource(object_name, "object_type")

            # iterate object_type permissions and translate them to displayed permissions
            for permissions_set_id in object_type.get("permissions"):
                translated_permissions = self.__translate_permissions(object_type.get("permissions").get(permissions_set_id))
                permissions_set_name = self.permissions_sets[permissions_set_id].get("name")

                if re.match(r"^\w00", permissions_set_name):
                    # profile-based (X00...) permissions set; apply permissions to OAA users
                    assignees = self.permissions_sets.get(permissions_set_id).get("users")

                    # iterate translated permissions and apply them
                    for permission in translated_permissions:
                        for assignee_id in assignees:
                            username = self.users.get(assignee_id).get("username")
                            self.app.local_users[username].add_permission(permission, resources = [self.app.resources.get(object_name)], apply_to_application = False)
                else:
                    # non-profile-based permissions set; apply permissions to OAA group
                    for permission in translated_permissions:
                        self.app.local_groups[permissions_set_name].add_permission(permission, resources = [self.app.resources.get(object_name)], apply_to_application = False)



    def discover_permissions_sets(self):
        """
        discover Salesforce permissions sets and create OAA groups from them
        """
        log.info("discovering salesforce.com permissions sets")
        self.permissions_sets = self.list_permissions_sets_with_assignments()
        for permissions_set_id in self.permissions_sets:
            permissions_set = self.permissions_sets.get(permissions_set_id)
            # don't create OAA groups for "X00..." profile-based permissions sets
            if not re.match(r"^\w00", permissions_set.get("name")):
                self.app.add_local_group(permissions_set.get("name"))

                # add assignees to local_group
                for user_id in permissions_set.get("users"):
                    user = self.users.get(user_id)
                    self.app.local_users[user.get("username")].add_group(permissions_set.get("name"))


    def discover_users(self):
        """
        discover Salesforce users
        """
        log.info("discovering salesforce.com users")
        self.users = self.list_users()
        for user_id in self.users:
            user = self.users.get(user_id)
            self.app.add_local_user(user.get("username"), identities = [user.get("username")])


    def list_object_types_and_permissions(self):
        """
        list object types and attached permissions sets
        """
        base_query = "SELECT Id, Parent.Id, SobjectType, PermissionsCreate, PermissionsDelete, PermissionsEdit, PermissionsModifyAllRecords, PermissionsRead, PermissionsViewAllRecords FROM ObjectPermissions ORDER BY SobjectType"
        object_types = {}

        response = self.__query_all(base_query)
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
        base_query = "SELECT name, Id, (SELECT AssigneeId FROM Assignments) FROM PermissionSet"
        permissions_sets = {}

        response = self.__query_all(base_query)
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
        base_query = "SELECT name FROM UserRole ORDER BY name"
        roles = {}

        response = self.__query_all(base_query)
        for role in response:
            roles[role.get("Id")] = {
                "name": role.get("Name")
            }

        return roles


    def list_users(self):
        """
        list salesforce users
        """
        base_query = "SELECT username, Id FROM User ORDER BY username"
        users = {}

        response = self.__query_all(base_query)
        for user in response:
            users[user.get("Id")] = {
                "username": user.get("Username")
            }

        return users


    def __populate_permissions(self):
        """
        map Salesforce permissions to OAA canonical permissions
        """
        permissions = {
            "Create": [OAAPermission.DataWrite, OAAPermission.MetadataWrite],
            "Delete": [OAAPermission.DataWrite, OAAPermission.MetadataWrite],
            "Edit": [OAAPermission.DataWrite, OAAPermission.MetadataWrite],
            "ModifyAllRecords": [OAAPermission.DataWrite, OAAPermission.MetadataWrite],
            "Read": [OAAPermission.DataRead, OAAPermission.MetadataRead],
            "ViewAllRecords": [OAAPermission.DataRead, OAAPermission.MetadataRead]
        }

        for permission in permissions:
            self.app.add_custom_permission(permission, permissions[permission])


    def __query_all(self, query, parameters = {}):
        """
        make an API GET request to the salesforce endpoint
        manually aggregate paginated results
        """
        offset = 0
        result = []

        while True:
            api_path = f"{self.base_url}/queryAll/?q={query} OFFSET {offset}"
            log.debug(f"making GET request to {api_path}")
            response = requests.get(api_path, headers = self.request_headers, params = parameters)

            if not response.ok:
                raise HTTPError(response = response)
            body = response.json()

            if "records" in body:
                result.extend(body.get("records"))
                if body.get("done"):
                    break
                else:
                    offset = offset + body.get("totalSize")
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
            raise HTTPError(response = response)
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


def run(veza_api_key, veza_url, sfdc_client_id, sfdc_client_secret, sfdc_password, sfdc_user, save_json = False):
    """
    run full OAA process; discover Salesforce entities, prepare OAA template, and push metadata to Veza
    """
    try:
        conn = OAAClient(url = veza_url, api_key = veza_api_key)
    except OAAClientError as error:
        log.error(f"Unable to connect to Veza {veza_url}")
        log.error(error.message)
        sys.exit(1)

    salesforce_app = OAA_SFDC_LightningAPI(sfdc_client_id, sfdc_client_secret, sfdc_password, sfdc_user)

    try:
        salesforce_app.discover()
    except HTTPError as error:
        log.error(f"Error during discovery: Salesforce API returned error: {error.response.status_code} for {error.request_url}")
        log.error(error)
        log.error("exiting")
        sys.exit(1)

    # payload = salesforce_app.app.get_payload()
    # print(json.dumps(payload, indent = 2))

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
        log.info("uploading custom application data")
        conn.push_application(
            provider_name,
            data_source_name = data_source_name,
            application_object = salesforce_app.app,
            save_json = save_json
        )
    except OAAClientError as error:
        log.error(f"{error.error}: {error.message} ({error.status_code})")
        if hasattr(error, "details"):
            for detail in error.details:
                log.error(f"  {detail}")

    log.info("success")


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
        handler.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)
        handler.setLevel(logging.INFO)
    log.addHandler(handler)

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

    # ensure required variables are provided
    if None in [veza_api_key, veza_url, sfdc_client_id, sfdc_client_secret, sfdc_password, sfdc_user]:
        log.error(f"missing one or more required parameters")
        sys.exit(1)

    run(veza_api_key, veza_url, sfdc_client_id, sfdc_client_secret, sfdc_password, sfdc_user, save_json)

if __name__ == "__main__":
    main()
