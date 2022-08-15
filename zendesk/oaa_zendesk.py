#!env python3
"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, OAAPermission, OAAPropertyType
from oaaclient.utils import log_arg_error
from requests import HTTPError
import argparse
import logging
import os
import re
import requests
import sys
import base64


logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)


class OAAZendesk():

    def __init__(self, zendesk_url: str, zendesk_user: str, api_key: str) -> None:
        zendesk_url = zendesk_url.rstrip("/")
        if re.match(r"^https:\/\/", zendesk_url):
            self.zendesk_url = zendesk_url
        else:
            self.zendesk_url = f"https://{zendesk_url}"

        self.zendesk_user = zendesk_user.strip()
        self.api_key = api_key.strip()

        self.app = CustomApplication("Zendesk", "zendesk")

        # store role ID to name map
        self.__role_ids = {}
        # store group IDs to name map
        self.__group_ids = {}
        self.__group_memberships = {}

        # load known Zendesk permissions into the OAA app
        self.__load_permissions()

    def discover(self) -> None:
        """ perform Zendesk discovery """
        self.discover_roles()
        self.discover_groups()
        self.discover_users()
        return

    def discover_roles(self) -> None:
        """ configures Zendesk roles combining built in roles that are locally defined in this code with custom roles pulled from API """

        # first populate the built-in roles that are not available via an API
        agent_role = self.app.add_local_role("agent")
        agent_role.add_permissions(["end_user_profile_access-edit",
                                    "ticket_comment_access-public",
                                    "macro_access-manage-personal",
                                    "view_access-manage-personal",
                                    ])

        # the built in agent role defaults to ticket visibility enabled, add ticket access and report access
        agent_role.add_permissions(["ticket_access-all", "report_access-readonly"])

        # Load custom roles from API
        response = self.__zapi_get("/api/v2/custom_roles.json")
        if response['next_page']:
            log.error(f"Roles response truncated, count: {response['count']}, next_page: {response['next_page']}, ")
        for r in response['custom_roles']:
            # not entirely clear if role names are unique, so if we see the same name twice
            # combine with role ID
            if r['name'] not in self.app.local_roles:
                role_name = r['name']
            else:
                role_name = f"{r['name']} - {r['id']}"
            role_id = r['id']
            # description = r['description']
            log.debug(f"Creating role {role_name} ({role_id})")
            role = self.app.add_local_role(role_name)

            # process the role permissions, zendesk role configuration is a mix of boolean permissions and strings
            self.__role_ids[role_id] = role_name
            for p in r['configuration']:
                if not r['configuration'][p]:
                    # is false or empty, move on
                    continue
                elif isinstance(r['configuration'][p], bool):
                    # is boolean true, assign the permission as is
                    permission_name = p
                elif isinstance(r['configuration'][p], str):
                    # permission has string value like "full" or "readonly" or "none" (as a string)
                    if r['configuration'][p].lower() == "none":
                        continue
                    else:
                        permission_name = f"{p}-{r['configuration'][p]}"
                else:
                    log.error(f"Permission {p} is not boolean or string, cannot process {type(p)}")
                    continue

                if permission_name not in self.app.custom_permissions:
                    log.info(f"Unknown permission {permission_name}, creating NonData permission")
                    self.app.add_custom_permission(permission_name, [OAAPermission.NonData])
                role.add_permissions([permission_name])

        return

    def discover_groups(self) -> None:
        """ discover groups, save ID -> name for later use """
        log.debug("Discovering groups")

        # define OAA custom properties for groups
        self.app.property_definitions.define_local_group_property("id", OAAPropertyType.STRING)
        self.app.property_definitions.define_local_group_property("description", OAAPropertyType.STRING)

        response = self.__zapi_get("/api/v2/groups.json")

        for g in response["groups"]:
            if g['deleted']:
                log.debug(f"Skipping deleted group {g['name']}")
            group = self.app.add_local_group(g['name'])
            group.created_at = g['created_at']
            group.set_property("id", g['id'])
            if g['description']:
                group.set_property("description", g['description'])
            self.__group_ids[g['id']] = g['name']

            membership_api_call = f"/api/v2/groups/{g['id']}/memberships.json?page[size]=100"
            while True:
                membership_response = self.__zapi_get(membership_api_call)
                for e in membership_response["group_memberships"]:
                    if e['user_id'] in self.__group_memberships:
                        self.__group_memberships[e['user_id']].append(g['id'])
                    else:
                        self.__group_memberships[e['user_id']] = [g['id']]
                if membership_response['meta']['has_more']:
                    membership_api_call = membership_response['links']['next']
                else:
                    # no more users
                    break
        return

    def discover_users(self) -> None:
        """ discover all the agent and admin users, currently does not collect end-users """
        log.debug("Discovering users")

        # define OAA custom properties for users
        self.app.property_definitions.define_local_user_property("id", OAAPropertyType.STRING)
        self.app.property_definitions.define_local_user_property("display_name", OAAPropertyType.STRING)
        self.app.property_definitions.define_local_user_property("role", OAAPropertyType.STRING)


        # get only admin and agents, skip over end-users
        # Zendesk API has odd pagination behavior, the response is different depending on if you passed page size or not
        # for consistency just always pass page size, max=100
        users_api_call = "/api/v2/users.json?role[]=admin&role[]=agent&page[size]=100"
        while True:
            response = self.__zapi_get(users_api_call)
            for u in response["users"]:
                user = self.app.add_local_user(u['email'], identities=[u['email']])
                user.is_active = not u['suspended']
                user.created_at = u['created_at']
                user.last_login_at = u['last_login_at']
                user.set_property("id", u['id'])
                user.set_property("display_name", u['name'])

                if u['default_group_id'] in self.__group_ids:
                    user.add_group(self.__group_ids[u['default_group_id']])

                for group_id in self.__group_memberships[u['id']]:
                    user.add_group(self.__group_ids[group_id])

                # zendesk users have a role type of admin, agent or end-user, save this as a proprety of the user
                user.set_property("role", u['role'])
                # log.debug(f"{u['email']=}:{u['role']=}, {u['role_type']=},  {u['custom_role_id']=}")

                # Zendesk has a mix of built in roles and custom roles, if the user has a custom role it is referenced by `custom_role_id`
                # custom roles are discovered by the discover_roles() function, built in roles are not returned by the API and have to be
                # defined as part of the OAA code
                if u['custom_role_id'] and u['custom_role_id'] in self.__role_ids:
                    # get the role name from the map
                    role_name = self.__role_ids[u['custom_role_id']]
                    user.add_role(role_name, apply_to_application=True)
                elif u['custom_role_id']:
                    log.error(f"Unknown role_id {u['custom_role_id']} for user {u['name']} ({u['id']})")
                else:
                    # user appears to be using built in role, use the `role` field to map to defined roles, error if not defined
                    if u['role'] not in self.app.local_roles:
                        log.error(f"User {u['name']} ({u['id']}) has undefined role '{u['role']}'")
                    user.add_role(u['role'], apply_to_application=True)
                    pass

            if response['meta']['has_more']:
                users_api_call = response['links']['next']
            else:
                # no more users
                break

        return

    def __load_permissions(self) -> None:
        """
        load all the known Zendesk permissions into the OAA app, any permissions returned as part of role discovery that are
        not part of this map will be dynamically created and assign `OAAPermission.NonData`, to add a permission add the entry
        by name and the list of Veza canonical permissions.
        """

        zendesk_permissions = {
            "assign_tickets_to_any_group": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "chat_access": [OAAPermission.DataRead, OAAPermission.DataWrite],
            "end_user_list_access-full": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "end_user_profile_access-edit": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "end_user_profile_access-edit-within-org": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "end_user_profile_access-full": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "end_user_profile_access-readonly": [OAAPermission.MetadataRead],
            "explore_access-edit": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "explore_access-full": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "explore_access-readonly": [OAAPermission.MetadataRead],
            "forum_access_restricted_content": [OAAPermission.NonData],
            "forum_access-edit-tops": [OAAPermission.MetadataWrite],
            "forum_access-full": [OAAPermission.DataRead, OAAPermission.DataWrite],
            "forum_access-readonly": [OAAPermission.DataRead],
            "group_access": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "light_agent": [OAAPermission.NonData],
            "macro_access-full": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "macro_access-manage-group": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "macro_access-manage-personal": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "macro_access-readonly": [OAAPermission.MetadataRead],
            "manage_business_rules": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "manage_contextual_workspaces": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "manage_dynamic_content": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "manage_extensions_and_channels": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "manage_facebook": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "manage_organization_fields": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "manage_ticket_fields": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "manage_ticket_forms": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "manage_user_fields": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "moderate_forums": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "organization_editing": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "organization_notes_editing": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "report_access-full": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "report_access-readonly": [OAAPermission.DataRead],
            "side_conversation_create": [OAAPermission.NonData],
            "ticket_access-all": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "ticket_access-asssigned-only": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "ticket_access-within-groups": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "ticket_access-within-organization": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "ticket_comment_access-public": [OAAPermission.DataWrite],
            "ticket_deletion": [OAAPermission.DataDelete],
            "ticket_editing": [OAAPermission.DataWrite],
            "ticket_merge": [OAAPermission.MetadataWrite],
            "ticket_tag_editing": [OAAPermission.MetadataWrite],
            "user_view_access-full": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "user_view_access-manage-group": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "user_view_access-manage-personsal": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "user_view_access-playonly": [OAAPermission.MetadataRead],
            "user_view_access-readyonly": [OAAPermission.MetadataRead],
            "view_access-full": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "view_access-manage-group": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "view_access-manage-personal": [OAAPermission.MetadataRead, OAAPermission.MetadataWrite],
            "view_access-playonly": [OAAPermission.MetadataRead],
            "view_access-readonly": [OAAPermission.MetadataRead],
            "view_deleted_tickets": [OAAPermission.DataRead],
            "voice_access": [OAAPermission.NonData],
            "voice_dashboard_access": [OAAPermission.MetadataRead]
        }

        for p in zendesk_permissions:
            self.app.add_custom_permission(p, zendesk_permissions[p])

        return

    def __zapi_get(self, path: str, params: dict = {}) -> dict:
        """ Zendesk API GET
        Parameters:
        path (string): API path relative to zendesk_url
        params (dictionary): Optional HTTP parameters to include

        Returns:
        dictionary: API Response

        Raises:
        HTTPError
        """

        headers = {}
        b64_auth = base64.b64encode(f"{self.zendesk_user}/token:{self.api_key}".encode()).decode()
        headers['authorization'] = f"Basic {b64_auth}"
        path = path.lstrip("/")
        if re.match(r"^https:\/\/", path):
            api_path = path
        else:
            api_path = f"{self.zendesk_url}/{path}"

        log.debug(f"Zendesk API GET {api_path}")
        response = requests.get(api_path, headers=headers, params=params, timeout=10)
        if response.ok:
            return response.json()
        else:
            raise HTTPError(response.text, response=response)


def run(zendesk_url: str, zendesk_user: str, zendesk_api_key: str, veza_url: str, veza_api_key: str, save_json: bool = False, verbose: bool = False) -> None:
    if verbose:
        log.setLevel(logging.DEBUG)
        log.debug("Enabling verbose logging")

    try:
        veza_con = OAAClient(url=veza_url, api_key=veza_api_key)
    except OAAClientError as e:
        log.error(f"Unable to connect to Veza ({veza_url})")
        log.error(e.message)
        sys.exit(1)

    zendesk = OAAZendesk(zendesk_url, zendesk_user, zendesk_api_key)

    try:
        zendesk.discover()
    except HTTPError as e:
        log.error(f"Error during discovery: Zendesk API returned error: {e.response.status_code} for {e.request.url}")
        log.error(e)
        sys.exit(2)

    provider_name = "Zendesk"
    provider = veza_con.get_provider(provider_name)
    if provider:
        log.info("Found existing provider")
    else:
        log.info(f"Creating Provider {provider_name}")
        provider = veza_con.create_provider(provider_name, "application")
    log.info(f"Provider: {provider['name']} ({provider['id']})")

    # push data
    try:
        data_source_name = zendesk.zendesk_url.split("://")[1]
        log.info(f"Pushing app, datasource name: {data_source_name}")
        veza_con.push_application(provider_name, data_source_name=data_source_name, application_object=zendesk.app, save_json=save_json)
        log.info("Success")
    except OAAClientError as e:
        log.error(f"{e.error}: {e.message} ({e.status_code})")
        if hasattr(e, "details"):
            for d in e.details:
                log.error(d)

    return


def main() -> None:
    """ process command line and OS environment variables to ensure everything is set, call `run` function """

    parser = argparse.ArgumentParser()
    parser.add_argument("--zendesk-url", default=os.getenv("ZENDESK_URL"), help="Zendesk URL to discover")
    parser.add_argument("--zendesk-user", default=os.getenv("ZENDESK_USER"), help="Zendesk user for authentication")
    parser.add_argument("--veza-url", default=os.getenv("VEZA_URL"), help="Veza URL for OAA connection")
    parser.add_argument("--save-json", action="store_true", help="Save OAA JSON payload to file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    zendesk_url = args.zendesk_url
    zendesk_user = args.zendesk_user
    veza_url = args.veza_url
    # ensure all require command line args are present or discovered from OS environment
    if not zendesk_url:
        log_arg_error(log, "--zendesk-url", "ZENDESK_URL")
    if not zendesk_user:
        log_arg_error(log, "--zendesk-user", "ZENDESK_USER")
    if not veza_url:
        log_arg_error(log, "--veza-url", "VEZA_URL")

    # security values can only be loaded through OS environment
    zendesk_api_key = os.getenv("ZENDESK_API_KEY")
    if not zendesk_api_key:
        log_arg_error(log, env="ZENDESK_API_KEY")

    veza_api_key = os.getenv("VEZA_API_KEY")
    if not veza_api_key:
        log_arg_error(log, env="VEZA_API_KEY")

    if None in [zendesk_url, zendesk_user, zendesk_api_key, veza_url, veza_api_key]:
        log.error("Missing one or more required parameters")
        sys.exit(1)

    run(zendesk_url, zendesk_user, zendesk_api_key, veza_url, veza_api_key, save_json=args.save_json, verbose=args.verbose)


if __name__ == '__main__':
    main()
