#!/usr/bin/env python3
"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time

import requests
from requests.exceptions import HTTPError, RequestException
from requests import Response
from requests.exceptions import JSONDecodeError as RequestsJSONDecodeError
from datetime import datetime

import oaaclient.utils as oaautils
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, CustomResource, LocalGroup, LocalUser, OAAPermission, OAAPropertyType

# logging handler
logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)



class OAAGitLab():
    """
    OAA Class for discovering GitLab deployment.

    Argument:
        gitlab_url (string): URL for GitLab host with our without protocol, if no protocol assumes https://
        access_token (string): Token used for GitLab API calls
        deployment_name (string): Optional, name for deployment will be used for Application name, if omitted hostname is used

    Attributes:
        app (CustomApplication): CustomApplication object to create OAA template

        member_group_name (string): Name for group that will be created and all users added to, represents logged in users inherit permissions
        member_role_name (string): Name for role that includes permissions all logged in users have
        admin_role_name (name): Name for admin role created
        perm_map (dictionary): Mapping of GitLab numeric access levels to name strings
    """

    MAX_API_RETRIES = 5
    def __init__(self, gitlab_url: str, access_token: str, deployment_name: str = None) -> None:
        self.parent_name = None
        self.member_group_name = "Member"
        self.member_role_name = "Member"
        self.admin_role_name = "Admin"

        if re.match(r"^https:\/\/", gitlab_url):
            self.gitlab_url = gitlab_url
        elif re.match(r"http:\/\/", gitlab_url):
            log.warning(f"Using http insecure URL {self.gitlab_url}")
            self.gitlab_url = gitlab_url
        else:
            self.gitlab_url = f"https://{gitlab_url}"

        self.gitlab_url= self.gitlab_url.strip("/")

        if not deployment_name:
            self.deployment_name = self.gitlab_url.split("://")[1]
        else:
            self.deployment_name = deployment_name


        self.access_token = access_token

        # test token
        try:
            calling_user = self._gl_api_get("/api/v4/user")
        except RequestException as e:
            log.error(f"Error validating API token")
            raise(e)

        self.calling_as_admin = False
        if calling_user.get("is_admin"):
            self.calling_as_admin = True
        log.info(f"Running as GitLab user {calling_user.get('name')} ({calling_user.get('username')}) - is_admin {calling_user.get('is_admin', False)}")

        if self.deployment_name == "gitlab.com":
            self.datasource_name = f"gitlab.com - {calling_user.get('name')} ({calling_user.get('id')})"
        else:
            self.datasource_name = self.deployment_name

        app_name = f"GitLab - {self.deployment_name}"

        self.app = CustomApplication(app_name, "GitLab")
        # define custom properties for the users
        self.app.property_definitions.define_local_user_property("gitlab_id", OAAPropertyType.NUMBER)
        self.app.property_definitions.define_local_user_property("bot", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_local_user_property("is_licensed", OAAPropertyType.STRING)
        self.app.property_definitions.define_local_user_property("state", OAAPropertyType.STRING)
        self.app.property_definitions.define_local_user_property("saml_login", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_local_user_property("email", OAAPropertyType.STRING)

        # define custom properties for group object
        self.app.property_definitions.define_resource_property("group", "gitlab_id", OAAPropertyType.NUMBER)
        self.app.property_definitions.define_resource_property("group", "visibility", OAAPropertyType.STRING)
        self.app.property_definitions.define_resource_property("group", "require_two_factor_authentication", OAAPropertyType.BOOLEAN)

        # define custom properties for project
        self.app.property_definitions.define_resource_property("project", "gitlab_id", OAAPropertyType.NUMBER)
        self.app.property_definitions.define_resource_property("project", "visibility", OAAPropertyType.STRING)

        self._populate_permissions()

        # GitLab returns permissions as integers, secret decoder ring as dictionary
        self.access_levels = {0: "No access",
                              5: "Minimal access",
                              10: "Guest",
                              20: "Reporter",
                              30: "Developer",
                              40: "Maintainer",
                              50: "Owner"
                              }

        #TODO: Might not need anymore
        # in order to avoid calling groups API repeatedly to get user's access levels store the users access levels into dictionary keyed by group id
        self.group_user_access_levels = {}
        # store each groups parent ID to reduce API calls
        self.group_parent_ids = {}

    def _map_access_level(self, access_level: int) -> str:
        """ returns string of role name from GitLab numeric based access levels """

        try:
            access_level = int(access_level)
            access_role = self.access_levels[access_level]
        except ValueError as e:
            log.error(f"access_level must be numeric value, cannot map {access_level}")
            raise e
        except KeyError as e:
            log.error(f"cannot map access_level {access_level}, unknown value")
            raise e

        return access_role

    def _populate_permissions(self) -> None:
        """ Defines permissions and creates base roles/groups """

        # Self-Hosted Admin users
        self.app.add_custom_permission("Admin", [OAAPermission.DataRead, OAAPermission.DataWrite, OAAPermission.MetadataRead, OAAPermission.MetadataWrite, OAAPermission.DataCreate, OAAPermission.DataDelete])

        # GitLab built in permissions
        gitlab_permissions = {
            "View": [OAAPermission.MetadataRead],
            "Manage Access": [OAAPermission.MetadataWrite],
            "Pull": [OAAPermission.DataRead],
            "Branch": [OAAPermission.DataRead],
            "Merge": [OAAPermission.DataWrite],
            "Push": [OAAPermission.DataWrite],
            "Maintain": [OAAPermission.DataWrite]
        }

        for p in gitlab_permissions:
            self.app.add_custom_permission(p, gitlab_permissions[p], apply_to_sub_resources=True)

        # Minimal access role is not recursive
        self.app.add_custom_permission("Minimal access", [OAAPermission.NonData], apply_to_sub_resources=False)

        # GitLab Roles & groups
        self.app.add_local_role(self.admin_role_name, unique_id=self.admin_role_name, permissions=["Admin"])
        self.app.add_local_role(self.member_role_name, unique_id=self.member_role_name, permissions=["View"])
        self.app.add_local_group(self.member_group_name, unique_id=self.member_group_name)

        # Repo Roles
        self.app.add_local_role("Minimal access", unique_id="Minimal access", permissions=["Minimal access"])
        self.app.add_local_role("Guest", unique_id="Guest", permissions=["View", "Pull"])
        self.app.add_local_role("Reporter", unique_id="Reporter", permissions=["View", "Pull"])
        self.app.add_local_role("Developer", unique_id="Developer", permissions=["View", "Pull", "Branch", "Push", "Merge"])
        self.app.add_local_role("Maintainer", unique_id="Maintainer", permissions=["View", "Pull", "Branch", "Push", "Merge"])
        self.app.add_local_role("Owner", unique_id="Owner", permissions=["View", "Pull", "Branch", "Push", "Merge", "Manage Access"])

    def discover(self) -> None:
        """Run GitLab discovery process """
        log.info("Starting GitLab discovery")

        # discover all the users, if running with group token it will only discover users that are part of the group and subgroups

        # If admin user, then we can use the /users API to get more detail on each user
        if self.calling_as_admin:
            self.discover_all_users()

        # discover all the groups, if running with group token will only discover group from token
        #TODO: validate you do not get public groups with SaaS
        self.discover_all_groups()
        return

    def discover_all_users(self) -> None:
        """Discover all GitLab users """

        log.info("Discovering all GitLab users")
        gitlab_users = self._gl_api_get("/api/v4/users")
        for user in gitlab_users:
            self.add_user(user)

        return

    def add_user(self, user_info: dict) -> LocalUser:
        """Add single user to OAA App

        Adds a single user based on the user_info dictionary, containing user
        details from either the users or members API. If the user already exists the existing user
        object is returned.

        Args:
            user_info (dict): API response containing a single user's information

        Returns:
            LocalUser: OAA local user object for user
        """

        user_name = user_info['username']
        user_id = user_info["id"]
        if user_id not in self.app.local_users:
            local_user = self.app.add_local_user(user_name, unique_id=user_id)

            local_user.created_at = user_info.get("created_at")
            local_user.last_login_at = user_info.get("last_sign_in_at")
            local_user.set_property("gitlab_id", user_info['id'])

            if user_info.get("using_license_seat"):
                local_user.set_property("is_licensed",  user_info['using_license_seat'])

            # GitLab use three states, active, blocked, deactivated
            local_user.set_property("state", user_info['state'])
            if user_info['state'] == "active":
                local_user.is_active = True
            else:
                local_user.is_active = False

            # user email will only be available on self-hosted when run with Admin token
            if user_info.get("email"):
                local_user.add_identities([user_info["email"]])
                local_user.set_property("email", user_info["email"])

            # SAML identity for SSO should be available if configured
            if user_info.get("group_saml_identity"):
                group_saml_identity = user_info["group_saml_identity"]
                external_id = group_saml_identity.get("extern_uid")
                if not external_id:
                    log.warning(f"group_saml_identity does not contain external_id, {group_saml_identity}, user: {user_name} {user_id}")
                else:
                    local_user.add_identity(external_id)
                    # set property for local_user is saml enabled
                    local_user.set_property("saml_login", True)
                    if re.match(r".+@.+\..+", external_id):
                        # external ID looks like an email, set it to the email property, not all external ids are emails
                        local_user.set_property("email", external_id)

            if user_info.get("is_admin"):
                local_user.add_role(self.admin_role_name, apply_to_application=True)

            if user_info.get("bot") is True:
                local_user.set_property("bot", True)

            if user_info.get("access_level", 0) < 10:
                # No access = 0, Minimal Access = 5, these users don't get access to internal repositories automatically
                pass
            else:
                # Add users to the member group to give access to internal repositories
                local_user.add_group(self.member_group_name)

        return self.app.local_users[user_id]

    def discover_all_groups(self) -> None:
        """Discover GitLab groups

        Discovers all top-level groups available to the calling user, and any sub-groups

        """

        log.info("Starting discovery GitLab Groups")
        gitlab_groups = self._gl_api_get("api/v4/groups", params={"top_level_only": True})

        for group in gitlab_groups:
            self.discover_group(group.get("id"))

    def discover_group(self, group_id: int, parent_group_resource: CustomResource = None) -> CustomResource:
        """Discover Single Group and Sub-Groups

        Args:
            group_id (int): Group ID
            parent_group_resource (CustomResource, optional): OAA CustomResource of parent group or None for top level groups. Defaults to None.

        Returns:
            CustomResource: New custom resource representing Group
        """

        group_info = self._gl_api_get(f"api/v4/groups/{group_id}", params={"with_projects": False})
        name = group_info.get("name")
        full_name = group_info.get("full_name")
        log.info(f"Discovering group {full_name}")
        local_group = self.app.add_local_group(name, unique_id=group_id)

        if parent_group_resource:
            # sub group
            group_resource = parent_group_resource.add_sub_resource(full_name, unique_id=group_id, resource_type="group")
        else:
            # top level group
            group_resource = self.app.add_resource(full_name, unique_id=group_id, resource_type="group")

        # set visibility
        group_resource.set_property("gitlab_id", group_id)
        group_resource.set_property("visibility", group_info.get("visibility"))
        group_resource.set_property("require_two_factor_authentication", group_info.get("require_two_factor_authentication", False))

        # set description ensure limit character length
        description = group_info.get("description", "")
        group_resource.description = description[:256]

        # discover groups users
        group_users = self._gl_api_get(f"/api/v4/groups/{group_id}/members")
        for user in group_users:
            local_user = self.add_user(user)
            local_user.add_group(group_id)
            if user.get("access_level", 0) > 0:
                user_role = self._map_access_level(user["access_level"])

                local_user.add_role(user_role, resources=[group_resource])

        # projects
        group_projects = self._gl_api_get(f"/api/v4/groups/{group_id}/projects")
        for project in group_projects:
            self.add_project(project, group_resource)

        # sub groups
        sub_groups = self._gl_api_get(f"/api/v4/groups/{group_id}/subgroups")
        for sub_group in sub_groups:
            sub_group_id = sub_group.get("id")
            self.discover_group(sub_group_id, parent_group_resource=group_resource)

        return group_resource

    def add_project(self, project: dict, group_resource: CustomResource) -> None:
        """Add a project to the OAA Custom Application

        Args:
            project (dict): API response with Project details
            group_resource (CustomResource): OAA resource representing parent group for project
        """

        # since we aren't currently tracking by group space use full path for project name
        project_name = project['name_with_namespace']
        project_id = project['id']
        description = project['description']
        log.debug(f"Project - {project_name}")
        project_resource = group_resource.add_sub_resource(project_name, unique_id=project_id, resource_type="project")
        project_resource.set_property("gitlab_id", project_id)

        description = project.get("description")
        if description and isinstance(description, str):
            project_resource.description = description[:256]

        # get individual member permissions
        # project_members = self._gl_api_get(f"api/v4/projects/{project_id}/members/all")
        project_members = self._gl_api_get(f"api/v4/projects/{project_id}/members")
        for member in project_members:
            user_name = member['username']
            user_id = member["id"]
            if member.get("access_level", 0) > 0:
                if user_id not in self.app.local_users:
                    self.add_user(member)
                access_role = self._map_access_level(member['access_level'])
                self.app.local_users[user_id].add_role(access_role, [project_resource])

        visibility = project["visibility"]
        project_resource.set_property("visibility", visibility)
        if visibility == "private":
            # private project, accessible only by group members and direct permissions, nothing to do
            log.debug(f"{project_name} is private repo, not additional permissions to add")
        elif visibility == "internal":
            # internal repo, any logged in user has view
            log.debug(f"{project_name} is internal repo, adding '{self.member_group_name}' for group {self.member_group_name}")
            self.app.local_groups[self.member_group_name].add_role(self.member_role_name, [project_resource])
        elif visibility == "public":
            # public repo add view for all internal users
            log.debug(f"{project_name} is public repo, adding '{self.member_group_name}' for group {self.member_group_name}")
            self.app.local_groups[self.member_group_name].add_role(self.member_role_name, [project_resource])

        return

    def _gl_api_get(self, path: str, params: dict = None) -> list|dict:
        """GitLab API GET

        Parameters:
        path (string): API path relative to gitlab_url
        params (dictionary): Optional HTTP parameters to include

        Returns:
        dictionary: API Response

        Raises:
        RequestException
        """
        if not params:
            params = {}

        headers = {}
        headers['authorization'] = f"Bearer {self.access_token}"
        path = path.lstrip("/")
        if re.match(r"^https:\/\/", path):
            api_path = path
        else:
            api_path = f"{self.gitlab_url}/{path}"

        result = []
        while True:
            response = self._perform_get(url=api_path, headers=headers, params=params, timeout=60)
            try:
                body = response.json()
            except RequestsJSONDecodeError as e:
                log.error("Unable to decode request response to JSON")
                log.debug(response.text)
                raise e

            if "X-Next-Page" in response.headers:
                # multipage response
                result.extend(body)
                next_page = response.headers.get("X-Next-Page")
                if not next_page:
                    # on the last page, break
                    break
                else:
                    params["page"] = next_page
            else:
                # single page response, return
                return body

        return result

    def _perform_get(self, *args, **kwargs) -> Response:
        """Performs single requests GET call

        Wraps `requests.get()` and handles API retries for retriable response codes and GitLab rate-limit handling

        Returns response object or raises a request exception for failures

        """

        try_count = 0
        while True:
            try_count += 1
            try:
                response = requests.get(*args, **kwargs)
                response.raise_for_status()

                return response
            except requests.exceptions.HTTPError as e:
                if try_count > self.MAX_API_RETRIES:
                    raise e

                if e.response.status_code not in [400, 429, 500, 502, 503, 504, 524, 525]:
                    # not a retryable error
                    raise e

                log.warning(f"GitLab API response error, {e}")
                # set default sleep time
                sleep_time = try_count * 1

                ratelimit_remaining = e.response.headers.get("RateLimit-Remaining", "")
                ratelimit_reset = e.response.headers.get("RateLimit-Reset", "")

                if ratelimit_remaining and ratelimit_reset:
                    try:
                        ratelimit_remaining = int(ratelimit_remaining)
                        retry_reset_time = datetime.utcfromtimestamp(int(ratelimit_reset))
                        retry_reset_str = e.response.headers.get("RateLimit-ResetTime")
                        utcnow = datetime.utcnow()
                        if e.response.status_code == 429 or ratelimit_remaining < 1:
                            log.warning(f"Rate limit exceeded, reset after {retry_reset_str}")
                            if retry_reset_time > utcnow:
                                # reset time is in the future
                                sleep_delta = retry_reset_time - utcnow
                                sleep_time = sleep_delta.seconds
                                log.warning(f"Back off for {sleep_time} seconds")
                            else:
                                # reset time has already passed, fall back to default sleep time and retry
                                pass

                    except Exception as inner_e:
                        log.error(f"Exception encountered processing ratelimit information: {inner_e}")
                        log.error("Back off for one minute")
                        sleep_time = 60
                elif e.response.status_code == 429:
                    log.warning("Rate limit returned without reset data in headers, back off for one minute")
                    sleep_time = 60

                log.warning(f"Retrying {try_count} of {self.MAX_API_RETRIES}")
                log.debug(f"Sleeping for {sleep_time}")
                time.sleep(sleep_time)
                continue
            except requests.exceptions.ConnectionError as e:
                if try_count > self.MAX_API_RETRIES:
                    raise e

                # connection errors
                log.warning(f"GitLab API connection error, {e}")
                log.warning(f"Retrying {try_count} of {self.MAX_API_RETRIES}")
                time.sleep(try_count * 1)
            except requests.exceptions.ChunkedEncodingError as e:
                if try_count > self.MAX_API_RETRIES:
                    raise e

                log.warning(f"GitLab API response included chunked encoding error, {e}")
                log.warning(f"Retrying {try_count} of {self.MAX_API_RETRIES}")
                time.sleep(try_count * 1)
            except requests.exceptions.RequestException as e:
                # any other type of requests error
                raise e


def run(gitlab_url: str, gitlab_access_token: str, veza_url: str, veza_user: str, veza_api_key: str, save_json: bool = False, verbose: bool = False) -> None:
    """ run full OAA process, discovery GitLab entities, perpare OAA template and push to Veza """
    # log.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=log.INFO)
    if verbose or os.getenv("OAA_DEBUG", False):
        log.setLevel(logging.DEBUG)
        log.debug("Enabling verbose logging")

    # Instantiate a OAA Client, do this early to validate connection before processing application
    try:
        veza_con = OAAClient(url=veza_url, api_key=veza_api_key)
    except OAAClientError as e:
        log.error(f"Unable to connect to Veza ({veza_url})")
        log.error(e.message)
        raise Exception(f"Unnable to connect to Veza ({veza_url})")

    try:
        gitlab_app = OAAGitLab(gitlab_url, gitlab_access_token)
        gitlab_app.discover()
    except RequestException as e:
        log.error(f"Error during GitLab discovery. API error {e}")
        raise e
    except Exception as e:
        log.error(e)
        raise e

    provider_name = "GitLab"
    provider = veza_con.get_provider(provider_name)
    if provider:
        log.info("Found existing provider")
    else:
        log.info(f"Creating Provider {provider_name}")
        provider = veza_con.create_provider(provider_name, "application")
    log.info(f"Provider: {provider['name']} ({provider['id']})")

    # push data
    try:
        response = veza_con.push_application(provider_name, data_source_name=gitlab_app.datasource_name, application_object=gitlab_app.app, save_json=save_json)
        if response.get("warnings", None):
            log.warning("Push succeeded with warnings:")
            for e in response["warnings"]:
                log.warning(e)
        log.info("Success")
    except OAAClientError as e:
        log.error(f"{e.error}: {e.message} ({e.status_code})")
        if hasattr(e, "details"):
            for d in e.details:
                log.error(d)
        raise e


def main() -> None:
    """ process command line and OS environment variables to ensure everything is set, call `run` function """

    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
    log = logging.getLogger()

    parser = argparse.ArgumentParser()
    parser.add_argument("--gitlab-url", default=os.getenv("GITLAB_URL", "https://gitlab.com"), help="GitLab URL to discover")
    parser.add_argument("--veza-url", default=os.getenv("VEZA_URL"), help="Veza URL for OAA connection")
    parser.add_argument("--veza-user", default=os.getenv("VEZA_USER"), help="Veza user for API connection")
    parser.add_argument("--save-json", action="store_true", help="Save OAA JSON payload to file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    gitlab_url = args.gitlab_url
    veza_url = args.veza_url
    veza_user = args.veza_user
    # ensure all require command line args are present or discovered from OS environment
    if not gitlab_url:
        oaautils.log_arg_error(log, "--gitlab-url", "GITLAB_URL")
    if not veza_url:
        oaautils.log_arg_error(log, "--veza-url", "VEZA_URL")

    # security values can only be loaded through OS environment
    gitlab_access_token = os.getenv("GITLAB_ACCESS_TOKEN")
    if not gitlab_access_token:
        oaautils.log_arg_error(log, env="GITLAB_ACCESS_TOKEN")

    veza_api_key = os.getenv("VEZA_API_KEY")
    if not veza_api_key:
        oaautils.log_arg_error(log, env="VEZA_API_KEY")

    if None in [gitlab_url, gitlab_access_token, veza_url, veza_api_key]:
        log.error("Missing one or more required parameters")
        sys.exit(1)

    try:
        run(gitlab_url, gitlab_access_token, veza_url, veza_user, veza_api_key, save_json=args.save_json, verbose=args.verbose)
    except OAAClientError as e:
        log.error("An error was encountered with the Veza API")
        log.error(e)
        log.error("Exiting with error")
        sys.exit(1)
    except RequestException as e:
        log.error("An error was encountered with the GitLab API")
        log.error("Exiting with error")
        sys.exit(1)

if __name__ == '__main__':
    # replace the log with the root logger if running as main
    log = logging.getLogger()
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
    main()
