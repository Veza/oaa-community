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
from datetime import datetime, timedelta

import oaaclient.utils as oaautils
import requests
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, CustomResource, OAAPermission, OAAPropertyType
from requests import HTTPError
from requests.auth import HTTPBasicAuth

logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)

class OAABitbucket():
    """OAA Bitbucket Discovery

    OAABitbucket handles discovery of the Bitbucket Cloud workspace, projects and repositories with their user permissions
    It generates a OAA `CustomApplication` instance for submission

    Args:
        workspace (str): Bitbucket Cloud workspace to discover
        username (str): Username for Bitbucket connection
        app_key (str): App key generated for user
        skip_branch_restriction_discovery (bool, optional): Set to True to skip branch protection discovery. Defaults to False.

    Parameters:
        app (CustomApplication): Populate by the `discover()` method
    """

    def __init__(self, workspace: str, username: str = "",
                 app_key: str = "", client_key: str = "", client_secret: str = "",
                 skip_branch_restriction_discovery: bool = False) -> None:


        self.workspace = workspace
        self.skip_branch_restriction_discovery = skip_branch_restriction_discovery

        # Defined the list of allowed branch restriction rules for which the data needs to be collected.
        self.allowed_branch_restriction_rules = [
            "allow_auto_merge_when_builds_pass", "require_passing_builds_to_merge", "enforce_merge_checks",
            "require_approvals_to_merge", "require_default_reviewer_approvals_to_merge",
            "require_tasks_to_be_completed"]


        self.app = CustomApplication(f"Bitbucket - {workspace}", application_type="Bitbucket")

        self.app.property_definitions.define_local_user_property("email", OAAPropertyType.STRING)
        self.app.property_definitions.define_local_group_property("owner", OAAPropertyType.STRING)

        self.app.property_definitions.define_local_user_property("is_collaborator", OAAPropertyType.BOOLEAN)

        self.app.property_definitions.define_resource_property("Project", "key", OAAPropertyType.STRING)
        self.app.property_definitions.define_resource_property("Project", "is_private", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_resource_property("Project", "has_publicly_visible_repos", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_resource_property("Repo", "is_private", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_resource_property("Repo", "slug", OAAPropertyType.STRING)
        self.app.property_definitions.define_resource_property("Repo", "project_key", OAAPropertyType.STRING)
        self.app.property_definitions.define_resource_property("Repo", "fork_policy", OAAPropertyType.STRING)

        if not self.skip_branch_restriction_discovery:
            self.app.property_definitions.define_resource_property("Repo", "default_branch_protected", OAAPropertyType.BOOLEAN)
            for branch_restriction_rule in self.allowed_branch_restriction_rules:
                self.app.property_definitions.define_resource_property("Repo", branch_restriction_rule, OAAPropertyType.BOOLEAN)

        self._populate_perms()

        self._oauth_token = None
        self._http_auth = None
        self._oauth_expire_time = None
        self._refresh_token = None
        self._client_key = client_key
        self._client_secret = client_secret

        if client_key and client_secret:
            self._oauth_token = self.bitbucket_oauth_login()
            log.info("Using Oauth authentication")
        elif username and app_key:
            self._http_auth = HTTPBasicAuth(username, app_key)
        else:
            raise ValueError("Must provide username and app_key or client_key and client_secret for authentication")

        self.atlassian_login = os.getenv("ATLASSIAN_LOGIN", "")
        self.atlassian_api_key = os.getenv("ATLASSIAN_API_KEY")

        pass

    def discover(self) -> None:
        """Start Bitbucket discovery

        Starts the Bitbucket workspace discovery, run after class in initialized
        """

        self._discover_workspace()
        self._discover_workspace_groups()
        self._discover_projects()
        self._discover_bitbucket_emails()
        return

    def _discover_workspace(self) -> None:
        """Perform workspace discovery

        Get the workspace permissions which populates all the workspace users
        """
        log.info(f"Starting workspace discovery {self.workspace}")
        workspace_perms = self.bitbucket_api_get(f"workspaces/{self.workspace}/permissions")
        for e in workspace_perms:
            user = e.get("user")
            if not user:
                log.warning("Workspace permission returned for non-user entity")
                log.warning(f"type: {e.get('type', None)}, keys: {e.keys()}")
                log.debug(json.dumps(e))
                continue

            account_name = user.get("display_name")
            account_id = user.get("account_id")

            if not account_id:
                log.warning("User has no account_id, skipping ...")
                log.debug(json.dumps(user))
                continue

            if not account_name:
                account_name = account_id

            new_user = self.app.add_local_user(name=account_name, unique_id=account_id)

            if e.get("last_accessed"):
                last_accessed = e["last_accessed"]
                new_user.last_login_at = last_accessed
            if e.get("added_on"):
                added_on = e["added_on"]
                new_user.created_at = added_on

            if not e['permission'] in self.app.custom_permissions:
                log.error(f"Unknown workspace permission for user: {e['permission']}")
                continue

            if e['permission'] == "collaborator":
                new_user.set_property("is_collaborator", True)
            else:
                new_user.set_property("is_collaborator", False)

            new_user.add_permission(e['permission'], apply_to_application=True)
        return

    def _discover_workspace_groups(self) -> None:
        """Discovery Workspace Groups

        Bitbucket does not include a groups/membership API as part of current v2 API, they are maintaining the
        v1 API for the groups endpoint for an unknown amount of time.

        Use the v1 API to get the list of Bitbucket groups and memberships
        """

        log.info("Starting workspace groups discovery")
        if self._oauth_token:
            log.debug("Attempting to discover groups using internal API")
            groups = self.bitbucket_api_get(f"https://api.bitbucket.org/internal/workspaces/{self.workspace}/groups", params={"pagelen": 100})
            for g in groups:
                slug = g.get("slug")
                name = g.get("name")
                group_type = g.get("type")
                if group_type != "group":
                    log.warning(f"Discovered group of known type: {g}")

                local_group = self.app.add_local_group(name=name, unique_id=slug)
                owner = g.get("owner", {}).get("username")
                if owner:
                    local_group.set_property("owner", owner)
                else:
                    log.debug(f"Unable to determine owner for group {g}")

                self._discover_group_members(slug)

        else:
            log.debug("Using v1 API for groups discovery")
            groups = self.bitbucket_api_get(f"https://api.bitbucket.org/1.0/groups/{self.workspace}")
            for group in groups:
                slug = group.get("slug")
                name = group.get("name")
                local_group = self.app.add_local_group(name=name, unique_id=slug)

                for member in group.get("members", []):
                    member_id = member.get("account_id")
                    if member_id in self.app.local_users:
                        self.app.local_users[member_id].add_group(slug)

        log.info("Finished workspace groups discovery")
        return

    def _discover_group_members(self, group_slug: str) -> None:
        """Discovery members for single group

        Uses the Bitbucket internal API to discovery members for a group. Requires Oauth workflow.

        Populates self.app.local_users memberships

        Args:
            group_slug (str): Group slug to discover for
        """
        if not self._oauth_token:
            log.error("Cannot discover group members without oauth token")
            return

        log.debug(f"Discovery group memberships for {group_slug}")
        members = self.bitbucket_api_get(f"https://api.bitbucket.org/internal/workspaces/{self.workspace}/groups/{group_slug}/members", params={"pagelen": 100})
        for u in members:
            account_id = u.get("account_id")
            if account_id not in self.app.local_users:
                log.warning(f"Unknown user to discovered as member of group: {group_slug}, {u}")
                continue

            self.app.local_users[account_id].add_group(group_slug)

        return

    def _discover_projects(self) -> None:
        """Discover Bitbucket projects

        Loop through all the projects in the Bitbucket workspace. Discovers repositories for each project.
        """
        log.info("Starting project discovery")
        projects = self.bitbucket_api_get(f"workspaces/{self.workspace}/projects")

        for p in projects:
            key = p["key"]
            name = p["name"]

            project = self.app.add_resource(name, resource_type="Project")
            if p.get("description"):
                project.description = self._truncate_description(p.get("description", ""))

            project.set_property("key", p["key"])
            project.set_property("is_private", p["is_private"])
            if "has_publicly_visible_repos" in p:
                project.set_property("has_publicly_visible_repos", p["has_publicly_visible_repos"])

            self._discover_project_repos(key, project)

        return

    def _discover_project_repos(self, key: str, project: CustomResource) -> None:
        """Discover all repositories in project

        Args:
            key (str): Project `key` value for Bitbucket API
            project (CustomResource): Parent project CustomResource to add repository resources too
        """
        log.info(f"Discovering repos for project {key}")

        # we can only get explicit permissions for the repo if running with admin, if we get a 403 set to false so we stop trying in future repos
        try_explicit_permissions = True

        project_repos = self.bitbucket_api_get(f"repositories/{self.workspace}", params={"q": f"project.key=\"{key}\"", "pagelen": 100})
        for r in project_repos:
            name = r['name']
            slug = r['slug']
            project_key = r['project']['key']
            repo = project.add_sub_resource(name, resource_type="Repo")
            if r.get("description"):
                repo.description = self._truncate_description(r.get("description", ""))
            repo.set_property("is_private", r["is_private"])
            repo.set_property("slug", slug)
            repo.set_property("project_key", project_key)
            repo.set_property("fork_policy", r["fork_policy"])

            try:
                default_branch = r['mainbranch']['name']
                if not self.skip_branch_restriction_discovery:
                    repos_list_restrictions = self.bitbucket_api_get(f"repositories/{self.workspace}/{slug}/branch-restrictions",
                                                                     params={"pagelen": 100, "pattern": default_branch})
                    if repos_list_restrictions:
                        repo.set_property("default_branch_protected", True)
                    else:
                        repo.set_property("default_branch_protected", False)
                    for restrictions in repos_list_restrictions:
                        if restrictions['pattern'] == default_branch and restrictions['kind'] in self.allowed_branch_restriction_rules:
                            repo.set_property(restrictions['kind'], True)

            except HTTPError as e:
                if e.response.status_code == 403:
                    log.warning("Permission denied on branch protections")
                    self.skip_branch_restriction_discovery = True
                    pass
                else:
                    raise e
            if try_explicit_permissions:
                try:
                    self._discover_project_permission_explicit(repo_slug=slug, repo_resource=repo)
                    # if explicit discovery is successful move to next repo
                    continue
                except HTTPError as e:
                    if e.response.status_code == 403:
                        # user does not have admin permission on repository, cannot retrieve explicit perms
                        # set to false to stop trying on future repos
                        log.warning("Unable to get explicit repository permissions, falling back to user perms")
                        try_explicit_permissions = False
                    else:
                        # something else went wrong
                        raise e

            # should only get this far if _discover_project_permission_explicit failed and falling back to effective repository permissions discovery
            repo_perms = self.bitbucket_api_get(f"workspaces/{self.workspace}/permissions/repositories/{slug}", params={"pagelen": 100})
            for perm in repo_perms:
                permission = perm.get("permission")
                if "user" in perm:
                    # user assignment
                    account_id = perm["user"]["account_id"]
                    if account_id in self.app.local_users:
                        self.app.local_users[account_id].add_permission(permission, resources=[repo])
                    else:
                        log.error(f"Permission assigned to unknown user {perm}")
                else:
                    log.error(f"Unknown repository permission assignment: {perm}")

        return

    def _discover_project_permission_explicit(self, repo_slug: str, repo_resource: CustomResource) -> None:
        """Discover explicit repository permissions

        Discover the explicitly assigned repository permissions for users and groups

        Args:
            repo_slug (str): repository slug
            repo_resource (CustomResource): Custom Resource for repo
        """
        repo_user_perms = self.bitbucket_api_get(f"repositories/{self.workspace}/{repo_slug}/permissions-config/users")
        for user_perm in repo_user_perms:
            permission = user_perm.get("permission")
            account_id = user_perm.get("user", {}).get("account_id")
            if permission not in self.app.custom_permissions:
                log.error("User has repository permission that is not know, skipping")
                log.error(user_perm)
                continue

            if account_id in self.app.local_users:
                self.app.local_users[account_id].add_permission(permission, resources=[repo_resource])
            else:
                log.error("Repo permission assigned to unknown user")
                log.error(user_perm)

        repo_group_perms = self.bitbucket_api_get(f"repositories/{self.workspace}/{repo_slug}/permissions-config/groups")
        for group_perm in repo_group_perms:
            permission = group_perm.get("permission")

            group_slug = group_perm.get("group", {}).get("slug")
            if permission not in self.app.custom_permissions.keys():
                log.error("User has repository permission that is not know, skipping")
                log.error(group_perm)
                continue

            if group_slug in self.app.local_groups:
                self.app.local_groups[group_slug].add_permission(permission, resources=[repo_resource])
            else:
                log.error("Repo permission assigned to unknown group")
                log.error(group_perm)

        return

    def _discover_bitbucket_emails(self) -> None:
        """Discovery user emails through Atlassian API

        Bitbucket API does not return user emails (identities) but the Atlassian API does. If provided with Atlasssian credentials
        then we can loop through the Atlassian users and sync up any IDs that match and added any emails returned.
        """

        atlassian_login = os.getenv("ATLASSIAN_LOGIN")
        atlassian_api_key = os.getenv("ATLASSIAN_API_KEY")

        if not (atlassian_login and atlassian_api_key):
            log.debug("Atlassian login and api key not set, skipping email discovery")
            return

        log.info("Starting Atlassian user info discovery")
        start_at = 0
        max_results = 100
        jira_user_list = []
        auth = HTTPBasicAuth(atlassian_login, atlassian_api_key)

        # validate that the user has the correct permissions before continuing
        try:
            check_response = requests.get(
                f"https://{self.workspace}.atlassian.net/rest/api/3/mypermissions", params={"permissions": "USER_PICKER"},
                auth=auth, timeout=60)
            user_picker_permission = check_response.json().get("permissions", {}).get("USER_PICKER", {})
            if not user_picker_permission.get("havePermission"):
                log.error(f"Atlassian user does not have Browse Users Global Permission, cannot retrieve user identities. Atlassian user {atlassian_login}")
                return
        except requests.exceptions.RequestException as e:
            log.error("Error while calling Atlassian API, unable to collect user identities")
            log.error(e)
            if e.response:
                log.debug(e.response.text)
            return

        # get all the users
        while True:
            response = requests.get(
                f"https://{self.workspace}.atlassian.net/rest/api/3/users/search", params={"startAt": start_at, "maxResults": max_results},
                auth=auth, timeout=60)

            if response.ok:
                user_list = response.json()
                if not user_list:
                    break

                for user in user_list:
                    if user.get("accountId") in self.app.local_users:
                        account_id = user.get("accountId")
                        email = user.get("emailAddress")
                        if email:
                            self.app.local_users[account_id].add_identity(email)
                            self.app.local_users[account_id].set_property("email", email)

                jira_user_list.extend(user_list)
                start_at += max_results

            else:
                log.warning(f"Unable to retrieve Atlassian user details, {response.reason}")
                break

        return

    def bitbucket_api_get(self, path: str, params: dict = None) -> dict:
        """Perform a bitbucket GET call and handle pagination

        Args:
            path (str): API path either relative to Bitbucket base API path or complete URL
            params (dict, optional): HTTP request parameters. Defaults to None.

        Raises:
            HTTPError: If API call returns error

        Returns:
            dict: API response
        """

        if re.match(r"^https:\/\/.*", path):
            url = path
        else:
            path = path.lstrip("/")
            url = f"https://api.bitbucket.org/2.0/{path}"

        # determine which authentication flow we're using
        auth = None
        headers = {}
        if self._oauth_token:
            headers["Authorization"] = f"Bearer {self._oauth_token}"
        else:
            auth = self._http_auth

        retries = 0
        start_time = datetime.now()
        values = []
        while True:
            if self._oauth_expire_time and datetime.now() > self._oauth_expire_time:
                self._oauth_token = self.bitbucket_oauth_login()
                headers["Authorization"] = f"Bearer {self._oauth_token}"

            try:
                response = requests.get(url, auth=auth, headers=headers, params=params, timeout=60)
                response.raise_for_status()

                retries = 0
                data = response.json()
                if "page" not in data:
                    # none list response, single entity get
                    values = data
                    break
                elif "next" in data:
                    # pagination needed
                    url = data['next']
                    values.extend(data['values'])
                else:
                    # list response in single page or last iteration
                    values.extend(data['values'])
                    break

            except requests.exceptions.HTTPError as e:
                if e.response.status_code in [500, 502, 503, 504] and retries < 5:
                    log.warning(f"Bitbucket API returned error, {e}")
                    retries += 1
                    log.warning(f"Retrying {retries} of 5")
                    time.sleep(retries * 1)
                    continue
                elif e.response.status_code == 429:
                    log.warning(f"Bitbucket API rate limit encountered")
                    if (datetime.now() - start_time) > timedelta(minutes=70):
                        log.error("Maximum retry wait time has been exceeded")
                        raise e
                    retries += 1
                    sleep_time = min(retries * 60, 600)
                    log.warning(f"Backing off, retry {retries}, {sleep_time} seconds")
                    time.sleep(sleep_time)
                else:
                    raise e

            except requests.exceptions.RequestException as e:
                log.warning(f"Bitbucket API error making call, {e}")
                if retries < 5:
                    retries += 1
                    log.warning(f"Retrying {retries} of 5")
                    time.sleep(retries * 1)
                    continue
                else:
                    raise e

        return values

    def bitbucket_oauth_login(self) -> str:

        token = ""

        auth = HTTPBasicAuth(self._client_key, self._client_secret)

        if self._refresh_token:
            log.debug("Refreshing oauth token")
            response = requests.post("https://bitbucket.org/site/oauth2/access_token", auth=auth, data={"grant_type": "refresh_token", "refresh_token": self._refresh_token})
        else:
            response = requests.post("https://bitbucket.org/site/oauth2/access_token", auth=auth, data={"grant_type": "client_credentials"})
        response.raise_for_status()

        if response.ok:
            data = response.json()
            token = data.get("access_token")
            if not token:
                log.error("0Auth login request did not return an auth token")

            expires_in = data.get("expires_in")
            self._refresh_token = data.get("refresh_token")
            try:
                self._oauth_expire_time = datetime.now() + timedelta(seconds=expires_in) - timedelta(minutes=5)
                log.debug(f"Set oauth expire time to {self._oauth_expire_time.isoformat()}")
            except Exception as e:
                log.error(f"Unable to update oauth expire time. Will be unable to refresh token. {e}")

        return token

    def _populate_perms(self) -> None:
        """Create OAA Permissions and Roles
        """

        self.app.add_custom_permission("owner",  permissions=[OAAPermission.DataRead, OAAPermission.DataWrite, OAAPermission.DataDelete])
        self.app.add_custom_permission("collaborator",  permissions=[OAAPermission.DataRead, OAAPermission.DataWrite])
        self.app.add_custom_permission("member",  permissions=[OAAPermission.DataRead])

        self.app.add_custom_permission(
            "admin", apply_to_sub_resources=True, permissions=[OAAPermission.DataRead, OAAPermission.DataWrite, OAAPermission.DataDelete])
        self.app.add_custom_permission("write", apply_to_sub_resources=True, permissions=[OAAPermission.DataWrite, OAAPermission.DataRead])
        self.app.add_custom_permission("read", apply_to_sub_resources=True, permissions=[OAAPermission.DataRead])

    def _truncate_description(self, description: str, length: int = 256) -> str|None:

        try:
            encoded = description.encode("utf-8", errors="replace")
            truncated = encoded[:length]
            result = truncated.decode("utf-8", errors="ignore")
        except Exception as e:
            log.error(f"Error shortening description, {e}")
            log.debug(f"description original value: '{description}'")
            return None

        return result

def run(bitbucket_workspace: str,
        bitbucket_username: str,
        bitbucket_app_key: str,
        veza_url: str,
        veza_api_key: str,
        save_json: bool = False,
        debug: bool = False,
        oauth_client_key: str = "",
        oauth_client_secret: str = "",
        skip_branch_restriction_discovery: bool = False,
        create_report: bool = False
        ) -> None:
    """Run Bitbucket connector

    This function can be imported to run the connector from another Python source.

    Args:
        bitbucket_workspace (str): Bitbucket Workspace for discovery
        bitbucket_username (str): Username for Bitbucket user based authentication. Set to "" to use oauth.
        bitbucket_app_key (str): User app key for user based authentication. Set to "" to use oauth.
        veza_url (str): Veza tenant URL
        veza_api_key (str): Veza API key
        save_json (bool, optional): Set to true to save OAA payload to local file prior to push. Defaults to False.
        debug (bool, optional): Set to True to enable verbose debug logging. Defaults to False.
        oauth_client_key (str, optional): Bitbucket OAuth client key.. Defaults to "".
        oauth_client_secret (str, optional): Bitbucket Oauth client secret.. Defaults to "".
        skip_branch_restriction_discovery (bool, optional): Set to True to skip branch protection discovery. Defaults to False.

    Raises:
        RequestException: For errors encountered from Bitbucket API
        OAAClientError: For errors encountered from Veza API
    """

    if debug:
        log.setLevel(logging.DEBUG)

    veza_con = OAAClient(veza_url, api_key=veza_api_key)

    bitbucket = OAABitbucket(
        bitbucket_workspace, bitbucket_username, bitbucket_app_key,
        oauth_client_key, oauth_client_secret, skip_branch_restriction_discovery)

    try:
        bitbucket.discover()
    except requests.exceptions.RequestException as e:
        log.error(f"Error making Bitbucket API Call: {e}")
        log.debug(f"{e.response.text}")
        raise e

    log.info("Starting push")
    provider_name = "Bitbucket"
    provider = veza_con.get_provider(provider_name)
    if provider:
        log.info("Found existing provider")
    else:
        log.info(f"Creating Provider {provider_name}")
        provider = veza_con.create_provider(provider_name, "application")
        create_report = True
    log.info(f"Provider: {provider['name']} ({provider['id']})")

    # set the Box icon
    data_source_name = f"bitbucket - {bitbucket.workspace}"
    # push data
    try:
        response = veza_con.push_application(provider_name, data_source_name=data_source_name, application_object=bitbucket.app, save_json=save_json)
        if response.get("warnings", None):
            log.warning("Push succeeded with warnings:")
            for e in response["warnings"]:
                log.warning(e)

        log.info("Success")
    except OAAClientError as e:
        log.error(f"Veza API error {e.error}: {e.message} ({e.status_code})")
        if hasattr(e, "details"):
            for d in e.details:
                log.error(d)
        log.error("Update did not finish")
        raise e

    if create_report:
        report_source_file = "report-bitbucket-security.json"
        if os.path.isfile(report_source_file):
            log.info(f"Creating or updating report from {report_source_file}")
            with open(report_source_file) as f:
                report_definition = json.load(f)
            response = oaautils.build_report(veza_con, report_definition)
            report_id = response.get("id")
            if report_id:
                log.info(f"Report available at: {veza_url}/app/reports/{report_id}, Veza may still be populating report data")
            else:
                log.error("Report creation did not return ID")
                log.info(json.dumps(response))
        else:
            log.warning(f"Unable to create report, cannot locate source file {report_source_file}")
    return

###########################################################
# Main
###########################################################
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=False, default=os.getenv("BITBUCKET_WORKSPACE"), help="Name of Bitbucket workspace")
    parser.add_argument("--skip-branch-restriction-discovery", action="store_true", help="Skip discovery of branch restriction rules")
    parser.add_argument("--veza-url", required=False, default=os.getenv("VEZA_URL"), help="Hostname for Veza deployment")
    parser.add_argument("--save-json", action="store_true", help="Save OAA JSON payload to file")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug output")
    parser.add_argument("--create-report", action="store_true", help="Create/update a Veza Report with common Queries. Defaults to true for first discovery.")
    args = parser.parse_args()

    bitbucket_workspace = args.workspace
    skip_branch_restriction_discovery = args.skip_branch_restriction_discovery
    veza_url = args.veza_url
    save_json = args.save_json

    # get root logger if running as main
    log = logging.getLogger()

    debug = False
    if args.debug or os.getenv("OAA_DEBUG"):
        debug = True

    # Bitbucket parameters
    if not bitbucket_workspace:
        oaautils.log_arg_error(log, "--workspace", "BITBUCKET_WORKSPACE")

    bitbucket_username = os.getenv("BITBUCKET_USER", "")
    bitbucket_app_key = os.getenv("BITBUCKET_APP_KEY", "")
    bitbucket_oauth_client_key = os.getenv("BITBUCKET_CLIENT_KEY", "")
    bitbucket_oauth_client_secret = os.getenv("BITBUCKET_CLIENT_SECRET", "")

    # Veza Parameters
    veza_api_key = os.getenv('VEZA_API_KEY')
    if not veza_url:
        oaautils.log_arg_error(log, "--veza-url", "VEZA_URL")
    if not veza_api_key:
        oaautils.log_arg_error(log, env="VEZA_API_KEY")


    if not ((bitbucket_oauth_client_key and bitbucket_oauth_client_secret) or (bitbucket_username and bitbucket_app_key)):
        log.error("No Bitbucket authentication credentials provided")
        log.error("Must provider username and app key or Oauth client and secret")
        sys.exit(1)

    if None in [bitbucket_workspace, veza_url, veza_api_key]:
        log.error("Missing one or more required parameters")
        sys.exit(1)

    try:
        run(bitbucket_workspace=bitbucket_workspace,
            skip_branch_restriction_discovery=skip_branch_restriction_discovery,
            bitbucket_username=bitbucket_username,
            bitbucket_app_key=bitbucket_app_key,
            veza_url=veza_url,
            veza_api_key=veza_api_key,
            save_json=save_json,
            debug=debug,
            oauth_client_key=bitbucket_oauth_client_key,
            oauth_client_secret=bitbucket_oauth_client_secret,
            create_report=args.create_report)
    except requests.exceptions.RequestException as e:
        log.error("Error encountered from Bitbucket API, exiting")
        log.error(e)
        sys.exit(1)
    except OAAClientError as e:
        log.error("Error encountered from Veza API, exiting")
        log.error(e)
        sys.exit(2)

    log.info("Success")

if __name__ == '__main__':
    # replace the log with the root logger if running as main
    log = logging.getLogger()
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
    main()