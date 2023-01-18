#!env python3
"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, CustomResource, OAAPermission, OAAPropertyType, LocalUser, LocalGroup
from requests import HTTPError
from requests.auth import HTTPBasicAuth
import argparse
import logging
import oaaclient.utils as oaautils
import os
import re
import requests
import sys

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

    Parameters:
        app (CustomApplication): Populate by the `discover()` method
    """

    def __init__(self, workspace: str, username: str, app_key: str) -> None:


        self.workspace = workspace
        self._http_auth = HTTPBasicAuth(username, app_key)

        self.app = CustomApplication(f"Bitbucket - {workspace}", application_type="Bitbucket")

        self.app.property_definitions.define_resource_property("Project", "key", OAAPropertyType.STRING)
        self.app.property_definitions.define_resource_property("Project", "is_private", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_resource_property("Project", "has_publicly_visible_repos", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_resource_property("Repo", "is_private", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_resource_property("Repo", "slug", OAAPropertyType.STRING)
        self.app.property_definitions.define_resource_property("Repo", "project_key", OAAPropertyType.STRING)

        self._populate_perms()
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

        Get the workspace permissions which populatese all the workspace users
        """
        log.info(f"Starting workspace discovery {self.workspace}")
        workspace_perms = self.bitbucket_api_get(f"workspaces/{self.workspace}/permissions")
        for e in workspace_perms:
            account_name = e['user']['display_name']
            account_id = e['user']['account_id']
            account_uuid = e['user']['uuid']

            new_user = self.app.add_local_user(name=account_name, unique_id=account_id)

            if e.get("last_accessed"):
                last_accessed = e["last_accessed"]
                new_user.last_login_at = last_accessed
            if e.get("added_on"):
                added_on = e["added_on"]
                new_user.created_at = added_on

            new_user.add_permission(e['permission'], apply_to_application=True)
        return

    def _discover_workspace_groups(self) -> None:
        """Discovery Workspace Groups

        Bitbucket does not include a groups/membership API as part of current v2 API, they are maintaining the
        v1 API for the groups endpoint for an unknown amount of time.

        Use the v1 API to get the list of Bitbucket groups and memberships
        """

        log.info("Starting workspace groups discovery")
        groups = self.bitbucket_api_get(f"https://api.bitbucket.org/1.0/groups/{self.workspace}")
        for group in groups:
            slug = group.get("slug")
            name = group.get("name")
            local_group = self.app.add_local_group(name=name, unique_id=slug)

            for member in group.get("members", []):
                member_id = member.get("account_id")
                if member_id in self.app.local_users:
                    self.app.local_users[member_id].add_group(slug)

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
            project.description = p["description"]

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
            repo.description = r["description"]
            repo.set_property("is_private", r["is_private"])
            repo.set_property("slug", slug)
            repo.set_property("project_key", project_key)


            if try_explicit_permissions:
                try:
                    self._discover_project_permission_explicit(repo_slug=slug, repo_resource=repo)
                    # if explicit discovery is successful move to next repo
                    continue
                except HTTPError as e:
                    if e.response.status_code == 403:
                        # user does not have admin permission on repository, cannot retrieve explicit perms
                        # set to false to stop trying on future repos
                        log.info("Unable to get explicit repository permissions, falling back to user perms")
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
        while True:
            response = requests.get(f"https://{self.workspace}.atlassian.net/rest/api/3/users/search?startAt={start_at}&maxResults={max_results}", auth=auth, timeout=60)

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

                jira_user_list.extend(user_list)
                start_at += max_results

            else:
                log.warning(f"Unable to retreive Atlassian user details, {response.reason}")
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

        values = []
        while True:
            response = requests.get(url, auth=self._http_auth, params=params, timeout=60)

            if response.ok:
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
                    # list response in single page or last itteration
                    values.extend(data['values'])
                    break
            else:
                raise HTTPError(response.reason, response=response)

        return values

    def _populate_perms(self) -> None:
        """Create OAA Permissions and Roles
        """

        self.app.add_custom_permission("owner",  permissions=[OAAPermission.DataRead, OAAPermission.DataWrite, OAAPermission.DataDelete])
        self.app.add_custom_permission("member",  permissions=[OAAPermission.DataRead])

        self.app.add_custom_permission("admin", apply_to_sub_resources=True, permissions=[OAAPermission.DataRead, OAAPermission.DataWrite, OAAPermission.DataDelete])
        self.app.add_custom_permission("write", apply_to_sub_resources=True, permissions=[OAAPermission.DataWrite, OAAPermission.DataRead])
        self.app.add_custom_permission("read", apply_to_sub_resources=True, permissions=[OAAPermission.DataRead])


def run(bitbucket_workspace: str, bitbucket_username: str, bitbucket_app_key: str, veza_url: str, veza_api_key: str, save_json: bool = False, debug: bool = False):
    """Run Bitbucket connector

    This function can be imported to run the connector from another Python source.

    Args:
        bitbucket_workspace (str): _description_
        bitbucket_username (str): _description_
        bitbucket_app_key (str): _description_
        veza_url (str): _description_
        veza_api_key (str): _description_
        save_json (bool, optional): _description_. Defaults to False.
        debug (bool, optional): _description_. Defaults to False.
    """

    if debug:
        log.setLevel(logging.DEBUG)

    veza_con = OAAClient(veza_url, api_key=veza_api_key)

    bitbucket = OAABitbucket(bitbucket_workspace, bitbucket_username, bitbucket_app_key)

    bitbucket.discover()

    log.info("Starting push")
    provider_name = "Bitbucket"
    provider = veza_con.get_provider(provider_name)
    if provider:
        log.info("Found existing provider")
    else:
        log.info(f"Creating Provider {provider_name}")
        provider = veza_con.create_provider(provider_name, "application")
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

    return

###########################################################
# Main
###########################################################
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=False, default=os.getenv("BITBUCKET_WORKSPACE"), help="Name of Bitbucket workspace")
    parser.add_argument("--veza-url", required=False, default=os.getenv("VEZA_URL"), help="Hostname for Veza deployment")
    parser.add_argument("--save-json", action="store_true", help="Save OAA JSON payload to file")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug output")
    args = parser.parse_args()

    bitbucket_workspace = args.workspace
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
    bitbucket_username = os.getenv("BITBUCKET_USER")
    bitbucket_app_key = os.getenv("BITBUCKET_APP_KEY")

    if not bitbucket_username:
        oaautils.log_arg_error(log, env="BITBUCKET_USER")

    if not bitbucket_app_key:
        oaautils.log_arg_error(log, env="BITBUCKET_APP_KEY")
    # Veza Parameters
    veza_api_key = os.getenv('VEZA_API_KEY')
    if not veza_url:
        oaautils.log_arg_error(log, "--veza-url", "VEZA_URL")
    if not veza_api_key:
        oaautils.log_arg_error(log, env="VEZA_API_KEY")


    if None in [bitbucket_workspace, bitbucket_username, bitbucket_app_key, veza_url, veza_api_key]:
        log.error("Missing one or more required parameters")
        sys.exit(1)

    run(bitbucket_workspace=bitbucket_workspace, bitbucket_username=bitbucket_username,
        bitbucket_app_key=bitbucket_app_key, veza_url=veza_url, veza_api_key=veza_api_key, save_json=save_json, debug=debug)

if __name__ == '__main__':
    # replace the log with the root logger if running as main
    log = logging.getLogger()
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
    main()