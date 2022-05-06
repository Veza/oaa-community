#!env python3

from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, CustomResource, OAAPermission, OAAPropertyType
from requests import HTTPError
import argparse
import logging
import json
import os
import re
import requests
import sys

logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)


class OAAGitLab():
    """
    OAA Class for discovering GitLab deployment.

    Argument:
        gitlab_url (string): URL for GitLab host with our without protocol, if no protocol assumes https://
        access_token (string): Impersination token used for GitLab API calls
        deployment_name (string): Optional, name for deployment will be used for Application name, if omitted hostname is used

    Attributes:
        app (CustomApplication): CustomApplication object to create OAA template

        member_group_name (string): Name for group that will be created and all users added to, represents logged in users inherit permissions
        member_role_name (string): Name for role that includes permissions all logged in users have
        admin_role_name (name): Name for admin role created
        perm_map (dictionary): Mapping of GitLab numeric access levels to name strings
    """

    def __init__(self, gitlab_url: str, access_token: str, deployment_name: str = None) -> None:
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

        if not deployment_name:
            self.deployment_name = self.gitlab_url.split("://")[1]
        else:
            self.deployment_name = deployment_name

        self.access_token = access_token
        self.app = CustomApplication(f"GitLab - {self.deployment_name}", "GitLab")

        # test token
        try:
            calling_user = self.__gl_api_get("/api/v4/user")
        except HTTPError as e:
            log.error(f"Error calling GitLab API ({e.response.status_code})")
            raise(HTTPError)

        if not calling_user['is_admin']:
            log.warning(f"Calling GitLab API as non-admin user {calling_user['username']}, discovery may be limitted ")

        self.__populate_permissions()

        # GitLab returns permissions as integers, secret decorder ring as dictinoary
        self.access_levels = {0: "No access",
                              5: "Minimal access",
                              10: "Guest",
                              20: "Reporter",
                              30: "Developer",
                              40: "Maintainer",
                              50: "Owner"
                              }

        # in order to avoid calling groups API repeaditly to get user's access levels store the users access levels into dictionary keyed by group id
        self.group_user_access_levels = {}
        # store each groups parent ID to reduce API calls
        self.group_parent_ids = {}

    def __map_access_level(self, access_level: int) -> str:
        """ returns string of role name from GitLab numberic based access levels """

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

    def __populate_permissions(self) -> None:
        """ Defines permissions and creates base roles/groups """

        gitlab_permissions = {
            "Admin": [OAAPermission.DataWrite, OAAPermission.MetadataWrite],
            "View": [OAAPermission.MetadataRead],
            "Manage Access": [OAAPermission.MetadataWrite],
            "Pull": [OAAPermission.DataRead],
            "Branch": [OAAPermission.DataRead],
            "Merge": [OAAPermission.DataWrite],
            "Push": [OAAPermission.DataWrite],
            "Maintain": [OAAPermission.DataWrite]
        }

        for p in gitlab_permissions:
            self.app.add_custom_permission(p, gitlab_permissions[p])

        # GitLab Roles & groups
        self.app.add_local_role(self.admin_role_name, ["Admin"])
        self.app.add_local_role(self.member_role_name, ["View"])
        self.app.add_local_group(self.member_group_name)

        # Repo Roles
        self.app.add_local_role("Guest", ["View", "Pull"])
        self.app.add_local_role("Reporter", ["View", "Pull"])
        self.app.add_local_role("Developer", ["View", "Pull", "Branch", "Push", "Merge"])
        self.app.add_local_role("Maintainer", ["View", "Pull", "Branch", "Push", "Merge"])
        self.app.add_local_role("Owner", ["View", "Pull", "Branch", "Push", "Merge", "Manage Access"])

    def discover(self) -> None:
        """ run full GitLab discovery process """
        log.info("Starting GitLab discovery")
        self.discover_users()
        self.discover_groups()
        self.discover_projects()
        return

    def discover_users(self) -> None:
        """ discover GitLab users """

        # define custom properties for the users
        self.app.property_definitions.define_local_user_property("gitlab_id", OAAPropertyType.NUMBER)
        self.app.property_definitions.define_local_user_property("bot", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_local_user_property("is_licensed", OAAPropertyType.STRING)
        self.app.property_definitions.define_local_user_property("state", OAAPropertyType.STRING)

        log.info("Discovering GitLab Users")
        gitlab_users = self.__gl_api_get("/api/v4/users")
        for user in gitlab_users:
            user_name = user['username']
            is_admin = user['is_admin']
            if user_name not in self.app.local_users:
                log.debug(f"Adding user {user_name}")
                # some propreties available that might be nice to save
                # name = user['name']
                local_user = self.app.add_local_user(user_name, identities=[user['email']])
                local_user.created_at = user['created_at']
                local_user.last_login_at = user['last_sign_in_at']
                local_user.set_property("gitlab_id", user['id'])
                local_user.set_property("is_licensed",  user['using_license_seat'])

                # GitLab use three states, active, blocked, deactivated
                local_user.set_property("state", user['state'])
                if user['state'] == "active":
                    local_user.is_active = True
                else:
                    local_user.is_active = False
            if not user['bot']:
                self.app.local_users[user_name].add_group(self.member_group_name)
                self.app.local_users[user_name].add_role(self.member_role_name, apply_to_application=True)
                if is_admin:
                    self.app.local_users[user_name].add_role(self.admin_role_name, apply_to_application=True)
            else:
                self.app.local_users[user_name].set_property("bot", True)


        return

    def discover_groups(self) -> None:
        """ discover GitLab groups, populates map of user permissions to avoid repeating calls to API """

        log.info("Starting discovery GitLab Groups")
        gitlab_groups = self.__gl_api_get("api/v4/groups")

        for group in gitlab_groups:
            group_name = group['name']
            group_id = group['id']
            self.group_parent_ids[group_id] = group['parent_id']
            log.info(f"Group - {group_name}")
            self.app.add_local_group(group_name)

            # get group membership
            group_members = self.__gl_api_get(f"/api/v4/groups/{group_id}/members")
            self.group_user_access_levels[group_id] = {}
            for member in group_members:
                user_name = member['username']
                if user_name not in self.app.local_users:
                    raise Exception(f"Unknown user {user_name}")
                self.app.local_users[user_name].add_group(group_name)
                self.group_user_access_levels[group_id][user_name] = self.__map_access_level(member['access_level'])

    def discover_projects(self) -> None:
        """ discover all Projects, currently works at a flat level """

        log.info("Starting discovery GitLab Projects")
        # define custom propreties for project
        self.app.property_definitions.define_resource_property("project", "gitlab_id", OAAPropertyType.NUMBER)
        self.app.property_definitions.define_resource_property("project", "visibility", OAAPropertyType.STRING)

        projects = self.__gl_api_get("api/v4/projects")

        for project in projects:
            # since we aren't currently tracking by group space use full path for project name
            project_name = project['name_with_namespace']
            project_id = project['id']
            description = project['description']
            log.info(f"Project - {project_name}")
            self.app.add_resource(project_name, "project", description=description)
            self.app.resources[project_name].set_property("gitlab_id", project_id)

            log.debug(f"{project['namespace']=}")
            if project["namespace"]["kind"] == "group":
                group_id = project["namespace"]["id"]
                self.assign_group_permissions(self.app.resources[project_name], group_id)
            else:
                # import pdb; pdb.set_trace()
                log.info(f"Non-group namespace {project['namespace']['kind']}")

            # get individual member permissions
            project_members = self.__gl_api_get(f"api/v4/projects/{project_id}/members")
            for member in project_members:
                user_name = member['username']
                access_role = self.__map_access_level(member['access_level'])
                log.debug(f"Assigning {user_name} {access_role} to {project_name}")
                self.app.local_users[user_name].add_role(access_role, [self.app.resources[project_name]])

            visibility = project["visibility"]
            self.app.resources[project_name].set_property("visibility", visibility)
            if visibility == "private":
                # private project, accessable only by group members and direct permissions, nothing to do
                log.debug(f"{project_name} is private repo, not additional permissions to add")
            elif visibility == "internal":
                # internal repo, any logged in user has
                log.debug(f"{project_name} is internal repo, adding '{self.member_group_name}' for group {self.member_group_name}")
                self.app.local_groups[self.member_group_name].add_role(self.member_role_name, [self.app.resources[project_name]])
            elif visibility == "public":
                # public repo add view for all internal users
                log.debug(f"{project_name} is public repo, adding '{self.member_group_name}' for group {self.member_group_name}")
                self.app.local_groups[self.member_group_name].add_role(self.member_role_name, [self.app.resources[project_name]])

    def assign_group_permissions(self, resource: CustomResource, group_id: int) -> None:
        """
        loops through all users in a group and assigns their respective permissions to the resource

        utilizes self.group_user_access_levels map populated during discover_groups to avoid API calls
        recuresively calls itself if group has parent ID in self.group_parent_ids
        """
        # group_name = project["namespace"]["name"]
        # apply group members to project based on their permissions

        # group_members = self.__gl_api_get(f"/api/v4/groups/{group_id}/members")
        for user_name, access_role in self.group_user_access_levels[group_id].items():
            log.debug(f"Assigning {user_name} {access_role} to {resource.name}")
            self.app.local_users[user_name].add_role(access_role, [resource])

        # group_details = self.__gl_api_get(f"/api/v4/groups/{group_id}")
        if self.group_parent_ids[group_id]:
            log.debug(f"Recursive call to assign parent group {self.group_parent_ids[group_id]}")
            self.assign_group_permissions(resource, self.group_parent_ids[group_id])

        return

    def __gl_api_get(self, path: str, params: dict = {}) -> dict:
        """ GitLab API GET

        Parameters:
        path (string): API path relative to gitlab_url
        params (dictionary): Optional HTTP parameters to include

        Returns:
        dictionary: API Response

        Raises:
        HTTPError
        """
        headers = {}
        headers['authorization'] = f"Bearer {self.access_token}"
        path = path.lstrip("/")
        if re.match(r"^https:\/\/", path):
            api_path = path
        else:
            api_path = f"{self.gitlab_url}/{path}"

        result = []
        while True:
            response = requests.get(api_path, headers=headers, params=params, timeout=10)
            if response.ok:
                if "X-Next-Page" in response.headers:
                    # multipage response
                    result.extend(response.json())
                    next_page = response.headers.get("X-Next-Page")
                    if not next_page:
                        # on the last page, break
                        break
                    else:
                        params["page"] = next_page
                else:
                    # single page response, return
                    try:
                        return response.json()
                    except json.decoder.JSONDecodeError:
                        raise HTTPError("Could not JSON decode API response", response=response)
            else:
                raise HTTPError(response.text, response=response)

        return result


def log_arg_error(arg: str = None, env: str = None) -> None:
    """ helper function to generate consistent log messages when required parameter cannot be loaded """

    if arg and env:
        log.error(f"Unable to load required parameter, must supply {arg} or set OS environment variable {env}")
    elif arg and not env:
        log.error(f"Unable to load required parameter, must supply {arg}")
    elif env:
        log.error(f"Unable to load required parameter, must set OS environment variable {env}")
    else:
        raise Exception("Must provide arg or env to include in error message")
    return


def run(gitlab_url: str, gitlab_access_token: str, veza_url: str, veza_user: str, veza_api_key: str, save_json: bool = False, verbose: bool = False) -> None:
    """ run full OAA process, discovery GitLab entities, perpare OAA template and push to Veza """
    # log.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=log.INFO)
    if verbose:
        log.setLevel(logging.DEBUG)
        log.debug("Enabling verbose logging")

    # Instantiate a OAA Client, do this early to validate connection before processing application
    try:
        veza_con = OAAClient(url=veza_url, api_key=veza_api_key)
    except OAAClientError as e:
        log.error(f"Unable to connect to Veza ({veza_url})")
        log.error(e.message)
        raise Exception(f"Unnable to connect to Veza ({veza_url})")
    gitlab_app = OAAGitLab(gitlab_url, gitlab_access_token)

    try:
        gitlab_app.discover()
    except HTTPError as e:
        log.error(f"Error during discovery: GitLab API returned error: {e.response.status_code} for {e.request.url}")
        log.error(e)
        raise Exception(f"Error during discovery: GitLab API returned error: {e.response.status_code} for {e.request.url}")

    # payload = gitlab_app.app.get_payload()
    # log.debug(json.dumps(payload, indent=2))

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
        veza_con.push_application(provider_name, data_source_name=gitlab_app.deployment_name, application_object=gitlab_app.app, save_json=save_json)
        log.info("Success")
    except OAAClientError as e:
        log.error(f"{e.error}: {e.message} ({e.status_code})")
        if hasattr(e, "details"):
            for d in e.details:
                log.error(d)


def main() -> None:
    """ process command line and OS environment variables to ensure everything is set, call `run` function """

    parser = argparse.ArgumentParser()
    parser.add_argument("--gitlab-url", default=os.getenv("GITLAB_URL"), help="GitLab URL to discover")
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
        log_arg_error("--gitlab-url", "GITLAB_URL")
    if not veza_url:
        log_arg_error("--veza-url", "VEZA_URL")
    if not veza_user:
        log_arg_error("--veza-user", "VEZA_USER")

    # security values can only be loaded through OS environment
    gitlab_access_token = os.getenv("GITLAB_ACCESS_TOKEN")
    if not gitlab_access_token:
        log_arg_error(env="GITLAB_ACCESS_TOKEN")

    veza_api_key = os.getenv("VEZA_API_KEY")
    if not veza_api_key:
        log_arg_error(env="VEZA_API_KEY")

    if None in [gitlab_url, gitlab_access_token, veza_url, veza_user, veza_api_key]:
        log.error("Missing one or more required parameters")
        sys.exit(1)

    run(gitlab_url, gitlab_access_token, veza_url, veza_user, veza_api_key, save_json=args.save_json, verbose=args.verbose)


if __name__ == '__main__':
    main()
