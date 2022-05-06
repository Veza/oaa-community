#!env python3
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, CustomPermission, OAAPermission, OAAPropertyType
from pprint import pprint
from requests import HTTPError
from time import time
from urllib.parse import urlparse
import argparse
import base64
import boto3
import botocore
import csv
import jwt
import os
import re
import requests
import sys


def gh_api_get(path, auth_token, github_url="https://api.github.com"):
    """ Github API GET

    Parameters:
    path (string): API path relative to github_url
    auth_token (string): Bearer token value
    pagination (bool): Expect result to be paginated, set True when endpoint accepts per_page & page parameters
    github_url (str): Optional path for Github endpoing, defaults to "https://api.github.com"

    Returns:
    dictionary: API Response

    """
    headers = {}
    headers['authorization'] = f"Bearer {auth_token}"
    headers['accept'] = "application/vnd.github.v3+json"
    path = path.lstrip("/")
    if re.match(r"^https:\/\/", path):
        api_path = path
    else:
        api_path = f"{github_url}/{path}"

    result = []
    while True:
        response = requests.get(api_path, headers=headers, timeout=10)

        # if "X-RateLimit-Remaining" in response.headers:
        #     pass
        #     limit_remaining = response.headers.get("X-RateLimit-Remaining")
        #     print(f"Rate limit remaining: {limit_remaining}")

        if response.ok:
            if response.links and "next" in response.links:
                # paginated response
                api_path = response.links['next']['url']
                result.extend(response.json())
                continue
            elif response.links:
                # last
                result.extend(response.json())
                break
            else:
                # single page response, return
                return response.json()
        else:
            raise HTTPError(response.text, response=response)

    return result


def gh_api_post(path, auth_token, data=None, github_url="https://api.github.com"):
    """ Github API POST

    Parameters:
    path (string): API path relative to github_url
    auth_token (string): Bearer token value
    data (dictionary): Data to include in body of POST
    github_url (str): Optional path for Github endpoing, defaults to "https://api.github.com"

    Returns:
    dictionary: API Response

    """

    headers = {}
    headers['authorization'] = f"Bearer {auth_token}"
    headers['accept'] = "application/vnd.github.v3+json"
    path = path.lstrip("/")
    response = requests.post(f"{github_url}/{path}", headers=headers, json=data, timeout=10)

    if response.ok:
        return response.json()
    else:
        raise HTTPError(response.text, response=response)


def gh_get_org_auth(app_id, org, key_file=None, base64_key=None, github_url="https://api.github.com"):
    """ use GitHub App authentication to retreive a token for the specific org

    app_id: {int} numeric app ID for GitHub App
    key_file: {string} path to PEM key file for GitHub App
    base64_key: {string} base64 encoding of key for GitHub App
    org: {string} org name (slug) to return authentication for
    github_url (str): Optional path for GitHub endpoing, defaults to "https://api.github.com"

    returns: {string} authentication token
    """

    if not key_file and not base64_key:
        raise Exception("Must provide GitHub key via key_file or base64_key")

    app_key = None
    if key_file and os.path.isfile(key_file):
        with open(key_file) as f:
            app_key = f.read()
    elif key_file and not os.path.isfile(key_file):
        raise Exception(f"Unable to locate key_file {key_file}")
    elif base64_key:
        app_key = base64.b64decode(base64_key)
    else:
        raise Exception("key_file cannot be none")

    # build Github jwt authentication payload, valid from 10 seconds ago to 10 minutes from now
    jwt_payload = {"iat": int(time() - 10), "exp": int(time() + 600), "iss": app_id}

    encoded_jwt = jwt.encode(jwt_payload, app_key, algorithm="RS256")
    installations = gh_api_get("/app/installations", encoded_jwt, github_url=github_url)

    org_id = None
    for i in installations:
        if i['account']['login'] == org:
            org_id = i['id']
            break

    # print(f"Debug: Found {org}: {org_id}")
    if not org_id:
        raise Exception(f"Unable to find org {org} in app installations")

    auth_response = gh_api_post(f"/app/installations/{org_id}/access_tokens", auth_token=encoded_jwt, data=None, github_url=github_url)

    if 'token' in auth_response:
        return auth_response['token']
    else:
        raise HTTPError(auth_response.text, response=auth_response)


class OAAGitHub():
    ORG_MEMBERS_GROUP_NAME = "Org Members"
    ORG_MEMBERS_ROLE_NAME = "Org Member"
    ORG_ADMINS_ROLE_NAME = "Org Admin"

    def __init__(self, org_name, access_token, github_url="https://api.github.com"):
        self.app = CustomApplication(f"Github - {org_name}", "Github")
        self.org_name = org_name
        self.access_token = access_token
        self.org_default_repo_permission = None
        self.github_url = github_url

        self.__define_github_permissions()
        self.__define_github_roles()

        # configure custom properties
        self.app.property_definitions.define_local_user_property("OutsideCollaborator", OAAPropertyType.BOOLEAN)

        self.app.property_definitions.define_resource_property("repository", "Private", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_resource_property("repository", "allow_forking", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_resource_property("repository", "visibility", OAAPropertyType.STRING)
        self.app.property_definitions.define_resource_property("repository", "default_branch", OAAPropertyType.STRING)
        self.app.property_definitions.define_resource_property("repository", "default_branch_protected", OAAPropertyType.BOOLEAN)

        # run discovery
        self.discover_org()

    def discover_org(self):
        """ Discover all the user and team information for an organization including the default repo permissions """
        org_info = gh_api_get(f"orgs/{self.org_name}", self.access_token, github_url=self.github_url)
        if "default_repository_permission" not in org_info:
            raise Exception("Unable to determine default repository permission, ensure Github App has Organization Administration read-only permission")

        # github API returns the literal string "none" when organization has no default permission, convert to None
        if org_info['default_repository_permission'] == "read":
            self.org_default_repo_permission = "Pull"
        elif org_info['default_repository_permission'] == "write":
            self.org_default_repo_permission = "Push"
        elif org_info['default_repository_permission'] == "none":
            self.org_default_repo_permission = None
        else:
            self.org_default_repo_permission = org_info['default_repository_permission']

        # build list of org members
        self.app.add_local_group(self.ORG_MEMBERS_GROUP_NAME)
        members = gh_api_get(f"orgs/{self.org_name}/members?role=member", self.access_token, github_url=self.github_url)
        for member in members:
            login = member['login']
            if login not in self.app.local_users:
                self.app.add_local_user(login)
            self.app.local_users[login].set_property("OutsideCollaborator", False)
            self.app.local_users[login].add_group(self.ORG_MEMBERS_GROUP_NAME)
            self.app.local_users[login].add_role(self.ORG_MEMBERS_ROLE_NAME, apply_to_application=True)

        # build list of organization admins
        org_admins = gh_api_get(f"orgs/{self.org_name}/members?role=admin", self.access_token, github_url=self.github_url)
        for admin in org_admins:
            login = admin['login']
            if login not in self.app.local_users:
                self.app.add_local_user(login)
            self.app.local_users[login].set_property("OutsideCollaborator", False)
            self.app.local_users[login].add_role(self.ORG_ADMINS_ROLE_NAME, apply_to_application=True)

        # build up teams
        teams = gh_api_get(f"orgs/{self.org_name}/teams", self.access_token, github_url=self.github_url)
        for team in teams:
            team_name = team['name']
            print(f"Populating team {team_name}")
            self.app.add_local_group(team_name)
            # team member API call uses org id number, easier to just grab the base url from the response
            team_members = gh_api_get(f"{team['url']}/members", self.access_token, github_url=self.github_url)
            for member in team_members:
                user_login = member['login']
                if user_login not in self.app.local_users:
                    self.app.add_local_user(user_login)
                self.app.local_users[user_login].add_group(team_name)

    def discover_all_repos(self):
        """ get all the repositories for this org and call discover_repo for each """
        repos = gh_api_get(f"/orgs/{self.org_name}/repos", self.access_token, github_url=self.github_url)
        for repo in repos:
            self.discover_repo(repo)

    def discover_repo(self, repo):
        """ populate the OAA app with the access details for a given repo, takes in GitHub repo information dictionary"""

        # add the repository to the OAA model, will create a CustomResource for each repo
        self.app.add_resource(name=repo['name'], resource_type="repository")

        if repo['description'] and len(repo['description']) > 256:
            # OAA description max length is 256, GitHub's description could be longer, truncate
            self.app.resources[repo['name']].description = repo['description'][:255]
        else:
            self.app.resources[repo['name']].description = repo['description']

        # get the full name of the repository (oprg/repo) to make getting the repo details easier
        full_name = repo['full_name']
        print(f"Processing {full_name}")

        # set repository properties
        if repo['private']:
            print(" -- Marking repo private")
        self.app.resources[repo['name']].set_property("private", repo['private'])
        # visibility is separate from private, can be `public`, `private` or `internal`
        self.app.resources[repo['name']].set_property("visibility", repo['visibility'])
        self.app.resources[repo['name']].set_property("allow_forking", repo['allow_forking'])

        # test default branch for branch protections and set boolean result
        self.app.resources[repo['name']].set_property("default_branch", repo['default_branch'])
        default_branch_protected = self.__is_branch_protected(full_name, repo['default_branch'])
        self.app.resources[repo['name']].set_property("default_branch_protected", default_branch_protected)

        # Grab team permissions
        teams = gh_api_get(f"/repos/{full_name}/teams", self.access_token, github_url=self.github_url)
        for team in teams:
            self.app.local_groups[team['name']].add_role(role=team['permission'].capitalize(), resources=[self.app.resources[repo['name']]])

        # loop through each collaborator on the reposotory and save their permission level
        # ?affiliation=direct will show users with direct permissions on repo vs inherited from team or default
        collaborators = gh_api_get(f"/repos/{full_name}/collaborators?affiliation=direct", self.access_token, github_url=self.github_url)
        for c in collaborators:
            user_login = c['login']
            if user_login not in self.app.local_users:
                # since all org members were added first, any new user is an outside collaborator
                self.app.add_local_user(user_login)
                self.app.local_users[user_login].set_property("OutsideCollaborator", True)
            # for each collaborator add the most privilaged level
            highest_permission = self.__return_highest_permission(c['permissions'])
            if highest_permission:
                print(f" - {user_login} - {highest_permission}")
                self.app.local_users[user_login].add_role(role=highest_permission, resources=[self.app.resources[repo['name']]])
            else:
                print(f" - {user_login} - unable to determine highest permission from {c['permissions']}")
        #
        # add org admin role to repo
        # self.app.add_access(identity="admin", identity_type=OAAIdentityType.LocalRole, permission="admin", resource=repo['name'])

        # add default role with org default permission
        if self.org_default_repo_permission is not None:
            self.app.local_groups[self.ORG_MEMBERS_GROUP_NAME].add_role(role=self.org_default_repo_permission, resources=[self.app.resources[repo['name']]])

    def __return_highest_permission(self, permission_list):
        """ returns the highest permission that is True from the list of Github repo permissions
        the Github API returns True for all levels below the assigned level, to simplify reporting
        only save the highest level """

        ordered_permissions = ["admin", "maintain", "push", "triage", "pull"]
        for level in ordered_permissions:
            if permission_list.get(level, False):
                return level.capitalize()

        # none of them where true, not sure how this would happen
        return None

    def __is_branch_protected(self, repo_path, branch_name):
        """ pull branch protection information and return true if any branch protections are enabled """
        protected = False
        try:
            gh_api_get(f"repos/{repo_path}/branches/{branch_name}/protection", self.access_token, github_url=self.github_url)
            # if API returned succesfully than there are branch protections configured
            protected = True
        except HTTPError as e:
            # api will return 404 if no branch protections configured, ensure that its the expected error
            # if not expected 404 error raise the error since something else went wrong
            if e.response.status_code == 404:
                details = e.response.json()
                if "message" in details and details["message"] == "Branch not protected":
                    protected = False
                    pass
            elif e.response.status_code == 403:
                # branch protections not available on free plans, will return 403 if you try to get them
                # Error message returned: Upgrade to GitHub Pro or make this repository public to enable this feature
                details = e.response.json()
                if "message" in details and "Upgrade" in details["message"]:
                    protected = False
                    pass
            else:
                raise e

        return protected

    def __define_github_permissions(self):
        """ ad github expected permissions to the custom application
        https://docs.github.com/en/organizations/managing-access-to-your-organizations-repositories/repository-permission-levels-for-an-organization
        """
        github_permissions = {
            "View": [OAAPermission.MetadataRead],
            "Manage Access": [OAAPermission.MetadataWrite],
            "Pull": [OAAPermission.DataRead],
            "Fork": [OAAPermission.DataRead],
            "Merge": [OAAPermission.DataWrite],
            "Push": [OAAPermission.DataWrite],
            "Maintain": [OAAPermission.DataWrite]
        }

        for p in github_permissions:
            self.app.define_custom_permission(CustomPermission(p, github_permissions[p]))

        self.app.define_custom_permission(CustomPermission("Admin", [OAAPermission.DataWrite, OAAPermission.MetadataWrite], apply_to_sub_resources=True))

    def __define_github_roles(self):
        # Org Roles
        self.app.add_local_role(self.ORG_MEMBERS_ROLE_NAME, ["View"])
        self.app.add_local_role(self.ORG_ADMINS_ROLE_NAME, ["Admin"])

        # Repo Roles
        self.app.add_local_role("Pull", ["Pull", "Fork"])
        self.app.add_local_role("Triage", ["Pull", "Fork"])
        self.app.add_local_role("Push", ["Pull", "Fork", "Push", "Merge"])
        self.app.add_local_role("Maintain", ["Pull", "Fork", "Push", "Merge"])
        self.app.add_local_role("Admin", ["Pull", "Fork", "Push", "Merge", "Manage Access"])


def load_user_map(oaa_app, user_map):
    """
    OAA can support mapping local users to IdP identities but GitHub API does not provide user emails for mapping
    if caller provides CSV file of GitHub logins to emails loop through and add as many as we can
    csv format should be two columns "github username,email"
    if user_map path begins with s3:// connect to the S3 bucket and stream the object
    """
    print(f"Loading User map {user_map}")
    user_map_url = urlparse(user_map)
    if user_map_url.scheme == "s3":
        # s3 object
        try:
            print("Connecting to S3")
            bucket_name = user_map_url.netloc
            object_path = user_map_url.path.lstrip("/")
            print(f"Loading User map from S3 bucket \"{bucket_name}\", object \"{object_path}\"")
            s3 = boto3.resource("s3")
            bucket = s3.Bucket(bucket_name)
            obj = bucket.Object(key=object_path)
            response = obj.get()
            lines = response['Body'].read().decode('utf-8').splitlines(True)
            for line in csv.reader(lines):
                login = line[0].strip()
                identity = line[1].strip()
                if login in oaa_app.app.local_users:
                    print(f" -- {login} -> {identity}")
                    oaa_app.app.local_users[login].add_identity(identity)
        except botocore.exceptions.ClientError as e:
            print(e.response['Error'], file=sys.stderr)
            exit(1)
    else:
        # local file
        try:
            with open(user_map) as f:
                for line in csv.reader(f):
                    login = line[0].strip()
                    identity = line[1].strip()
                    if login in oaa_app.app.local_users:
                        print(f" -- {login} -> {identity}")
                        oaa_app.app.local_users[login].add_identity(identity)
        except FileNotFoundError:
            print(f"Unable to locate file {user_map}, exiting", file=sys.stderr)
            exit(1)
        except IOError as e:
            print(f"Error while reading usermap file {user_map}", file=sys.stderr)
            print(e, file=sys.stderr)
            exit(1)


def run(org_name, app_id, veza_url, oaa_user, veza_api_key, key_file=None, base64_key=None, user_map=None, save_json=False):
    # Instantiate a OAA Client, do this early to validate connection before processing application
    try:
        veza_con = OAAClient(url=veza_url, api_key=veza_api_key)
    except OAAClientError as e:
        print(f"Unnable to connect to Veza ({veza_url})", file=sys.stderr)
        print(e.message, file=sys.stderr)
        exit(1)

    # use Github App API to retrieve authentication token for organization
    org_token = gh_get_org_auth(app_id, org_name, key_file=key_file, base64_key=base64_key)
    if org_token:
        print(f"Retrieved token for orgination {org_name}, starting discovery")

    # instantiate an instance of the OAAGitHub class, this class represents an Org and creates an OAA app
    oaa_app = OAAGitHub(org_name, org_token)
    # populate all repositories
    try:
        oaa_app.discover_all_repos()
    except HTTPError as e:
        print(f"Error discoverying repositories: GitHub API returned error: {e.response.status_code} for {e.request.url}")
        print(e)
        print("Exiting")
        sys.exit(1)

    # process user_map file if provided
    if user_map:
        load_user_map(oaa_app, user_map)

    # Push to Veza
    # Define the provider and create if necessary
    provider_name = "Github"
    provider = veza_con.get_provider(provider_name)
    if provider:
        print("-- Found existing provider")
    else:
        print(f"++ Creating Provider {provider_name}")
        provider = veza_con.create_provider(provider_name, "application")
    print(f"-- Provider: {provider['name']} ({provider['id']})")

    # push data
    try:
        response = veza_con.push_application(provider_name, data_source_name=f"github-{org_name}", application_object=oaa_app.app, save_json=save_json)
        if response.get("warnings", None):
            print("-- Push succeeded with warnings:")
            for e in response["warnings"]:
                print(f"  - {e}")
    except OAAClientError as e:
        print(f"-- Error: {e.error}: {e.message} ({e.status_code})", file=sys.stderr)
        if hasattr(e, "details"):
            for d in e.details:
                pprint(f"  -- {d}")


def log_arg_error(arg=None, env=None):
    if arg and env:
        print(f"Unable to load required paramter, must supply {arg} or set OS environment variable {env}", file=sys.stderr)
    elif arg and not env:
        print(f"Unable to load required paramter, must supply {arg}", file=sys.stderr)
    elif env:
        print(f"Unable to load required paramter, must set OS environment variable {env}", file=sys.stderr)
    else:
        raise Exception("Must provide arg or env to include in error message")
    return


###########################################################
# Main
###########################################################
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--org", required=False, default=os.getenv("GITHUB_ORG"), help="Github Org slug to parse.")
    parser.add_argument("--app-id", type=int, required=False, default=os.getenv("GITHUB_APP_ID"), help="Github App ID")
    parser.add_argument("--key-file", required=False, default=os.getenv("GITHUB_KEY"), help="PEM keyfile for Github App authentication")
    parser.add_argument("--user-map", type=str, required=False, default=os.getenv("GITHUB_USER_MAP"), help="optional csv user map for GitHub user names to email identites")
    parser.add_argument("--veza-url", required=False, default=os.getenv("VEZA_URL"), help="Hostname for Veza deployment")
    parser.add_argument("--oaa-user", required=False, default=os.getenv("OAA_USER"), help="Veza username for OAA connection")
    parser.add_argument("--save-json", action="store_true", help="Save OAA JSON payload to file")
    args = parser.parse_args()

    org_name = args.org
    app_id = args.app_id
    key_file = args.key_file
    veza_url = args.veza_url
    oaa_user = args.oaa_user
    save_json = args.save_json
    user_map = args.user_map

    # security tokens can only come from OS environment
    base64_key = os.getenv("GITHUB_KEY_BASE64")
    veza_api_key = os.getenv('VEZA_API_KEY')

    if not org_name:
        log_arg_error("--org", "GITHUB_ORG")
    if not app_id:
        log_arg_error("--app_id", "GITHUB_APP_ID")
    if not veza_url:
        log_arg_error("--veza-url", "VEZA_URL")
    if not oaa_user:
        log_arg_error("--oaa-user", "OAA_USER")
    if not veza_api_key:
        log_arg_error(env="VEZA_API_KEY")

    if None in [org_name, app_id, veza_url, oaa_user, veza_api_key, save_json]:
        print("Missing one or more required parameters", file=sys.stderr)
        sys.exit(1)

    if not key_file and not base64_key:
        print("GitHub API not provided via --key-file or one of OS environment GITHUB_KEY or GITHUB_KEY_BASE64")
        sys.exit(1)

    run(org_name, app_id, veza_url, oaa_user, veza_api_key, key_file=key_file, base64_key=base64_key, user_map=user_map, save_json=save_json)


if __name__ == '__main__':
    main()
