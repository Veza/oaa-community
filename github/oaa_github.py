#!env python3
"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

from datetime import datetime
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, CustomPermission, OAAPermission, OAAPropertyType, CustomResource
from oaaclient.utils import log_arg_error
from requests import HTTPError
from urllib.parse import urlparse
import argparse
import base64
import boto3
import botocore
import csv
import json
import jwt
import logging
import os
import re
import requests
import sys
import time

# base64 encoding of the GitHub Mark icon for uploading later
GITHUB_MARK_ICON = """
iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyRpVFh0WE1MOmNvbS5hZG9i
ZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6
bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuMy1jMDExIDY2LjE0NTY2MSwgMjAxMi8wMi8wNi0xNDo1NjoyNyAgICAgICAgIj4gPHJkZjpS
REYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIg
eG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1s
bnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9w
IENTNiAoTWFjaW50b3NoKSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDpFNTE3OEEyQTk5QTAxMUUyOUExNUJDMTA0NkE4OTA0RCIgeG1wTU06RG9jdW1l
bnRJRD0ieG1wLmRpZDpFNTE3OEEyQjk5QTAxMUUyOUExNUJDMTA0NkE4OTA0RCI+IDx4bXBNTTpEZXJpdmVkRnJvbSBzdFJlZjppbnN0YW5jZUlEPSJ4bXAu
aWlkOkU1MTc4QTI4OTlBMDExRTI5QTE1QkMxMDQ2QTg5MDREIiBzdFJlZjpkb2N1bWVudElEPSJ4bXAuZGlkOkU1MTc4QTI5OTlBMDExRTI5QTE1QkMxMDQ2
QTg5MDREIi8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiA8P3hwYWNrZXQgZW5kPSJyIj8+m4QGuQAAAyRJREFUeNrEl21o
jWEYx895TDPbMNlBK46IUiNmPvHBSUjaqc0H8pF5+aDUKPEBqU2NhRQpX5Rv5jWlDIWlMCv7MMSWsWwmb3tpXub4XXWdPHvc9/Gc41nu+nedc7/8r/99PffL
dYdDPsvkwsgkTBwsA/PADJCnzX2gHTwBt8Hl7p537/3whn04XoDZDcpBlk+9P8AFcAghzRkJwPF4zGGw0Y9QS0mAM2AnQj77FqCzrtcwB1Hk81SYojHK4DyG
uQ6mhIIrBWB9Xm7ug/6B/nZrBHBegrkFxoVGpnwBMSLR9EcEcC4qb8pP14BWcBcUgewMnF3T34VqhWMFkThLJAalwnENOAKiHpJq1FZgI2AT6HZtuxZwR9Gi
dSHtI30jOrbawxlVX78/AbNfhHlomEUJJI89O2MqeE79T8/nk8nMBm/dK576hZgmA3cp/R4l9/UeSxiHLVIlNm4nFfT0bxyuIj7LHRTKai+zdJobwMKzcZSJ
b0ePV5PKN+BqAAKE47UlMnERELMM3EdYP/yrd+XYb2mOiYBiQ8OQnoRBlXrl9JZix7D1pHTazu4MoyBcnYamqAjIMTR8G4FT8LuhLsexXYYjICBiqhQBvYb6
fLZIJCjPypVvaOoVAW2WcasCnL2Nq82xHJNSqlCeFcDshaPK0twkAhosjZL31QYw+1rlMpWGMArl23SBsZZO58F2tlJXmjOXS+s4WGvpMiBJT/I2PInZ6lIs
9/hBsNS1hS6BG0DSqmYEDRlCXQrmy50P1oDRKTSegmNbUsA0zDMwRhPJXeCE3vWLPQMvan6X8AgIa1vcR4AkGZkDR4ejJ1UHpsaVI0g2LInpOsNFUud1rhxS
V+fzC9Woz2EZkWQuja7/B+jUrgtIMpy9YCW4n4K41YfzRneW5E1KJTe4B2Zq1Q5EHEtj4U3AfEzR5SVY4l7QYQPJdN2as7RKBF0BPZqqH4VgMAMBL8Byxr7y
8zCZiDlnOcEKIPmUpgB5Z2ww5RdOiiRiNajUmWda5IG6WbhsyY2fx6m8gLcoJDJFkH219M3We1+cnda93pfycZpIJEL/s/wSYADmOAwAQgdpBAAAAABJRU5E
rkJggg==
"""

# logging handler
logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)

class GitHubGraphError(Exception):
    """Raise when GraphAPI returns errors

    GraphAPI can return HTTP 200 OK with errors in the message, exception wraps returned errors and saves query for debug

    Args:
        errors (list): list of errors from the API response
        query (dict): Query submitted that resulted in error
        message (str, optional): Message string for base exception, defaults to "Error encountered during Graph API call"
    """
    def __init__(self, errors: list, query: str, message: str = "Error encountered during Graph API call"):
        self.message = message
        self.errors = errors
        self.query = query
        super().__init__(self.message)


def gh_api_get(path, auth_token, github_url="https://api.github.com"):
    """ Github API GET

    Parameters:
    path (string): API path relative to github_url
    auth_token (string): Bearer token value
    pagination (bool): Expect result to be paginated, set True when endpoint accepts per_page & page parameters
    github_url (str): Optional path for Github endpoint, defaults to "https://api.github.com"

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
    retries = 0
    while True:
        try:
            response = requests.get(api_path, headers=headers, timeout=20)
        except requests.exceptions.RequestException as e:
            log.warning(f"Error making GitHub API call, {e}")
            if retries < 5:
                retries += 1
                log.warning(f"Retrying {retries} of 5")
                time.sleep(retries * 2)
                continue
            else:
                raise e

        retries = 0
        if "X-RateLimit-Remaining" in response.headers:
            limit_remaining = int(response.headers.get("X-RateLimit-Remaining"))
            if limit_remaining < 150 and limit_remaining % 50 == 0:
                log.warning(f"GitHub API X-RateLimit-Remaining: {limit_remaining}")
            if limit_remaining < 1:
                limit_reset = int(response.headers.get("x-ratelimit-reset"))
                resets_at = datetime.fromtimestamp(limit_reset).isoformat()
                raise HTTPError(f"GitHub API Rate limit exceeded, resets at {resets_at}", response=response)

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
    jwt_payload = {"iat": int(time.time() - 10), "exp": int(time.time() + 600), "iss": app_id}

    encoded_jwt = jwt.encode(jwt_payload, app_key, algorithm="RS256")
    installations = gh_api_get("/app/installations", encoded_jwt, github_url=github_url)

    org_id = None
    for i in installations:
        if i['account']['login'] == org:
            org_id = i['id']
            break

    if not org_id:
        raise Exception(f"Unable to find org in app installations, verify GitHub App is installed in org {org}")

    log.debug(f"retrieving GitHub access token for {org}({org_id})")
    auth_response = gh_api_post(f"/app/installations/{org_id}/access_tokens", auth_token=encoded_jwt, data=None, github_url=github_url)

    if 'token' in auth_response:
        return auth_response['token']
    else:
        raise HTTPError(auth_response.text, response=auth_response)


def gh_graph_run(query: str, auth_token: str, variables: dict = None, graph_url: str = "https://api.github.com/graphql") -> dict:
    """ Run a query against the GitHub GraphQL API

    Args:
        query (str): String of GraphQL query to run
        auth_token (str): GitHub bearer auth token
        variabls (dict, optional): Variables for submission with query
        graph_url (str, optional): GraphQL API endpoint. Defaults to "https://api.github.com/graphql".

    Raises:
        HTTPError: For non 200 response from API

    Returns:
        dict: GraphQL query response
    """

    headers = {}
    headers['authorization'] = f"Bearer {auth_token}"

    query_data = {"query": query}
    if variables:
        query_data['variables'] = variables

    response = requests.post(graph_url, headers=headers, json=query_data, timeout=60)
    if response.ok:
        response_json = response.json()
        if "errors" in response_json:
            # GraphAPI can return errors in a success, raise an exception with the error details

            # collapse the query into a single line for better logging
            query_data["query"] = re.sub(r"\s+", " ", query_data["query"])
            raise GitHubGraphError(errors=response_json["errors"], query=query_data)
        return response.json()
    else:
        raise HTTPError(response.text, response=response)


class OAAGitHub():
    ORG_MEMBERS_GROUP_NAME = "Org Members"
    ORG_MEMBERS_ROLE_NAME = "Org Member"
    ORG_OWNERS_ROLE_NAME = "Org Owner"

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
        self.app.property_definitions.define_local_user_property("emails", OAAPropertyType.STRING_LIST)
        self.app.property_definitions.define_local_user_property("profile_name", OAAPropertyType.STRING)

        self.app.property_definitions.define_resource_property("repository", "Private", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_resource_property("repository", "allow_forking", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_resource_property("repository", "visibility", OAAPropertyType.STRING)
        self.app.property_definitions.define_resource_property("repository", "default_branch", OAAPropertyType.STRING)
        self.app.property_definitions.define_resource_property("repository", "default_branch_protected", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_resource_property("repository", "is_fork", OAAPropertyType.BOOLEAN)


    def discover_org(self):
        """ Discover all the user and team information for an organization including the default repo permissions """
        log.info(f"Starting org discovery {self.org_name}")
        org_info = gh_api_get(f"orgs/{self.org_name}", self.access_token, github_url=self.github_url)

        if not org_info.get("default_repository_permission"):
            # default_repository_permission should be included in all responses but will be `null` if the calling user does not have sufficient permissions
            raise Exception(f"{self.org_name} - Unable to determine default repository permission, ensure Github App has Organization Administration read-only permission")

        # github API returns the literal string "none" when organization has no default permission, convert to None
        log.info(f"{self.org_name} default org permission {org_info['default_repository_permission']}")
        if org_info['default_repository_permission'] == "none":
            self.org_default_repo_permission = None
        else:
            self.org_default_repo_permission = org_info['default_repository_permission']

        self.app.add_local_group(self.ORG_MEMBERS_GROUP_NAME)

        self.discover_org_members()
        self.discover_org_teams()

        return

    def discover_org_members(self):
        """ Discovery the list of organization members and their organization role. Uses the GitHub GraphQL API """
        log.debug(f"Discovering org users and roles for {self.org_name}")
        query = """query($org_name:String!, $first:Int!, $after:String){
                    organization(login: $org_name) {
                        membersWithRole(first: $first,  after: $after) {
                            pageInfo {
                                endCursor
                                hasNextPage
                            }
                            totalCount
                            edges {
                                role
                                hasTwoFactorEnabled
                                node {
                                    createdAt
                                    email
                                    id
                                    login
                                    name
                                    updatedAt
                                    organizationVerifiedDomainEmails(login: $org_name)
                                }
                            }
                        }
                    }
                }
        """
        variables = {"org_name": self.org_name, "first": 100, "after": None}

        total_users = 0
        users_with_identity = 0
        while True:
            result = gh_graph_run(query,auth_token=self.access_token, variables=variables)
            for e in result["data"]["organization"]["membersWithRole"]["edges"]:
                total_users += 1
                login = e["node"]["login"]
                user = self.app.add_local_user(login)
                user.set_property("OutsideCollaborator", False)
                user.set_property("profile_name", e["node"]["name"])
                user.created_at = e["node"]["createdAt"]

                if e["node"]["organizationVerifiedDomainEmails"]:
                    users_with_identity += 1
                    user.add_identities(e["node"]["organizationVerifiedDomainEmails"])
                    user.set_property("Emails", e["node"]["organizationVerifiedDomainEmails"])

                if e["role"] == "MEMBER":
                    user.add_group(self.ORG_MEMBERS_GROUP_NAME)
                    user.add_role(self.ORG_MEMBERS_ROLE_NAME, apply_to_application=True)
                elif e["role"] == "ADMIN":
                    user.add_role(self.ORG_OWNERS_ROLE_NAME, apply_to_application=True)
                else:
                    log.warning(f"Unknown user organization role: {e['role']}")

            #pagination
            if result["data"]["organization"]["membersWithRole"]["pageInfo"]["hasNextPage"]:
                variables["after"] = result["data"]["organization"]["membersWithRole"]["pageInfo"]["endCursor"]
            else:
                break

        log.info(f"Discovered {total_users} users for organization {self.org_name}")
        log.debug(f"Identities found for {users_with_identity} of {total_users} users in org {self.org_name}")
        return

    def discover_org_teams(self):
        """Discovery the Organization teams and populate members"""

        log.debug(f"Discovering org teams and team members for {self.org_name}")

        # query one team at a time `teams(first: 1...` for it's members and child teams, create the OAA group for each team as its discovered
        # increments through all teams in GitHub's order
        query = """
                query ($org_name: String!, $first: Int, $team_after: String, $members_after: String, $children_after: String) {
                  organization(login: $org_name) {
                    teams(first: 1, after: $team_after) {
                      edges {
                        node {
                          name
                          id
                          slug
                          members(membership: IMMEDIATE, first: $first, after: $members_after) {
                            nodes {
                              id
                              name
                              login
                            }
                            pageInfo {
                              endCursor
                              hasNextPage
                            }
                          }
                          childTeams(immediateOnly: true, first: $first, after: $children_after) {
                            nodes {
                              name
                              slug
                              id
                            }
                            pageInfo {
                              endCursor
                              hasNextPage
                            }
                          }
                        }
                      }
                    pageInfo {
                        endCursor
                        hasNextPage
                        }
                    }
                  }
                }
                """
        variables = {"org_name": self.org_name, "first": 100, "team_after": None, "members_after": None, "children_after": None}

        team_after = None
        while True:
            variables["team_after"] = team_after
            result = gh_graph_run(query,auth_token=self.access_token, variables=variables)
            team = result["data"]["organization"]["teams"]["edges"][0]["node"]
            team_name = team["name"]
            team_slug = team["slug"]

            log.debug(f"Creating group and discovering memberships and child teams for {team_name} in {self.org_name}")
            if team_name not in self.app.local_groups:
                self.app.add_local_group(team_name)

            while True:
                # add members and children teams
                if not result["data"]["organization"]["teams"]["edges"]:
                    # no members for team, break
                    break
                elif len(result["data"]["organization"]["teams"]["edges"]) != 1:
                    # parent query should remained locked to only one team per response
                    raise Exception(f"GitHub query for team membership returned more than one team. team: {team['slug']}, org {self.org_name}")

                node = result["data"]["organization"]["teams"]["edges"][0]["node"]
                if node["name"] != team["name"]:
                    raise Exception(f"Received result for team membership data for wrong team, expected {team['name']}, recieved {node['name']}, org {self.org_name}")

                # assign child team groups to current team
                for child_team in node["childTeams"]["nodes"]:
                    # add the child team group as a member of the parent
                    if child_team["name"] not in self.app.local_groups:
                        self.app.add_local_group(child_team["name"])
                    self.app.local_groups[child_team["name"]].add_group(team["name"])

                variables["children_after"] = node["childTeams"]["pageInfo"]["endCursor"]

                # assign all members that are directly in the group
                for member in node["members"]["nodes"]:
                    member_login = member["login"]
                    self.app.local_users[member_login].add_group(team["name"])
                variables["members_after"] = node["members"]["pageInfo"]["endCursor"]

                if node["members"]["pageInfo"]["hasNextPage"] or node["childTeams"]["pageInfo"]["hasNextPage"]:
                    # more users or child teams to discover, re-run the query with updated cursors
                    result = gh_graph_run(query,auth_token=self.access_token, variables=variables)
                else:
                    # no more team members or child groups to discover
                    break

            # find next team or break
            if result["data"]["organization"]["teams"]["pageInfo"]["hasNextPage"]:
                team_after = result["data"]["organization"]["teams"]["pageInfo"]["endCursor"]
            else:
                # no more teams
                break

        return

    def discover_all_repos(self):
        """ get all the repositories for this org and call discover_repo for each """
        repos = gh_api_get(f"/orgs/{self.org_name}/repos", self.access_token, github_url=self.github_url)
        for repo in repos:
            self.discover_repo(repo)

    def discover_repo(self, repo):
        """ populate the OAA app with the access details for a given repo, takes in GitHub repo information dictionary"""

        # add the repository to the OAA model, will create a CustomResource for each repo
        repo_resource = self.app.add_resource(name=repo['name'], resource_type="repository")

        if repo['description'] and len(repo['description']) > 256:
            # OAA description max length is 256, GitHub's description could be longer, truncate
            repo_resource.description = repo['description'][:255]
        else:
            repo_resource.description = repo['description']

        # get the full name of the repository (oprg/repo) to make getting the repo details easier
        full_name = repo['full_name']
        log.info(f"Processing repository {full_name}")

        # set repository properties
        repo_resource.set_property("private", repo['private'])
        # visibility is separate from private, can be `public`, `private` or `internal`
        repo_resource.set_property("visibility", repo['visibility'])
        if "allow_forking" in repo:
            # allow_forking property might not be in all responses
            repo_resource.set_property("allow_forking", repo['allow_forking'])
        repo_resource.set_property("is_fork", repo['fork'])


        # test default branch for branch protections and set boolean result
        repo_resource.set_property("default_branch", repo['default_branch'])
        default_branch_protected = self.__is_branch_protected(full_name, repo['default_branch'])
        repo_resource.set_property("default_branch_protected", default_branch_protected)

        self.__get_repo_teams(full_name, repo_resource)
        self.__get_repo_collaborators(full_name, repo_resource)

        # add default role with org default permission
        if self.org_default_repo_permission is not None:
            self.app.local_groups[self.ORG_MEMBERS_GROUP_NAME].add_role(role=self.org_default_repo_permission, resources=[repo_resource])

        return

    def __get_repo_teams(self, full_name: str, repo_resource: CustomResource) -> None:
        """ Get teams assigned to a repository and add the team's role to the local_group

        Args:
            full_name (str): full name of the repo, e.g. org/repository
            repo_resource (CustomResource): OAA resource object for repository
        """

        # Grab team permissions
        teams = gh_api_get(f"/repos/{full_name}/teams", self.access_token, github_url=self.github_url)
        for team in teams:
            team_name = team['name']
            if team_name not in self.app.local_groups:
                # if team included in API response list that is not included in the Organization's teams stop extraction unless set otherwise
                if os.getenv("GITHUB_IGNORE_UNKNOWN_TEAMS") is not None:
                    log.warning(f"repo {full_name} unknown team assigned to repository, ignoring: {team_name} role {team_role}")
                    continue
                else:
                    log.error("Raising exception for unknown team assigned to repository, set GITHUB_IGNORE_UNKNOWN_TEAMS environment variable to disable exception")
                    raise Exception(f"repo {full_name} unknown team assigned to repository: {team_name} role {team_role}")

            team_role = self.__map_permission(team['permission'])

            if team_role.lower() in self._defined_roles:
                log.debug(f"repo {full_name} adding team {team_name}, role {team_role}")
                self.app.local_groups[team_name].add_role(role=team_role, resources=[repo_resource])
            else:
                log.warning(f"Unknown role for team {team_name}, role: {team_role}")

        return

    def __get_repo_collaborators(self, full_name: str, repo_resource: CustomResource) -> None:
        """ Get all repository collaborators (user's assigned directly to the repository) and assign the users the correct role on the repository resource

        Args:
            full_name (str): full name of the repo, e.g. org/repository
            repo_resource (CustomResource): OAA resource object for repository
        """

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
            user_role = self.__determine_user_role(c['permissions'])
            if user_role:
                log.debug(f"repo {full_name} adding {user_login}, role {user_role}")
                self.app.local_users[user_login].add_role(role=user_role, resources=[repo_resource])
            else:
                log.error(f"repo {full_name} - {user_login} - unable to determine highest permission from {c['permissions']}")

        return

    def __determine_user_role(self, permission_list):
        """ returns the highest permission that is True from the list of Github repo permissions
        the Github API returns True for all levels below the assigned level, to simplify reporting
        only save the highest level """

        ordered_permissions = ["admin", "maintain", "push", "triage", "pull"]
        for permission in ordered_permissions:
            if permission_list.get(permission, False):
                return self.__map_permission(permission)

        return None

    def __map_permission(self, permission: str) -> str:
        """Converts API notation for roles to user facing role names

        Args:
            permission (str): permission as returned from the API

        Returns:
            str: name of user facing role
        """

        # compare by lowercase to reduce chance of issues
        if permission.lower() == "pull":
            return "read"
        elif permission.lower() == "push":
            return "write"
        else:
            return permission

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
        self.app.add_local_role(self.ORG_OWNERS_ROLE_NAME, ["Admin"])

        # Repo Roles
        self.app.add_local_role("Read", ["Pull", "Fork"])
        self.app.add_local_role("Triage", ["Pull", "Fork"])
        self.app.add_local_role("Write", ["Pull", "Fork", "Push", "Merge"])
        self.app.add_local_role("Maintain", ["Pull", "Fork", "Push", "Merge"])
        self.app.add_local_role("Admin", ["Pull", "Fork", "Push", "Merge", "Manage Access"])

        self._defined_roles = [r.lower() for r in self.app.local_roles]


def load_user_map(oaa_app, user_map):
    """
    OAA can support mapping local users to IdP identities but GitHub API does not provide user emails for mapping
    if caller provides CSV file of GitHub logins to emails loop through and add as many as we can
    csv format should be two columns "github username,email"
    if user_map path begins with s3:// connect to the S3 bucket and stream the object
    """
    log.info(f"Loading User map {user_map}")
    user_map_url = urlparse(user_map)
    if user_map_url.scheme == "s3":
        # s3 object
        try:
            log.info("Connecting to S3")
            bucket_name = user_map_url.netloc
            object_path = user_map_url.path.lstrip("/")
            log.info(f"Loading User map from S3 bucket \"{bucket_name}\", object \"{object_path}\"")
            s3 = boto3.resource("s3")
            bucket = s3.Bucket(bucket_name)
            obj = bucket.Object(key=object_path)
            response = obj.get()
            lines = response['Body'].read().decode('utf-8').splitlines(True)
            for line in csv.reader(lines):
                login = line[0].strip()
                identity = line[1].strip()
                if login in oaa_app.app.local_users:
                    log.info(f"setting {login} -> {identity}")
                    oaa_app.app.local_users[login].add_identity(identity)
        except botocore.exceptions.ClientError as e:
            log.error(e.response['Error'])
            exit(1)
    else:
        # local file
        try:
            with open(user_map) as f:
                for line in csv.reader(f):
                    login = line[0].strip()
                    identity = line[1].strip()
                    if login in oaa_app.app.local_users:
                        log.info(f"setting {login} -> {identity}")
                        oaa_app.app.local_users[login].add_identity(identity)
        except FileNotFoundError:
            log.error(f"Unable to locate file {user_map}, exiting")
            exit(1)
        except IOError as e:
            log.error(f"Error while reading usermap file {user_map}")
            log.error(e)
            exit(1)


def run(org_name, app_id, veza_url, oaa_user, veza_api_key, key_file=None, base64_key=None, user_map=None, save_json=False):

    if os.getenv("OAA_DEBUG"):
        log.setLevel(logging.DEBUG)

    # Instantiate a OAA Client, do this early to validate connection before processing application
    try:
        veza_con = OAAClient(url=veza_url, api_key=veza_api_key)
    except OAAClientError as e:
        log.error(f"Unnable to connect to Veza ({veza_url})")
        log.error(e.message)
        exit(1)

    # use Github App API to retrieve authentication token for organization
    org_token = gh_get_org_auth(app_id, org_name, key_file=key_file, base64_key=base64_key)
    if org_token:
        log.info(f"Retrieved token for orgination {org_name}, starting discovery")

    # instantiate an instance of the OAAGitHub class, this class represents an Org and creates an OAA app
    oaa_app = OAAGitHub(org_name, org_token)

    try:
        oaa_app.discover_org()
    except HTTPError as e:
        log.error(f"Error discoverying organization: GitHub API returned error: {e.response.status_code} for {e.request.url}")
        log.error(e)
        log.error("Exiting")
        sys.exit(1)
    except GitHubGraphError as e:
        log.error(f"GitHub GraphAPI error discovering organization {org_name}")
        for error in e.errors:
            log.error(error)
        log.debug(f"Errored query: {e.query}")
        log.error("Exiting")
        sys.exit(1)

    # populate all repositories
    try:
        oaa_app.discover_all_repos()
    except HTTPError as e:
        log.error(f"Error discoverying repositories: GitHub API returned error: {e.response.status_code} for {e.request.url}")
        log.error(e)
        log.error("Exiting")
        sys.exit(1)

    # process user_map file if provided
    if user_map:
        load_user_map(oaa_app, user_map)

    # Push to Veza
    # Define the provider and create if necessary
    log.info("Starting push")
    provider_name = "Github"
    provider = veza_con.get_provider(provider_name)
    if provider:
        log.info("Found existing provider")
    else:
        log.info(f"Creating Provider {provider_name}")
        provider = veza_con.create_provider(provider_name, "application")
    log.info(f"Provider: {provider['name']} ({provider['id']})")

    veza_con.update_provider_icon(provider['id'], GITHUB_MARK_ICON)
    # push data
    try:
        response = veza_con.push_application(provider['name'], data_source_name=f"github-{org_name}", application_object=oaa_app.app, save_json=save_json)
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
        sys.exit(1)


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
        log_arg_error(log, "--org", "GITHUB_ORG")
    if not app_id:
        log_arg_error(log, "--app_id", "GITHUB_APP_ID")
    if not veza_url:
        log_arg_error(log, "--veza-url", "VEZA_URL")
    if not veza_api_key:
        log_arg_error(log, env="VEZA_API_KEY")

    if None in [org_name, app_id, veza_url, veza_api_key, save_json]:
        log.error("Missing one or more required parameters")
        sys.exit(1)

    if not key_file and not base64_key:
        log.error("GitHub API not provided via --key-file or one of OS environment GITHUB_KEY or GITHUB_KEY_BASE64")
        sys.exit(1)

    run(org_name, app_id, veza_url, oaa_user, veza_api_key, key_file=key_file, base64_key=base64_key, user_map=user_map, save_json=save_json)


if __name__ == '__main__':
    # replace the log with the root logger if running as main
    log = logging.getLogger()
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)

    main()
