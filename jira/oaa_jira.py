#!env python3
"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, OAAPermission, OAAPropertyType
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError
from urllib.parse import urlparse
import argparse
import json
import logging
import os
import re
import requests
import sys

logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)

# dictionary that will track permissions to roles since they come from two very different API calls, in the future OAA will handle this
jira_role_permissions = {}

def push_to_veza(veza_con, oaa_app, save_json=False):
  """ push data to Veza """

  # define the provider and create if necessary
  provider_name = "Jira"
  provider = veza_con.get_provider(provider_name)

  if provider:
    log.info("Found existing provider")
  else:
    log.info(f"creating Provider {provider_name}")
    provider = veza_con.create_provider(provider_name, "application")
    log.info(f"Provider: {provider['name']} ({provider['id']})")

  # push the data
  try:
    log.info(f"Pushing app {oaa_app.name}")
    veza_con.push_application(
      provider_name, data_source_name=f"jira-veza", application_object=oaa_app, save_json=save_json)
    log.info(f"Push complete")
  except OAAClientError as e:
    log.error(f"{e.error}: {e.message} ({e.status_code})")
    if hasattr(e, "details"):
      for d in e.details:
        log.error(json.dumps(d, indent=2))

  return

class JiraAPI():
  # build a connection to Jira Cloud
  def __init__(self, url, username, token):
    url = url.rstrip("/")
    if re.match(r"^https:\/\/.*", url):
      self.base_url = f"{url}/rest/api/3"
    else:
      self.base_url = f"https://{url}/rest/api/3"

    self.jira_instance = urlparse(self.base_url).netloc
    self.username = username
    self.token = token

  # execute an `HTTP GET` request against a path
  def api_get(self, path, parameters={}):
    """ make a standard API GET request """
    path = path.lstrip("/")
    if re.match(r"^https:\/\/", path):
      api_path = path
    else:
      api_path = f"{self.base_url}/{path}"

    result = []
    while True:
      response = requests.get(api_path, auth=HTTPBasicAuth(
        self.username, self.token), params=parameters)

      if not response.ok:
        raise HTTPError(response=response)
      body = response.json()
      if "isLast" in body and "values" in body:
        # handle paginated response
        result.extend(body['values'])
        if body['isLast']:
          break
        else:
          parameters["startAt"] = body['startAt'] + body['maxResults']
      else:
        # handle single page response
        result = response.json()
        break

    return result

  def get_all_users(self):
    """ API for getting all users requires special pagination handling """
    users = []
    page = 1
    start_at = 0
    max_results = 50

    # loop and request until an empty result is returned (manually paginate)
    while True:
      result = self.api_get(
        "users/search", parameters={"startAt": start_at, "maxResults": max_results})
      if result == []:
        break
      users.extend(result)
      start_at = page * max_results
      page += 1

    return users


def load_permissions(jira_con, oaa_app):
  response = jira_con.api_get("/permissions")
  permissions = response['permissions']

  # output discovered permissions to console
  # pprint(permissions)

  # define a base permission for "jira-software-users"
  oaa_app.add_custom_permission("view",
    [
      OAAPermission.DataRead,
      OAAPermission.DataWrite,
      OAAPermission.MetadataRead,
      OAAPermission.MetadataWrite
    ],
    apply_to_sub_resources=False
  )

  for permission in permissions:
    perm_list = parse_permissions(permission)
    if not permission in oaa_app.custom_permissions:
      oaa_app.add_custom_permission(permission, perm_list)

  # jira defaults to assigning logged in users permissions, assign the `jira-software-users`
  # role the default permissions. The users will only receive the permissions on projects
  # that are not market private
  oaa_app.add_local_role("jira-software-users", ["VIEW_ISSUES",
                                                 "VIEW_PROJECTS",
                                                 "ASSIGN_ISSUES",
                                                 "WORK_ON_ISSUES",
                                                 "EDIT_OWN_WORKLOGS",
                                                 "DELETE_OWN_WORKLOGS",
                                                 "DELETE_OWN_ATTACHMENTS",
                                                 "CREATE_ATTACHMENTS",
                                                 "EDIT_OWN_COMMENTS",
                                                 "DELETE_OWN_COMMENTS",
                                                 "ADD_COMMENTS",
                                                 "VIEW_VOTERS_AND_WATCHERS",
                                                 "TRANSITION_ISSUES",
                                                 "SET_ISSUE_SECURITY",
                                                 "SCHEDULE_ISSUES",
                                                 "RESOLVE_ISSUES",
                                                 "MOVE_ISSUES",
                                                 "LINK_ISSUES",
                                                 "EDIT_ISSUES",
                                                 "CREATE_ISSUES",
                                                 "CLOSE_ISSUES",
                                                 "ASSIGNABLE_USER",
                                                 "VIEW_READONLY_WORKFLOW",
                                                 "VIEW_DEV_TOOLS",
                                                 "MANAGE_SPRINTS_PERMISSION",
                                                 "BROWSE_PROJECTS"
                                                 ])


def load_users(jira_con, oaa_app):
  """ Load in all users for sian instance
  """

  # define OAA properties for local users
  oaa_app.property_definitions.define_local_user_property("account_id", OAAPropertyType.STRING)
  oaa_app.property_definitions.define_local_user_property("account_type", OAAPropertyType.STRING)

  users = jira_con.get_all_users()

  for user in users:
    if user['accountType'] != 'atlassian':
      # ignore non-users for now
      continue
    user_name = user['displayName']
    user_email = None
    if "emailAddress" in user:
      user_email = user['emailAddress']

    if user_name not in oaa_app.local_users:
      oaa_app.add_local_user(user_name, identities=user_email)

    oaa_app.local_users[user_name].set_property("account_id", user['accountId'])
    oaa_app.local_users[user_name].set_property("account_type", user['accountType'])
    oaa_app.local_users[user_name].is_active = user['active']


def load_groups(jira_con, oaa_app):
  """ discovery Jira groups and load members """

  groups = jira_con.api_get("group/bulk")

  for group in groups:
    group_name = group['name']
    if not group_name in oaa_app.local_groups:
      oaa_app.add_local_group(group_name)

    try:
      group_members = jira_con.api_get(
        "group/member", parameters={"groupname": group_name, "includeInactiveUsers": True})
    except HTTPError as e:
      if e.response.status_code == 404:
        log.warning(f"Issue finding group {group_name}, 404")
        continue
      raise e

    for member in group_members:
      if member['accountType'] == "app":
        # skip builtins and app users
        continue
      member_name = member['displayName']
      if member_name not in oaa_app.local_users:
        member_email = None
        if "emailAddress" in member:
          member_email = member['emailAddress']
        oaa_app.add_local_user(member_name, identities=member_email)

      oaa_app.local_users[member_name].add_group(group_name)

  # assign the jira-software-users group access to the jira app
  oaa_app.local_groups['jira-software-users'].add_role('jira-software-users', apply_to_application=True)


def load_projects(jira_con, oaa_app):

  oaa_app.property_definitions.define_resource_property("project", "private", OAAPropertyType.BOOLEAN)
  # list projects
  projects = jira_con.api_get("project/search", {"expand": "description"})

  for project in projects:
    project_description = project.get("description")
    project_id          = project.get("id")
    project_key         = project.get("key")
    project_name        = project.get("name")

    log.info(f"Loading project {project_name}")

    if project_name not in oaa_app.resources:
      oaa_app.add_resource(name=project_name, resource_type="project", description=project_description)

    # list project roles, then get project permission scheme
    project_roles = jira_con.api_get(f"project/{project_key}/role")
    project_permission_scheme = jira_con.api_get(f"project/{project_id}/permissionscheme", {"expand": "all"})

    process_project(jira_con, oaa_app, project, project_roles, project_permission_scheme)


def process_project(jira_con, oaa_app, project, project_roles, project_permission_scheme):
  project_id    = project.get("id")
  project_name  = project.get("name")
  log.info(f"Processing permission scheme for project: {project_name}")

  # print(f"[Debug]\tProject {project['isPrivate']=}")
  # build a dict of {project_id: {details}} to aggregate projectRole permissions
  roles_to_permissions = {}
  # build a dict of {project_id: {details}} to aggregate group permissions
  groups_to_permissions = {}

  # track a list of unknown holder types to only log once per type
  unknown_holder_types = []

  for permission in project_permission_scheme.get("permissions"):
    if "holder" not in permission:
      # no users/groups attached to the role - skip
      continue

    permission_name         = permission.get("permission")
    permission_holder       = permission.get("holder")
    permission_holder_type  = permission_holder.get("type")

    if permission_name not in oaa_app.custom_permissions:
      log.info(f"Creating permission {permission_name}")
      oaa_app.add_custom_permission(permission_name, parse_permissions(permission_name))

    if permission_holder_type == "projectRole":
      role_id = permission_holder.get("projectRole").get("id")

      if role_id not in roles_to_permissions:
        role_name = permission_holder.get("projectRole").get("name")
        role_url  = f"project/{project_id}/role/{role_id}"
        roles_to_permissions[role_id] = {"name": role_name, "url": role_url, "permissions": [permission_name]}
      else:
        roles_to_permissions.get(role_id).get("permissions").append(permission_name)

    elif permission_holder_type == "group":
      group_name = permission_holder.get("group").get("name")

      if group_name not in groups_to_permissions:
        groups_to_permissions[group_name] = {"name": group_name, "permissions": [permission_name]}
      else:
        groups_to_permissions.get(group_name).get("permissions").append(permission_name)

    elif permission_holder_type == "applicationRole":
      # TODO: implement
      pass

    elif permission_holder_type == "reporter":
      # TODO: implement
      pass

    elif permission_holder_type not in unknown_holder_types:
        log.warning(f"Unknown permission holder type {permission_holder_type} in project {project.get('name')}")
        unknown_holder_types.append(permission_holder_type)

  # iterate the groups_to_permissions dict and add authorization to the groups
  for group in groups_to_permissions:
    group_name = groups_to_permissions[group].get("name")

    # ensure that the group exists in the oaa_app
    if group_name not in oaa_app.local_groups:
      oaa_app.add_local_group(group_name)

    for permission in groups_to_permissions[group].get("permissions"):
        if permission not in oaa_app.custom_permissions:
            log.info(f"Creating permission {permission}")
            oaa_app.add_custom_permission(permission, parse_permissions(permission))

    # create a local role (project_id-group_name)
    local_project_role = f"{project_name}-{group_name}"
    if local_project_role not in oaa_app.local_roles:
      oaa_app.add_local_role(local_project_role, groups_to_permissions[group].get("permissions"))

    # add authorization to the group
    oaa_app.local_groups.get(group_name).add_role(role=local_project_role, resources=[oaa_app.resources.get(project_name)])

  # iterate the roles_to_permissions dict and add authorization to users who have the role
  for role in roles_to_permissions:
    # build a URL for the project role and get it via the Jira API
    role_url = f"project/{project_id}/role/{role}"
    role_details = jira_con.api_get(role_url)

    # create a local role (project_id-role_name)
    local_project_role = f"{project_name}-{roles_to_permissions[role].get('name')}"

    if local_project_role not in oaa_app.local_roles:
      oaa_app.add_local_role(local_project_role, roles_to_permissions[role].get("permissions"))

    # associate role to users
    for actor in role_details.get("actors"):
      actor_name = actor.get("displayName")

      # add the authorization to the user
      if actor_name in oaa_app.local_users:
        oaa_app.local_users.get(actor_name).add_role(role=local_project_role, resources=[oaa_app.resources.get(project_name)])

      if actor_name in oaa_app.local_groups:
        oaa_app.local_groups.get(actor_name).add_role(role=local_project_role, resources=[oaa_app.resources.get(project_name)])

  oaa_app.resources[project_name].set_property("private", project['isPrivate'])

  if not project['isPrivate']:
    # project is not private, need to assign access for jira-software-users
    oaa_app.local_groups['jira-software-users'].add_role("jira-software-users", resources=[oaa_app.resources.get(project_name)])
    return


def parse_permissions(name):
  """ takes a list of permissions from a Jira response and creates the Veza permissions for each
      uses basic string matching on keywords to associate canonical permissions
    """
  permissions = []
  name = name.lower()
  if "add" in name:
    permissions = [OAAPermission.DataWrite]
  elif "admin" in name:
    permissions = [OAAPermission.MetadataWrite]
  elif "assign" in name:
    permissions = [OAAPermission.MetadataWrite]
  elif "browse" in name:
    permissions = [OAAPermission.MetadataRead]
  elif "bulk_change" in name:
    permissions = [OAAPermission.DataWrite]
  elif "close" in name:
    permissions = [OAAPermission.MetadataWrite]
  elif "create" in name:
    permissions = [OAAPermission.DataWrite]
  elif "delete" in name:
    permissions = [OAAPermission.DataDelete]
  elif "edit" in name:
    permissions = [OAAPermission.DataWrite]
  elif "link" in name:
    permissions = [OAAPermission.MetadataWrite]
  elif "manage" in name:
    permissions = [OAAPermission.DataWrite]
  elif "modify" in name:
    permissions = [OAAPermission.DataWrite]
  elif "move" in name:
    permissions = [OAAPermission.NonData]
  elif "resolve" in name:
    permissions = [OAAPermission.MetadataWrite]
  elif "schedule_issues" in name:
    permissions = [OAAPermission.MetadataWrite]
  elif "set_issue_security" in name:
    permissions = [OAAPermission.MetadataWrite]
  elif "transition_issues" in name:
    permissions = [OAAPermission.MetadataWrite]
  elif "user_picker" in name:
    permissions = [OAAPermission.MetadataRead]
  elif "view" in name:
    permissions = [OAAPermission.DataRead]
  elif "work_on_issues" in name:
    permissions = [OAAPermission.MetadataWrite]
  else:
    log.warning(f"Unable to match canonical for permission {name}")
    permissions = [OAAPermission.NonData]

  return permissions


def discover(jira_con, oaa_app):
  load_permissions(jira_con, oaa_app)
  load_users(jira_con, oaa_app)
  load_groups(jira_con, oaa_app)
  load_projects(jira_con, oaa_app)


def log_arg_error(arg=None, env=None):
  if arg and env:
    log.error(f"Unable to load required paramter, must supply {arg} or set OS environment variable {env}")
  elif arg and not env:
    log.error(f"Unable to load required paramter, must supply {arg}")
  elif env:
    log.error(f"Unable to load required paramter, must set OS environment variable {env}")
  else:
    raise Exception("Must provide arg or env to include in error message")
  return

def main():
  parser = argparse.ArgumentParser(description="Veza OAA Jira Connector")
  parser.add_argument("--veza_url", default=os.getenv("VEZA_URL"), help="URL for Veza deployment")
  parser.add_argument("--jira_url", default=os.getenv("JIRA_URL"), help="URL for Atlassian instance. Example: https://<jira_domain>.atlassian.net")
  parser.add_argument("--jira_user", default=os.getenv("JIRA_USER"), help = "the user with which to connect to the Jira Cloud instance")
  parser.add_argument("--save_json", action="store_true", help="Save OAA JSON payload to file")
  parser.add_argument("--debug", action="store_true", help="Enable additional verbose debug logging")

  args = parser.parse_args()

  if args.debug or os.getenv("OAA_DEBUG"):
    log.setLevel(logging.DEBUG)

  veza_url = args.veza_url
  jira_url = args.jira_url
  jira_user = args.jira_user

  if not veza_url:
    log_arg_error("--veza_url", "VEZA_URL")
  if not jira_url:
    log_arg_error("--jira_url", "JIRA_URL")
  if not jira_user:
    log_arg_error("--jira_user", "JIRA_USER")

  veza_api_key = os.getenv("VEZA_API_KEY")
  if not veza_api_key:
    log_arg_error(env="VEZA_API_KEY")

  jira_token = os.getenv("JIRA_TOKEN")
  if not jira_token:
      log_arg_error(env="JIRA_TOKEN")

  if None in [veza_url, veza_api_key, jira_url, jira_user, jira_token]:
      log.error("Missing one or more required parameters")
      sys.exit(1)

  jira_con = JiraAPI(url=jira_url, username=jira_user, token=jira_token)
  # Instantiate an OAA Client, do this early to validate connection before processing application
  veza_con = OAAClient(url=veza_url, api_key=veza_api_key)

  oaa_app = CustomApplication(name=f"Jira - {jira_con.jira_instance}", application_type="Jira")

  try:
    test_call = jira_con.api_get("/permissions")
  except HTTPError as e:
    if e.response.status_code == 401:
      log.error(f"User {jira_user} is not logged in properly or does not have admin permissions to instance {args.jira_url}")
    sys.exit(1)

  discover(jira_con, oaa_app)
  push_to_veza(veza_con, oaa_app, args.save_json)

if __name__ == "__main__":
  # replace the log with the root logger if running as main
  log = logging.getLogger()
  logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
  main()
