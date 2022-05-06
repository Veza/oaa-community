#!env python3
from looker_permissions import looker_permission_definitions
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, CustomResource, OAAPermission, OAAPropertyType
from requests import HTTPError
from urllib.parse import urlparse
import argparse
import json
import logging
import looker_sdk
import oaaclient.utils as oaautils
import os
import requests
import sys


logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)


class OAALooker():
    """
    OAA Class for discovering Looker instance. Currently focuses on what models and database connections a user
    can access based on Looker roles

    Attributes:
        app (CustomApplication): CustomApplication object to create OAA template
        looker_con (looker_sdk): Looker SDK connection object
        looker_instance (str): Looker instance name like veza.cloud.looker.com

    """

    def __init__(self) -> None:
        self.app = CustomApplication("Looker", application_type="looker")

        self.__looker_token = None
        # login to the looker API with custom method first since it returns better errors
        self.__looker_api_login()

        self.looker_con = looker_sdk.init40()

        # get the Looker instance URL without api path or schema
        self.looker_instance = urlparse(self.looker_con.api_path).netloc

        # Looker API makes heavy use to ID numbers in responses, to reduce API calls, create maps of ID -> name
        self.__group_ids = {}  # map Looker group IDs to names to save API calls
        # self.__role_ids = {}

        self.__looker_roles = {}    # store information about each role in its own object
        self.__model_roles = {}     # track roles assigned to each model

        # configure custom oaa properties we are going to use
        self.app.property_definitions.define_local_user_property("id", OAAPropertyType.NUMBER)
        self.app.property_definitions.define_local_user_property("verified_looker_employee", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_local_user_property("presumed_looker_employee", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_local_group_property("id", OAAPropertyType.NUMBER)
        self.app.property_definitions.define_resource_property("model_set", "id", OAAPropertyType.NUMBER)
        self.app.property_definitions.define_resource_property("model_set", "built_in", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_resource_property("model_set", "all_access", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_resource_property("connection", "dialiect", OAAPropertyType.STRING)
        self.app.property_definitions.define_resource_property("connection", "host", OAAPropertyType.STRING)
        self.app.property_definitions.define_resource_property("connection", "username", OAAPropertyType.STRING)

        pass

    def discover(self) -> None:
        """ Run through Looker discovery steps and populate self.app with OAA template information """

        self.discover_roles()

        self.discover_groups()
        self.discover_users()

        # assign the admins to the app
        for user in self.__looker_roles["Admin"].users:
            self.app.local_users[user].add_role("Admin", apply_to_application=True)
        for group in self.__looker_roles["Admin"].groups:
            self.app.local_groups[group].add_role("Admin", apply_to_application=True)

        self.discover_models()

        return

    def discover_roles(self) -> None:
        """ Discovers Looker roles and populates permissions for template.

        Uses the Looker API to get all permissions and merges that with the looker_permission_definitions for the Veza
        CRUD definitions. Supports filtering down permissions for simplicity as well, to add a permission just update the
        `tracked_permissions` variable.

        Additionally store the names of the models the role has access to, model discovery happens separately but we need
        saving this information avoids repeat API calls later.
        """

        tracked_permissions = ["administer", "access_data", "develop", "explore", "see_lookml", "use_sql_runner"]
        all_permissions = self.looker_con.all_permissions()
        for p in all_permissions:
            if p.permission not in tracked_permissions:
                # limit permissions gathered to a smaller set
                continue
            if p.permission in looker_permission_definitions:
                self.app.add_custom_permission(p.permission, looker_permission_definitions[p.permission], apply_to_sub_resources=False)
            else:
                self.app.add_custom_permission(p.permission, [OAAPermission.NonData], apply_to_sub_resources=False)

        self.app.custom_permissions["administer"].apply_to_sub_resources = True

        all_roles = self.looker_con.all_roles()
        for r in all_roles:
            looker_role = self.__looker_roles[r.name] = LookerRole(r.name, r.id)
            role = self.app.add_local_role(r.name)
            # self.__role_ids[r.id] = r.name

            # only include permissions for the role that have been defined in the OAA app
            role_permissions = [p for p in r.permission_set.permissions if p in self.app.custom_permissions]
            role.add_permissions(role_permissions)
            for model in r.model_set.models:
                logging.debug(f"Adding {model=} for {r.name=}")
                if model in self.__model_roles:
                    self.__model_roles[model].append(r.name)
                else:
                    self.__model_roles[model] = [r.name]

            # have to use raw API to get users and groups for roles, the sdk "helpfully" gets the complete list of users who have a role combining direct
            # and group based assignments, the API allows to get the exact path of assignement
            role_users = self.__looker_api_get(f"/api/3.1/roles/{r.id}/users", params={"direct_association_only": True, "fields": "display_name,email"})
            logging.debug(f"{role_users=}")
            for user in role_users:
                if user["display_name"]:
                    looker_role.users.append(user['display_name'])
                else:
                    looker_role.users.append(user['email'])

            role_groups = self.__looker_api_get(f"/api/3.1/roles/{r.id}/groups", params={"fields": ["name"]})
            logging.debug(f"{role_groups=}")
            for group in role_groups:
                looker_role.groups.append(group['name'])

        return

    def discover_groups(self) -> None:
        """ discover the group information only, membership is handled by the user discovery """
        all_groups = self.looker_con.all_groups()

        for g in all_groups:
            # print(g)
            group_name = g.name
            group_id = g.id
            group = self.app.add_local_group(group_name)
            group.set_property("id", group_id)

            # store group id to name for later use
            self.__group_ids[group_id] = group_name

        return

    def discover_users(self) -> None:
        """ discover all the users and populate their groups """
        all_users = self.looker_con.all_users()

        for u in all_users:
            logging.debug(f"Adding users {u.display_name} - ({u.email})")
            if u.display_name:
                user_name = u.display_name
            else:
                user_name = u.email

            # user properties
            # user_id = u.id
            # disabled = u.is_disabled
            # first_name = u.first_name
            # last_name = u.last_name

            local_user = self.app.add_local_user(user_name, identities=[u.email])
            local_user.set_property("id", u.id)
            local_user.set_property("verified_looker_employee", u.verified_looker_employee)
            local_user.set_property("presumed_looker_employee", u.presumed_looker_employee)

            local_user.is_active = not u.is_disabled
            # use email credentials for created/last-login, might not be applicable
            # in order to have meaningful created/lastlogin we'd have to loop through all the different credential
            # types and find the newest login, the created at probably isn't usable for the age of the account
            # if u.credentials_email:
            #     local_user.created_at = u.credentials_email.created_at
            #     if u.credentials_email.logged_in_at:
            #         local_user.last_login_at = u.credentials_email.logged_in_at
            for group_id in u.group_ids:
                try:
                    group_name = self.__group_ids[group_id]
                except KeyError:
                    log.error(f"Unknown group id {group_id} for user {user_name}")
                    continue
                local_user.add_group(group_name)

    def discover_models(self) -> None:
        """ Looker model_sets are the group of models that a role has access too. For each model_set discover
        the models and assign the roles with access. Which roles have access to which models was saved during
        role discovery
        """
        for model_set in self.looker_con.all_model_sets():
            logging.debug(f"Processing model set {model_set.name}")
            model_set_resource = self.app.add_resource(model_set.name, resource_type="model_set")
            model_set_resource.set_property("id", model_set.id)
            model_set_resource.set_property("built_in", model_set.built_in)
            model_set_resource.set_property("all_access", model_set.all_access)

            # go through all users with role
            for model_name in model_set.models:
                logging.debug(f"Adding model {model_name} to model set {model_set.name}")
                model_resource = model_set_resource.add_sub_resource(model_name, resource_type="model")

                logging.debug(f"{self.__model_roles[model_name]=}")
                model = self.__looker_api_get(f"/api/3.1/lookml_models/{model_name}")
                for connection_name in model['allowed_db_connection_names']:
                    connection = self.looker_con.connection(connection_name)
                    connection_resource = model_resource.add_sub_resource(connection.name, resource_type="connection")
                    connection_resource.set_property("dialiect", connection.dialect_name)
                    connection_resource.set_property("host", connection.host)
                    connection_resource.set_property("username", connection.username)

                for role_name in self.__model_roles[model_name]:
                    logging.debug(f"Need to add {role_name=} to {model_name=}")
                    self.assign_role_to_resource(role_name, model_resource)
                    self.assign_role_to_resource(role_name, connection_resource)

    def assign_role_to_resource(self, role_name: str, resource: CustomResource) -> None:
        """ helper function to assign all the users/groups with a role to an OAA resource """
        if role_name not in self.__looker_roles:
            raise Exception(f"Unknown role {role_name}, not in internal model")

        role = self.__looker_roles[role_name]
        for user in role.users:
            if user not in self.app.local_users:
                logging.error(f"Unknown user {user}, may be support user")
                continue
            self.app.local_users[user].add_role(role_name, [resource])

        for group in role.groups:
            self.app.local_groups[group].add_role(role_name, [resource])

        return

    def __looker_api_get(self, path: str, params: dict = {}) -> dict:
        """ perform direct Looker API GET, used when SDK cannot get information, performs the login function if token
        is not already generated. Does not handle pagination.

        Returns json response as dictionary
        """
        looker_url = os.getenv("LOOKERSDK_BASE_URL").rstrip("/")
        path = path.lstrip("/")
        if not self.__looker_token:
            self.__looker_api_login()

        headers = {}
        headers["Authorization"] = f"token {self.__looker_token}"
        headers["Accept"] = "application/json"

        logging.info(f"GET({looker_url}/{path})")
        response = requests.get(f"{looker_url}/{path}", headers=headers, params=params, timeout=120)
        if response.ok:
            return response.json()
        else:
            try:
                data = response.json()
                if "message" in data:
                    message = data["message"]
                else:
                    message = data
            except json.decoder.JSONDecodeError:
                message = response.text()
            logging.error(f"Error {response.status_code}, url: {looker_url}/{path}: {message}")
            raise HTTPError(message, response=response)

    def __looker_api_login(self) -> None:
        """
        Performs the Looker login to retrieve a token using the same environment variables as the SDK
        """
        # expect the same OS parameters used by the SDK, since they are there
        looker_url = os.getenv("LOOKERSDK_BASE_URL")
        client_id = os.getenv("LOOKERSDK_CLIENT_ID")
        client_secret = os.getenv("LOOKERSDK_CLIENT_SECRET")

        login_creds = {"client_id": client_id, "client_secret": client_secret}
        response = requests.post(f"{looker_url}/api/3.1/login", timeout=10, data=login_creds)
        if response.ok:
            data = response.json()
            self.__looker_token = data['access_token']
            # token TTL data['expires_in']
        else:
            # unfortunately login error does not return helpful information, it returns the id and secret used to login
            # to avoid printing that to logs raise a message, can investigate if really needed
            logging.error("Unable to login to Looker API, please validate credentials")
            raise HTTPError("Unable to login to Looker API", response=response)


class LookerRole():
    """ to limit API calls we need to store some information about the roles, doing so with a model simplifies things """

    def __init__(self, name: str, id: int):
        self.name = name
        self.id = id
        self.users = []
        self.groups = []
        self.models = []


def run(veza_url: str, veza_api_key: str, save_json: bool = False, verbose: bool = False) -> None:
    """
    Perform Looker discovery and submit OAA payload to Veza
    """
    if verbose:
        log.setLevel(logging.DEBUG)
        log.debug("Enabling verbose logging")

    try:
        veza_con = OAAClient(url=veza_url, api_key=veza_api_key)
    except OAAClientError as e:
        log.error(f"Unable to connect to Veza ({veza_url})")
        log.error(e.message)
        sys.exit(1)

    try:
        oaa_looker = OAALooker()
        oaa_looker.discover()
    except looker_sdk.error.SDKError as e:
        logging.error("Discovery failed due to SDK API call error")
        # looker errors may be html, search string for 404 ¯\_(ツ)_/¯
        if "404" in str(e.args):
            logging.error("404 errors can indicate permissions issues, check permissions for Looker user")
        sys.exit(2)
    except HTTPError as e:
        logging.error("Discovery failed due to API error")
        if e.response.status_code == 404:
            logging.error("404 errors can indicate permissions issues, check permissions for Looker user")
        sys.exit(2)

    provider_name = "Looker"
    provider = veza_con.get_provider(provider_name)
    if provider:
        log.info("Found existing provider")
    else:
        log.info(f"Creating Provider {provider_name}")
        provider = veza_con.create_provider(provider_name, "application")
    log.info(f"Provider: {provider['name']} ({provider['id']})")

    # push data
    try:
        veza_con.push_application(provider_name, data_source_name=oaa_looker.looker_instance, application_object=oaa_looker.app, save_json=save_json)
        log.info("Success")
    except OAAClientError as e:
        log.error(f"{e.error}: {e.message} ({e.status_code})")
        if hasattr(e, "details"):
            for d in e.details:
                log.error(d)

    return


###########################################################
# Main
###########################################################
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--veza-url", required=False, default=os.getenv("VEZA_URL"), help="Hostname for Veza deployment")
    parser.add_argument("--save-json", action="store_true", help="Save OAA JSON payload to file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug output")
    args = parser.parse_args()

    veza_url = args.veza_url
    save_json = args.save_json

    # security tokens can only come from OS environment
    veza_api_key = os.getenv('VEZA_API_KEY')

    # expect Looker environment for SDK, print more helpful error message if not set
    for var in ["LOOKERSDK_BASE_URL", "LOOKERSDK_CLIENT_ID", "LOOKERSDK_CLIENT_SECRET"]:
        if not os.getenv(var):
            oaautils.log_arg_error(log, env=var)
            print("Missing required paramters for Looker SDK, exiting", file=sys.stderr)
            sys.exit(1)

    if not veza_url:
        oaautils.log_arg_error(log, "--veza-url", "VEZA_URL")
    if not veza_api_key:
        oaautils.log_arg_error(log, env="VEZA_API_KEY")

    if None in [veza_url, veza_api_key]:
        print("Missing one or more required parameters", file=sys.stderr)
        sys.exit(1)

    run(veza_url=veza_url, veza_api_key=veza_api_key, save_json=save_json, verbose=args.verbose)


if __name__ == '__main__':
    main()
