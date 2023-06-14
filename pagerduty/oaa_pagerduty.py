#!env python3
"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, CustomResource, OAAPermission, OAAPropertyType, LocalUser
from requests import HTTPError
import argparse
import logging
import oaaclient.utils as oaautils
import os
import re
import requests
import sys

logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)

PD_LOGO_B64="""
PHN2ZyB2ZXJzaW9uPSIxLjEiIGlkPSJMYXllcl8xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3
LnczLm9yZy8xOTk5L3hsaW5rIiB4PSIwcHgiIHk9IjBweCIKCSB2aWV3Qm94PSIwIDAgMTIwLjYgMTc1IiBzdHlsZT0iZW5hYmxlLWJhY2tncm91bmQ6bmV3
IDAgMCAxMjAuNiAxNzU7IiB4bWw6c3BhY2U9InByZXNlcnZlIj4KPHN0eWxlIHR5cGU9InRleHQvY3NzIj4KCS5zdDB7ZmlsbDojMDZBQzM4O30KPC9zdHls
ZT4KPGc+Cgk8cmVjdCB5PSIxMjguNCIgY2xhc3M9InN0MCIgd2lkdGg9IjI1LjciIGhlaWdodD0iNDYuNiIvPgoJPHBhdGggY2xhc3M9InN0MCIgZD0iTTk2
LjUsOC42QzgyLjgsMS4yLDczLjIsMCw1MC43LDBIMHYxMDYuMWgyNS43SDI5aDIxLjVjMjAsMCwzNS0xLjIsNDguMi0xMGMxNC40LTkuNSwyMS45LTI1LjQs
MjEuOS00My44CgkJQzEyMC42LDMyLjUsMTExLjQsMTYuNiw5Ni41LDguNnogTTU2LjQsODMuOUgyNS43VjIyLjdsMjktMC4yYzI2LjQtMC4yLDM5LjYsOSwz
OS42LDMwLjFDOTQuMyw3NS4zLDc3LjksODMuOSw1Ni40LDgzLjl6Ii8+CjwvZz4KPC9zdmc+Cg==
"""

def pd_api_get(path: str, api_key: str, params: dict = None) -> dict:
    """Perform PagerDuty API GET

    Args:
        path (str): API path
        api_key (str): PagerDuty API key
        params (dict, optional): Optional GET query parameters. Defaults to None.

    Raises:
        HTTPError

    Returns:
        dict: API response
    """

    path = path.lstrip("/")
    if re.match(r"^https:\/\/", path):
        api_path = path
    else:
        api_path = f"https://api.pagerduty.com/{path}"

    headers = {}
    headers["accpet"] = "application/vnd.pagerduty+json;version=2"
    headers["authorization"] = f"Token token={api_key}"

    response = requests.get(api_path, headers=headers, params=params, timeout=60)
    if response.ok:
        return response.json()
    else:
        raise HTTPError(response.text, response=response)


class OAAPagerDuty():
    """OAA Connector for PagerDuty

    Args:
        pd_api_key (str): PagerDuty API key

    Attributes:
        app (CustomApplication): OAA CustomApp instance
        subdomain (str): Determined subdomain of PagerDuty instance

    """

    def __init__(self, pd_api_key: str) -> None:

        self._pd_api_key = pd_api_key
        calling_abilities = pd_api_get("abilities", api_key=self._pd_api_key)
        if "teams" in calling_abilities["abilities"]:
            self._teams_enabled = True
        else:
            self._teams_enabled = False

        self.subdomain = self.get_subdomain()

        self.app = CustomApplication(f"PagerDuty - {self.subdomain}", application_type="PagerDuty")

        self.app.property_definitions.define_local_user_property("email", OAAPropertyType.STRING)
        self.app.property_definitions.define_local_user_property("is_billed", OAAPropertyType.BOOLEAN)

        self.app.property_definitions.define_resource_property("team", "pagerduty_id", OAAPropertyType.STRING)
        self.app.property_definitions.define_resource_property("team", "summary", OAAPropertyType.STRING)
        self.app.property_definitions.define_resource_property("team", "default_role", OAAPropertyType.STRING)

        self._populate_roles()

    def get_subdomain(self) -> str:
        """Determine the subdomain of the PagerDuty account

        Uses the users API tog et a single user and their subdomain as a workaround to determine the unique
        PagerDuty subdomain the API key is for

        Returns:
            str: subdomain
        """

        params = {"limit": 1, "include[]": "subdomains"}
        response = pd_api_get("/users", params=params, api_key=self._pd_api_key)

        single_user = response["users"][0]
        subdomains = single_user["subdomains"]
        if len(subdomains) > 1:
            log.warning("Multiple subdomains returned for user")

        return subdomains[0]

    def discover(self) -> None:
        """Run Discovery of PagerDuty environment
        """
        log.info("Starting Discovery")
        self.discover_users()

        self.discover_teams()
        log.info("Discovery Finished")
        return

    def discover_teams(self) -> None:

        if not self._teams_enabled:
            log.info("Teams not enabled or authorized, skipping teams discovery")
            return

        log.info("Discoverying Teams")
        params = {"limit": 100}

        while True:
            response = pd_api_get("/teams", api_key=self._pd_api_key, params=params)
            for team in response["teams"]:
                team_name = team.get("name")
                team_id = team.get("id")
                default_role = team.get("default_role")
                summary = team.get("summary")
                description = team.get("description")

                new_team = self.app.add_local_group(team_name, unique_id=team_id)

                team_resource = self.app.add_resource(team_name, resource_type="team")

                if description and len(description) > 256:
                    # PagerDuty description can be up to 1,024 characters
                    team_resource.description = description[:255]
                else:
                    team_resource.description = description

                team_resource.set_property("pagerduty_id", team_id)
                team_resource.set_property("summary", summary)
                team_resource.set_property("default_role", default_role)

                self.discover_team_members(team_id, team_resource=team_resource)

            if response.get("more"):
                # paginate
                params["offset"] = response["offset"] + response["limit"]
            else:
                break

    def discover_team_members(self, team_id: str, team_resource: CustomResource) -> None:
        """Discover team members and roles

        Args:
            team_id (str): PagerDuty ID for team
            team_resource (CustomResource): CustomResource for team
        """
        params = {"limit": 100}

        while True:
            members_response = pd_api_get(f"teams/{team_id}/members", api_key=self._pd_api_key, params=params)
            for member in members_response["members"]:
                user_id = member["user"]["id"]
                role = member["role"]
                self.app.local_users[user_id].add_role(role, resources=[team_resource])
                self.app.local_users[user_id].add_group(team_id)

            if members_response.get("more"):
                # paginate
                params["offset"] = members_response["offset"] + members_response["limit"]
            else:
                break

        return

    def discover_users(self) -> None:
        """Discover PagerDuty Users
        """
        log.info("Discovering users")
        params = {"limit": 100}

        while True:
            response = pd_api_get("/users", api_key=self._pd_api_key, params=params)
            for user in response["users"]:
                user_name = user.get("name")
                email = user.get("email")
                is_billed = user.get("billed")
                user_role = user.get("role")
                user_id = user.get("id")

                new_user = self.app.add_local_user(user_name, unique_id=user_id, identities=[email])
                new_user.add_role(user_role, apply_to_application=True)
                new_user.set_property("email", email)
                new_user.set_property("is_billed", is_billed)

            if response.get("more"):
                # paginate
                params["offset"] = response["offset"] + response["limit"]
            else:
                break

        return

    def _populate_roles(self) -> None:
        """Create the OAA roles for Pager Duty
        """
        self.app.add_custom_permission("admin", permissions=[OAAPermission.DataWrite, OAAPermission.DataRead, OAAPermission.DataDelete, OAAPermission.MetadataRead, OAAPermission.MetadataWrite])
        self.app.add_custom_permission("limited_user", permissions=[OAAPermission.DataRead, OAAPermission.MetadataRead])
        self.app.add_custom_permission("manager", permissions=[OAAPermission.DataWrite, OAAPermission.DataRead, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
        self.app.add_custom_permission("observer", permissions=[OAAPermission.DataRead, OAAPermission.MetadataRead])
        self.app.add_custom_permission("owner", permissions=[OAAPermission.DataWrite, OAAPermission.DataRead, OAAPermission.DataDelete, OAAPermission.MetadataRead, OAAPermission.MetadataWrite])
        self.app.add_custom_permission("read_only_limited_user", permissions=[OAAPermission.MetadataRead])
        self.app.add_custom_permission("read_only_user", permissions=[OAAPermission.DataRead, OAAPermission.MetadataRead])
        self.app.add_custom_permission("responder", permissions=[OAAPermission.DataWrite, OAAPermission.DataRead])
        self.app.add_custom_permission("restricted_access", permissions=[OAAPermission.MetadataRead, OAAPermission.MetadataWrite])
        self.app.add_custom_permission("user", permissions=[OAAPermission.DataRead, OAAPermission.MetadataRead])


        self.app.add_local_role("Golbal Admin", unique_id="admin", permissions=["admin"])
        self.app.add_local_role("Responder", unique_id="limited_user", permissions=["limited_user"])
        self.app.add_local_role("Observer", unique_id="observer", permissions=["observer"])
        self.app.add_local_role("Account Owner", unique_id="owner", permissions=["owner"])
        self.app.add_local_role("Limited Stakeholder", unique_id="read_only_limited_user", permissions=["read_only_limited_user"])
        self.app.add_local_role("Full Stakeholder", unique_id="read_only_user", permissions=["read_only_user"])
        self.app.add_local_role("Restricted Access", unique_id="restricted_access", permissions=["restricted_access"])
        self.app.add_local_role("User", unique_id="user", permissions=["user"])

        self.app.add_local_role("Responder", unique_id="responder", permissions=["responder"])
        self.app.add_local_role("Manager", unique_id="manager", permissions=["manager"])

        return


def run(pd_api_key: str, veza_url: str, veza_api_key: str, save_json: bool = False, debug: bool = False ) -> None:
    if debug:
        log.setLevel(logging.DEBUG)
        log.debug("Debug logging enabled")

    veza_con = OAAClient(veza_url, api_key=veza_api_key)

    pd = OAAPagerDuty(pd_api_key=pd_api_key)
    pd.discover()

    log.info("Starting push")
    provider_name = "PagerDuty"
    provider = veza_con.get_provider(provider_name)
    if provider:
        log.info("Found existing provider")
    else:
        log.info(f"Creating Provider {provider_name}")
        provider = veza_con.create_provider(provider_name, "application")
    log.info(f"Provider: {provider['name']} ({provider['id']})")

    # set the Box icon
    data_source_name = f"pagerduty - {pd.subdomain}"
    # push data
    try:
        veza_con.update_provider_icon(provider['id'], PD_LOGO_B64)
        response = veza_con.push_application(provider_name, data_source_name=data_source_name, application_object=pd.app, save_json=save_json)
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
    parser.add_argument("--veza-url", required=False, default=os.getenv("VEZA_URL"), help="Hostname for Veza deployment")
    parser.add_argument("--save-json", action="store_true", help="Save OAA JSON payload to file")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug output")
    args = parser.parse_args()

    veza_url = args.veza_url
    save_json = args.save_json

    debug = False
    if args.debug or os.getenv("OAA_DEBUG"):
        debug = True

    # security tokens can only come from OS environment
    veza_api_key = os.getenv('VEZA_API_KEY')

    if not veza_url:
        oaautils.log_arg_error(log, "--veza-url", "VEZA_URL")
    if not veza_api_key:
        oaautils.log_arg_error(log, env="VEZA_API_KEY")

    pd_api_key = os.getenv("PAGERDUTY_API_KEY")
    if not pd_api_key:
        oaautils.log_arg_error(log, env="PAGERDUTY_API_KEY")

    if None in [pd_api_key, veza_url, veza_api_key]:
        log.error("Missing one or more required parameters")
        sys.exit(1)

    run(pd_api_key=pd_api_key, veza_url=veza_url, veza_api_key=veza_api_key, save_json=save_json, debug=debug)


if __name__ == '__main__':
    main()
