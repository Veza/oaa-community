#!env python3
"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

import argparse
import json
import logging
import os
import sys

import oaaclient.utils as oaautils
import requests
from requests.exceptions import HTTPError
import slack_sdk
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, OAAPermission, OAAPropertyType, LocalUser

# set up logging
log = logging.getLogger(__name__)


class OAA_Slack_Connector():
    def __init__(self, slack_token: str):
        self.token = slack_token

        self.client = slack_sdk.WebClient(token=self.token)

        team_info = self.client.team_info()
        self.team_name = team_info.data.get("team", {}).get("name")

        self.app = CustomApplication(f"Slack - {self.team_name}", "Slack")
        self.app.property_definitions.define_local_user_property("slack_name", OAAPropertyType.STRING)
        self.app.property_definitions.define_local_user_property("email", OAAPropertyType.STRING)
        self.app.property_definitions.define_local_user_property("has_mfa", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_local_user_property("is_restricted", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_local_user_property("is_ultra_restricted", OAAPropertyType.BOOLEAN)
        self.app.property_definitions.define_local_user_property("bot_id", OAAPropertyType.STRING)

        self.app.property_definitions.define_local_group_property("is_deleted", OAAPropertyType.BOOLEAN)

        self.app.add_custom_permission("Member", permissions=[OAAPermission.DataWrite, OAAPermission.MetadataWrite])
        self.app.add_custom_permission("Guest", permissions=[OAAPermission.DataWrite, OAAPermission.MetadataWrite])
        self.app.add_custom_permission("Admin", permissions=[OAAPermission.DataWrite, OAAPermission.MetadataWrite])
        self.app.add_custom_permission("Owner", permissions=[OAAPermission.DataWrite, OAAPermission.MetadataWrite])
        self.app.add_custom_permission("Primary Owner", permissions=[OAAPermission.NonData])
        pass


    def discover(self) -> None:
        """Discovery method

        Performs Slack discovery and populates OAA application object `self.app` for push
        """
        log.info("Start Slack discovery")
        self._discover_users()
        self._discover_usergroups()
        log.info("Finish Slack discovery")
        return

    def _discover_users(self) -> None:
        """Discovers Slack users
        """

        next_cursor = ''
        while True:
            users_list_response = self.client.users_list(cursor=next_cursor)

            # determine if there aer more responses to retrieve
            response_metadata = users_list_response.data.get("response_metadata", {})
            next_cursor = response_metadata.get("next_cursor")

            for user in users_list_response.data.get("members", []):
                self._add_user(user)

            # stop if there are no more users to retrieve
            if not next_cursor:
                break

        return

    def _add_user(self, user: dict) -> LocalUser:
        """Create a new Local User

        Args:
            user (dict): Slack API response for user

        Returns:
            LocalUser: New OAA Local User
        """

        id = user.get("id")
        name = user.get("profile", {}).get("real_name_normalized")
        display_name = user.get("profile", {}).get("display_name_normalized")

        if display_name:
            user_name = display_name
        elif name:
            user_name = name
        else:
            # fall back on id
            log.warning(f"Unable to determine a name for user {id}")
            user_name = id

        deleted = user.get("deleted")
        invited_user = user.get("is_invited_user")
        email = user.get("profile", {}).get("email")

        is_bot = user.get("is_bot")
        bot_id = user.get("profile", {}).get("bot_id")

        oaa_user = self.app.add_local_user(name=user_name, unique_id=id)
        if email:
            oaa_user.add_identity(email)
            oaa_user.set_property("email", email)

        oaa_user.set_property("slack_name", name)
        oaa_user.set_property("has_mfa", user.get("has_2fa", False))
        oaa_user.set_property("is_restricted", user.get("is_restricted", False))
        oaa_user.set_property("is_ultra_restricted", user.get("is_ultra_restricted", False))

        if is_bot and bot_id is not None:
            oaa_user.set_property("bot_id", bot_id)
            #TODO: set account type to service

        if deleted or invited_user:
            oaa_user.is_active = False
        else:
            oaa_user.is_active = True

        if user.get("is_restricted"):
            oaa_user.add_permission("Guest", apply_to_application=True)
        else:
            oaa_user.add_permission("Member", apply_to_application=True)

        if user.get("is_admin"):
            oaa_user.add_permission("Admin", apply_to_application=True)
        if user.get("is_owner"):
            oaa_user.add_permission("Owner", apply_to_application=True)
        if user.get("is_primary_owner"):
            oaa_user.add_permission("Primary Owner", apply_to_application=True)

        return oaa_user

    def _discover_usergroups(self) -> None:
        """Discovers Slack user groups
        """

        usergroups = self.client.usergroups_list()
        for usergroup in usergroups.data.get("usergroups", []):
            group_id = usergroup["id"]
            group_name = usergroup["name"]
            oaa_group = self.app.add_local_group(group_name, unique_id=group_id)
            if usergroup.get("date_delete", 0) > 0:
                oaa_group.set_property("is_deleted", True)
            else:
                oaa_group.set_property("is_deleted", False)

            user_list = self.client.usergroups_users_list(usergroup=group_id)
            for member_id in user_list.data.get("users", []):
                if member_id not in self.app.local_users:
                    log.warning(f"Found member of group that is not in user list: user_id: {member_id}")
                    continue
                self.app.local_users[member_id].add_group(group_id)

        return

def run(slack_token: str, veza_url: str, veza_api_key: str, **config_args) -> None:
    """Run OAA Slack connector as function

    Args:
        slack_token (str): Slack App token for authentication
        veza_url (str): Veza tenant for OAA submission
        veza_api_key (str): Veza API key
        skip_deleted_users (bool, optional): Skip discovery of deleted Slack users, default False
        debug (bool, optional): Enable debug log output, default False
        save_json (bool, optional): Save OAA payload to local JSON file before push, default False

    Raises:
        slack_sdk.errors.SlackApiError: If Slack API returns error during discovery
        oaaclient.client.OAAClientError: Errors populating the OAA template or communicating with the Veza API
    """

    if config_args.get("debug"):
        log.setLevel(logging.DEBUG)
        logging.getLogger("urllib3").setLevel(logging.INFO)
        log.info("Enabling debug logging")
    else:
        log.setLevel(logging.INFO)

    save_json = config_args.get("save_json", False)
    if not isinstance(save_json, bool):
        raise TypeError("save_json argument must be boolean")

    skip_deleted_users = config_args.get("skip_deleted", False)
    if not isinstance(skip_deleted_users, bool):
        raise TypeError("skip_deleted argument must be boolean")

    try:
        conn = OAAClient(url = veza_url, api_key = veza_api_key)
    except OAAClientError as error:
        log.error(f"Unable to connect to Veza {veza_url}")
        log.error(error.message)
        raise error

    try:
        oaa_slack = OAA_Slack_Connector(slack_token=slack_token)
        oaa_slack.discover()
    except slack_sdk.errors.SlackApiError as e:
        log.error("Error from Slack SDK")
        log.error(e)
        raise e

    provider_name = "Slack"
    provider = conn.get_provider(provider_name)

    if provider:
        log.info("found existing provider")
    else:
        log.info(f"creating provider {provider_name}")
        provider = conn.create_provider(provider_name, "application")
    log.info(f"provider: {provider['name']} ({provider['id']})")

    # push data to Veza
    data_source_name = f"Slack - {oaa_slack.team_name}"
    try:
        log.debug("Updating Provider logo")
        conn.update_provider_icon(provider["id"], SLACK_SGV_B64)
        log.info("uploading custom application data")
        response = conn.push_application(provider_name,
                                         data_source_name = data_source_name,
                                         application_object = oaa_slack.app,
                                         save_json = save_json
                                        )
        if response.get("warnings", None):
            log.warning("Push succeeded with warnings:")
            for e in response["warnings"]:
                log.warning(e)
        log.info("success")
    except OAAClientError as error:
        log.error(f"{error.error}: {error.message} ({error.status_code})")
        if hasattr(error, "details"):
            for detail in error.details:
                log.error(f"  {detail}")
        raise error


    return

def main():
    """
    process command line and OS environment variables, then call `run`
    """
    parser = argparse.ArgumentParser(description = "OAA Slack Connector")
    parser.add_argument("--veza-url", default=os.getenv("VEZA_URL"), help="the URL of the Veza instance")
    parser.add_argument("--skip-deleted", action="store_true", help="Skip discovery of deleted users")
    parser.add_argument("--debug", action="store_true", help="Set the log level to debug")
    parser.add_argument("--save-json", action="store_true", help="Save OAA JSON payload to file")
    args = parser.parse_args()

    slack_token = os.getenv("SLACK_TOKEN")
    veza_api_key = os.getenv("VEZA_API_KEY")
    veza_url = args.veza_url
    save_json = args.save_json
    skip_deleted = args.skip_deleted

    if not veza_api_key:
        oaautils.log_arg_error(log, None, "VEZA_API_KEY")
    if not veza_url:
        oaautils.log_arg_error(log, "--veza-url", "VEZA_URL")

    if not slack_token:
        oaautils.log_arg_error(log, None, "SLACK_TOKEN")

    # ensure required variables are provided
    if None in [veza_api_key, veza_url, slack_token]:
        log.error(f"missing one or more required parameters")
        sys.exit(1)

    try:
        run(slack_token=slack_token, veza_url=veza_url,  veza_api_key=veza_api_key, skip_deleted=skip_deleted, save_json=save_json, debug=args.debug)
    except (OAAClientError, HTTPError, slack_sdk.errors.SlackApiError):
        log.error("Exiting with error")
        sys.exit(1)

SLACK_SGV_B64 = """
PHN2ZyB2ZXJzaW9uPSIxLjEiIGlkPSJMYXllcl8xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3
LnczLm9yZy8xOTk5L3hsaW5rIiB4PSIwcHgiIHk9IjBweCIKCSB2aWV3Qm94PSIwIDAgMjcwIDI3MCIgc3R5bGU9ImVuYWJsZS1iYWNrZ3JvdW5kOm5ldyAw
IDAgMjcwIDI3MDsiIHhtbDpzcGFjZT0icHJlc2VydmUiPgo8c3R5bGUgdHlwZT0idGV4dC9jc3MiPgoJLnN0MHtmaWxsOiNFMDFFNUE7fQoJLnN0MXtmaWxs
OiMzNkM1RjA7fQoJLnN0MntmaWxsOiMyRUI2N0Q7fQoJLnN0M3tmaWxsOiNFQ0IyMkU7fQo8L3N0eWxlPgo8Zz4KCTxnPgoJCTxwYXRoIGNsYXNzPSJzdDAi
IGQ9Ik05OS40LDE1MS4yYzAsNy4xLTUuOCwxMi45LTEyLjksMTIuOWMtNy4xLDAtMTIuOS01LjgtMTIuOS0xMi45YzAtNy4xLDUuOC0xMi45LDEyLjktMTIu
OWgxMi45VjE1MS4yeiIvPgoJCTxwYXRoIGNsYXNzPSJzdDAiIGQ9Ik0xMDUuOSwxNTEuMmMwLTcuMSw1LjgtMTIuOSwxMi45LTEyLjlzMTIuOSw1LjgsMTIu
OSwxMi45djMyLjNjMCw3LjEtNS44LDEyLjktMTIuOSwxMi45CgkJCXMtMTIuOS01LjgtMTIuOS0xMi45VjE1MS4yeiIvPgoJPC9nPgoJPGc+CgkJPHBhdGgg
Y2xhc3M9InN0MSIgZD0iTTExOC44LDk5LjRjLTcuMSwwLTEyLjktNS44LTEyLjktMTIuOWMwLTcuMSw1LjgtMTIuOSwxMi45LTEyLjlzMTIuOSw1LjgsMTIu
OSwxMi45djEyLjlIMTE4Ljh6Ii8+CgkJPHBhdGggY2xhc3M9InN0MSIgZD0iTTExOC44LDEwNS45YzcuMSwwLDEyLjksNS44LDEyLjksMTIuOXMtNS44LDEy
LjktMTIuOSwxMi45SDg2LjVjLTcuMSwwLTEyLjktNS44LTEyLjktMTIuOQoJCQlzNS44LTEyLjksMTIuOS0xMi45SDExOC44eiIvPgoJPC9nPgoJPGc+CgkJ
PHBhdGggY2xhc3M9InN0MiIgZD0iTTE3MC42LDExOC44YzAtNy4xLDUuOC0xMi45LDEyLjktMTIuOWM3LjEsMCwxMi45LDUuOCwxMi45LDEyLjlzLTUuOCwx
Mi45LTEyLjksMTIuOWgtMTIuOVYxMTguOHoiLz4KCQk8cGF0aCBjbGFzcz0ic3QyIiBkPSJNMTY0LjEsMTE4LjhjMCw3LjEtNS44LDEyLjktMTIuOSwxMi45
Yy03LjEsMC0xMi45LTUuOC0xMi45LTEyLjlWODYuNWMwLTcuMSw1LjgtMTIuOSwxMi45LTEyLjkKCQkJYzcuMSwwLDEyLjksNS44LDEyLjksMTIuOVYxMTgu
OHoiLz4KCTwvZz4KCTxnPgoJCTxwYXRoIGNsYXNzPSJzdDMiIGQ9Ik0xNTEuMiwxNzAuNmM3LjEsMCwxMi45LDUuOCwxMi45LDEyLjljMCw3LjEtNS44LDEy
LjktMTIuOSwxMi45Yy03LjEsMC0xMi45LTUuOC0xMi45LTEyLjl2LTEyLjlIMTUxLjJ6Ii8+CgkJPHBhdGggY2xhc3M9InN0MyIgZD0iTTE1MS4yLDE2NC4x
Yy03LjEsMC0xMi45LTUuOC0xMi45LTEyLjljMC03LjEsNS44LTEyLjksMTIuOS0xMi45aDMyLjNjNy4xLDAsMTIuOSw1LjgsMTIuOSwxMi45CgkJCWMwLDcu
MS01LjgsMTIuOS0xMi45LDEyLjlIMTUxLjJ6Ii8+Cgk8L2c+CjwvZz4KPC9zdmc+Cg==
"""

if __name__ == "__main__":
    # replace the log with the root logger if running as main
    log = logging.getLogger()
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)

    main()
