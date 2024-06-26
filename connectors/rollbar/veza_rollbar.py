#!/usr/bin/env python3
"""
Copyright 2023 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""
from __future__ import annotations

import argparse
import logging
import os
import json
import re
import sys
import time

import oaaclient.utils as oaautils
import requests
from datetime import datetime
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, CustomResource, LocalGroup, LocalRole, LocalUser, OAAPermission, OAAPropertyType
from requests.exceptions import RequestException

logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)


class VezaRollbarConnector():

    MAX_API_RETRIES = 5

    def __init__(self, auth_token: str) -> None:
        self.auth_token = auth_token
        self.unique_identifier = None
        self.base_url = "https://api.rollbar.com/api/1"

        self.app = CustomApplication("Rollbar.com", application_type="Rollbar")

        self._property_definitions()

    def _property_definitions(self):
        """
        Property Definitions for Local Users, Local Groups, Custom Resource.
        """
        # Define OAA properties for local users
        self.app.property_definitions.define_local_user_property("email", OAAPropertyType.STRING)

        # Define OAA properties for local groups
        self.app.property_definitions.define_local_group_property("access_level", OAAPropertyType.STRING)

        # Define OAA properties for custom resource
        self.app.property_definitions.define_resource_property("Project", "status", OAAPropertyType.STRING)
        self.app.property_definitions.define_resource_property("Project", "created_at", OAAPropertyType.TIMESTAMP)
        self.app.property_definitions.define_resource_property("Project", "modified_at", OAAPropertyType.TIMESTAMP)

    def permission_mapper(self, name: str) -> list:
        """
        Created this mapper using https://docs.rollbar.com/docs/users-teams-accounts provided by Rollbar
        """
        permissions = {
            "owner": [
                OAAPermission.DataCreate, OAAPermission.DataDelete, OAAPermission.DataRead,
                OAAPermission.DataWrite, OAAPermission.MetadataCreate, OAAPermission.MetadataDelete,
                OAAPermission.MetadataRead, OAAPermission.MetadataWrite, OAAPermission.NonData
            ],
            "standard": [
                OAAPermission.DataCreate, OAAPermission.DataDelete, OAAPermission.DataRead,
                OAAPermission.DataWrite, OAAPermission.MetadataCreate, OAAPermission.MetadataDelete,
                OAAPermission.MetadataRead, OAAPermission.MetadataWrite, OAAPermission.NonData
            ],
            "light": [
                OAAPermission.DataRead, OAAPermission.DataWrite, OAAPermission.MetadataRead, OAAPermission.MetadataWrite
            ],
            "view": [OAAPermission.DataRead, OAAPermission.MetadataRead]
        }
        return permissions.get(name, [OAAPermission.Uncategorized])

    def discover(self) -> None:
        """Discovery method"""
        log.info("Start App discovery")
        self._discover_users()
        self._discover_projects()
        self._discover_teams()
        log.info("Finished App discovery")

    def _discover_users(self) -> None:
        log.info("Start user discovery")
        user_resp = self.rollbar_api_get("users")
        for user_data in user_resp.get("result", {}).get("users", []):
            email = user_data.get("email")
            users: LocalUser = self.app.add_local_user(name=user_data.get("username"), identities=[], unique_id=user_data.get("id"))
            if email:
                users.add_identities([email])
            users.set_property("email", email)
        log.info("Finished user discovery")

    def _assign_projects_to_team(self, team: LocalGroup, role: LocalRole) -> None:
        team_projects_resp = self.rollbar_api_get(f"team/{team.unique_id}/projects")
        resources_list = []
        for project in team_projects_resp.get("result", []):
            if project.get("project_id") in self.app.resources:
                resources_list.append(self.app.resources[project.get("project_id")])
        team.add_role(role.unique_id, resources=resources_list)

    def _assign_users_to_team(self, team: LocalGroup) -> None:
        team_users_resp = self.rollbar_api_get(f"team/{team.unique_id}/users")
        for user_data in team_users_resp.get("result", []):
            if user_data.get("user_id") in self.app.local_users:
                user: LocalUser = self.app.local_users[user_data.get("user_id")]
                user.add_group(team.unique_id)

    def _discover_teams(self) -> None:
        log.info("Start role discovery")
        teams_resp = self.rollbar_api_get("teams")
        for team_data in teams_resp.get("result", []):
            team: LocalGroup = self.app.add_local_group(name=team_data.get("name"), unique_id=team_data.get("id"))
            role_name = team_data.get("access_level")
            team.set_property("access_level", role_name)
            role: None | LocalRole = None
            if role_name not in self.app.local_roles:
                self.app.add_custom_permission(role_name, permissions=self.permission_mapper(role_name))
                role = self.app.add_local_role(
                    name=role_name,
                    permissions=[role_name],
                    unique_id=role_name
                )
            else:
                role = self.app.local_roles[team_data.get("access_level")]
            self._assign_projects_to_team(team, role)
            self._assign_users_to_team(team)
            if self.unique_identifier is None:
                self.unique_identifier = team_data.get("account_id")
        log.info("Finished role discovery")

    def _discover_projects(self) -> None:
        log.info("Start project discovery")
        projects_resp = self.rollbar_api_get("projects")
        for project_data in projects_resp.get("result"):
            project: CustomResource = self.app.add_resource(name=project_data.get("name"), resource_type="Project", unique_id=project_data.get("id"))
            project.set_property("status", project_data.get("status"))
            project.set_property("created_at", f"{datetime.utcfromtimestamp(project_data.get('date_created')).isoformat()}Z")
            project.set_property("modified_at", f"{datetime.utcfromtimestamp(project_data.get('date_modified')).isoformat()}Z")
        log.info("Finished project discovery")

    def rollbar_api_get(self, path: str, parameters=None) -> list | dict:
        """ Function to send GET request to rollbar api and handling API exceptions and 429 status code.

        Args:
            path (str): _description_
            parameters (_type_, optional): _description_. Defaults to None.

        Raises:
            RequestException: _description_

        Returns:
            list|dict: _description_
        """
        if re.match(r"^https?:\/\/.*", path):
            url = path
        else:
            path = path.lstrip("/")
            url = f"{self.base_url}/{path}"

        if parameters is None:
            parameters = {}

        result = []
        log.debug(f"Performing %Application% API call: {url}, parameters={parameters}")

        headers = {
            "X-Rollbar-Access-Token": self.auth_token
        }
        body = self._perform_get(
            url=url,
            params=parameters,
            headers=headers
        )

        if "results" in body:
            result.extend(body["results"])
        else:
            result = body

        return result

    def _perform_get(self, *args, **kwargs) -> dict | list:

        if "timeout" not in kwargs:
            kwargs["timeout"] = 60

        try_count = 0
        while True:
            try_count += 1
            try:
                response = requests.get(*args, **kwargs)
                response.raise_for_status()
                return response.json()
            except requests.exceptions.HTTPError as e:
                if try_count >= self.MAX_API_RETRIES:
                    raise e

                if e.response.status_code not in [429, 500, 502, 503, 504]:
                    # not a retriable error
                    raise e

                log.warning(f"%Application% API response error, {e}")
                log.warning(f"Retrying {try_count} of {self.MAX_API_RETRIES}")

                # set default sleep time
                sleep_time = try_count * 1

                ratelimit_remaining = e.response.headers.get("X-Rate-Limit-Remaining", None)
                ratelimit_reset = e.response.headers.get("X-Rate-Limit-Reset", None)

                if ratelimit_remaining and ratelimit_reset:
                    try:
                        ratelimit_remaining = int(ratelimit_remaining)
                        retry_reset_time = datetime.utcfromtimestamp(int(ratelimit_reset))
                        utcnow = datetime.utcnow()
                        if e.response.status_code == 429 or ratelimit_remaining < 1:
                            log.warning(f"Rate limit exceeded, reset after {retry_reset_time}")
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
                if try_count >= self.MAX_API_RETRIES:
                    raise e

                # connection errors
                log.warning(f"%Application% API connection error, {e}")
                log.warning(f"Retrying {try_count} of {self.MAX_API_RETRIES}")
                time.sleep(try_count * 1)

            except requests.exceptions.JSONDecodeError as e:
                log.error("Unable to decode JSON response")
                if e.response:
                    log.debug(e.response.text)
                raise e
            except requests.exceptions.RequestException as e:
                # any other type of requests error
                raise e


def run(veza_url: str, veza_api_key: str, rollbar_access_token: str, **config_args) -> None:

    create_report = config_args.get("create_report")

    # Process any configuration arguments
    if config_args.get("debug"):
        log.setLevel(logging.DEBUG)
        logging.getLogger("urllib3").setLevel(logging.INFO)
        log.info("Enabling debug logging")
    else:
        log.setLevel(logging.INFO)

    save_json = config_args.get("save_json", False)
    if not isinstance(save_json, bool):
        raise TypeError("save_json argument must be boolean")

    # Connect to the Veza instance before discovery to validate that the credentials are valid
    try:
        conn = OAAClient(url=veza_url, api_key=veza_api_key)
    except OAAClientError as error:
        log.error(f"Unable to connect to Veza {veza_url}")
        log.error(error.message)
        raise error  # run function should raise any exception so that they can be handled by the parent code, never exit

    # Initialize the connector class and run discovery
    try:
        app = VezaRollbarConnector(auth_token=rollbar_access_token)
        app.discover()
    except RequestException as e:
        log.error("Error during discovery")
        log.error(f"{e} - {e.response.status_code} {e.response.text}")
        raise e

    # After discovery is complete, setup the Provide and Data Source to push the data too
    provider_name = "Rollbar"
    provider = conn.get_provider(provider_name)

    if provider:
        log.info("found existing provider")
    else:
        log.info(f"creating provider {provider_name}")
        provider = conn.create_provider(provider_name, "application", base64_icon=APP_SVG_B64)
        create_report = True
    log.info(f"provider: {provider['name']} ({provider['id']})")

    data_source_name = f"Rollbar - {app.unique_identifier}"

    try:
        log.info("uploading custom application data")
        response = conn.push_application(provider_name,
                                         data_source_name=data_source_name,
                                         application_object=app.app,
                                         save_json=save_json
                                         )
        # An OAA Push can succeed with warnings, you can log out the warnings
        if response.get("warnings", None):
            log.warning("Push succeeded with warnings:")
            for e in response["warnings"]:
                log.warning(e)
        log.info("success")
    except OAAClientError as error:
        # if there is an issue with the OAA payload the error details should contain useful information that will help in resolving the issue
        log.error(f"{error.error}: {error.message} ({error.status_code})")
        if hasattr(error, "details"):
            for detail in error.details:
                log.error(f"  {detail}")
        raise error

    if create_report:
        report_source_file = "report-rollbar-security.json"
        if os.path.isfile(report_source_file):
            log.info(f"Creating or updating report from {report_source_file}")
            with open(report_source_file) as f:
                report_definition = json.load(f)
            response = oaautils.build_report(conn, report_definition)
            report_id = response.get("id")
            if report_id:
                log.info(f"Report available at: {veza_url}/app/reports/{report_id}, Veza may still be populating report data")
            else:
                log.error("Report creation did not return ID")
                log.info(json.dumps(response))
        else:
            log.warning(f"Unable to create report, cannot locate source file {report_source_file}")


APP_SVG_B64 = """
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
"""


def main():
    """
    process command line and OS environment variables, then call `run`
    """
    parser = argparse.ArgumentParser(description="OAA Connector")
    parser.add_argument("--veza-url", default=os.getenv("VEZA_URL"), help="the URL of the Veza instance")
    parser.add_argument("--debug", action="store_true", help="Set the log level to debug")
    parser.add_argument("--save-json", action="store_true", help="Save OAA JSON payload to file")
    parser.add_argument("--create-report", action="store_true", help="Create/update a Veza Report with common Queries. Defaults to true for first discovery.")
    args = parser.parse_args()

    # Secrets should only be passed in through ENV
    veza_api_key = os.getenv("VEZA_API_KEY")
    rollbar_access_token = os.getenv("ROLLBAR_ACCESS_TOKEN")
    veza_url = args.veza_url
    save_json = args.save_json

    if not veza_api_key:
        oaautils.log_arg_error(log, None, "VEZA_API_KEY")
    if not rollbar_access_token:
        oaautils.log_arg_error(log, None, "ROLLBAR_ACCESS_TOKEN")
    if not veza_url:
        oaautils.log_arg_error(log, "--veza-url", "VEZA_URL")

    # ensure required variables are provided
    if None in [veza_api_key, rollbar_access_token, veza_url]:
        log.error("missing one or more required parameters")
        sys.exit(1)

    try:
        run(veza_url=veza_url, veza_api_key=veza_api_key, rollbar_access_token=rollbar_access_token, save_json=save_json, debug=args.debug, create_report=args.create_report)
    except (OAAClientError, RequestException):
        log.error("Exiting with error")
        sys.exit(1)


if __name__ == "__main__":
    # replace the log with the root logger if running as main
    log = logging.getLogger()
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)

    main()
