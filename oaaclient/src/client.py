#!env python3
"""

Classes for calling Veza APIs and managing OAA providers and data sources.

Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

from datetime import datetime
from enum import Enum
from requests.exceptions import JSONDecodeError as RequestsJSONDecodeError
from typing import Union, List
import argparse
import base64
import gzip
import json
import logging
import os
import re
import requests
import sys

from oaaclient.templates import CustomApplication, CustomIdPProvider
import oaaclient.utils as oaautils

PROVIDER_ICON_MAX_SIZE = 64_000

log = logging.getLogger(__name__)

class OAAClientError(Exception):
    """Error raised by OAAClient.

    Raised for issues connecting to the OAA API and when the API returns an error.

    Args:
        error (str): short string for error message
        message (str): detailed error message
        status_code (int, optional): status code for HTTP related errors. Defaults to None.
        details (list, optional): list of additional details for error. Defaults to None.
    """

    def __init__(self, error: str, message:str , status_code: int = None, details: list = None) -> None:
        Exception.__init__(self, f"{error}: {message}")
        self.error = error
        self.message = message
        self.status_code = status_code
        if not details:
            self.details = []
        else:
            self.details = details


class OAAClient():
    """OAA API Connection and Management.

    Tools for making the API calls to Veza for OAA related operations. Manages Providers, Datasources and can push OAA
    payloads from JSON or template apps.

    Args:
        url (str): URL for Veza instance.
        api_key (str): Veza API key.
        username (str, optional): Not used (legacy). Defaults to None.
        token (str, optional): legacy parameter name for API key. Defaults to None.

    Attributes:
        url (str): URL of the Veza instance to connect to
        api_key (str): Veza API key
        enable_compression (bool): Enable/disable compression of the OAA payload during push, defaults to enabled (True)

    Raises:
        OAAClientError: For errors connecting to API and if API returns errors
    """
    def __init__(self, url:str, api_key: str = None, username: str = None, token: str = None):
        if not re.match(r"^https:\/\/.*", url):
            self.url = f"https://{url}"
        else:
            self.url = url
        self.url = self.url.rstrip("/")

        # for development purposes only sometimes system is run without signed certificates,
        # disable certificate verification only if VEZA_UNSAFE_HTTPS OS env variable is set to true
        self.verify_ssl = True
        unsafe_https = os.getenv("VEZA_UNSAFE_HTTPS", "")
        if unsafe_https.lower() == "true":
            self.verify_ssl = False

        self.username = username

        if api_key:
            self.api_key = api_key
        else:
            self.api_key = token

        if not self.url:
            raise OAAClientError("MISSING_URL", "URL cannot be None")
        if not self.api_key:
            raise OAAClientError("MISSING_AUTH", "API key cannot be None")

        # enable payload compression by default, connection object property can be set to False to disable
        self.enable_compression = True

        # test connection to validate host and credentials
        providers = self.get_provider_list()

    def get_provider_list(self) -> List[dict]:
        """Return list of Providers.

        Returns:
            list[dict]: Returns a list of existing Providers as dictionaries
        """
        providers = self.__perform_get("/api/v1/providers/custom")
        return providers['values']

    def get_provider(self, name: str) -> dict:
        """Get Provider by name.

        Args:
            name (str): name of Provider

        Returns:
            dict: dictionary representing Provider or None
        """
        providers = self.get_provider_list()
        provider = None
        for p in providers:
            if p["name"].lower() == name.lower():
                provider = p
                break

        return provider

    def get_provider_by_id(self, provider_id: str) -> dict:
        """Get provider by UUID identifier.

        Args:
            provider_id (str): Unique UUID identifier for provider

        Returns:
            dict: dictionary representation of Provider or None
        """
        try:
            response = self.__perform_get("/api/v1/providers/custom/{provider_id}")
        except OAAClientError as e:
            if e.response.status_code == 404:
                return None
            else:
                raise e

        return response

    def create_provider(self, name: str, custom_template: str, base64_icon: str = None) -> dict:
        """Create a new Provider.

        Creates a new Provider with the given name. An error will be raised in there is Provider naming conflict

        Args:
            name (str): new Provider name
            custom_template (str): the OAA template to use for the Provider (e.g. "application")
            base64_icon (str, optional): Base64 encoded string of icon to set for Provider. Defaults to None.

        Returns:
            dict: dictionary representing the created Provider
        """
        response = self.__perform_post("/api/v1/providers/custom", {"name": name, "custom_template": custom_template})
        provider = response['value']

        if base64_icon:
            self.update_provider_icon(provider['id'], base64_icon)

        return provider

    def update_provider_icon(self, provider_id: str, base64_icon: str) -> None:
        """ Update an existing provider's icon from base64 encoded string.

        To load icon from file use `utils.encode_icon_file` to get the base64 encoding of the file first

        Args:
            provider_id (str): unique ID of existing provider
            base64_icon (str): base64 encoded string of new icon

        Raises:
            ValueError: If icon size exceeds maximum allowed size

        """
        if sys.getsizeof(base64_icon) > PROVIDER_ICON_MAX_SIZE:
            raise ValueError("Max icon size of 64KB exceeded")

        if isinstance(base64_icon, bytes):
            base64_icon = base64_icon.decode()

        icon_payload = {"icon_base64": base64_icon}
        self.__perform_post(f"/api/v1/providers/custom/{provider_id}:icon", data=icon_payload)

        return None

    def delete_provider(self, provider_id: str) -> dict:
        """Delete an existing provider by ID.

        Deleting a provider will delete all its datasources and historical data. Deleting a provider is a background operation that will
        complete after API response is returned.

        Args:
            provider_id (str): ID of provider to delete

        Returns:
            dict: response from API
        """
        response = self.__perform_delete(f"/api/v1/providers/custom/{provider_id}")
        return response


    def get_data_sources(self, provider_id: str) -> List[dict]:
        """Get Data Sources for Provider by ID.

        Get the list of existing Data Sources, filtered by Provider UUID.

        Args:
            provider_id (str): ID of Provider
        Returns:
            list[dict]: List of Data Sources as dictionaries
        """
        response = self.__perform_get(f"/api/v1/providers/custom/{provider_id}/datasources")
        return response['values']

    def get_data_source(self, name:str, provider_id:str) -> dict:
        """Get Provider's Data Source by name.

        Find a Data Source from a specific provider based on the name of the Data Source

        Args:
            name (str): Data Source name
            provider_id (str): Provider unique ID

        Returns:
            dict: Data Source as dict or None
        """
        data_sources = self.get_data_sources(provider_id)
        data_source = None
        for d in data_sources:
            if d["name"].lower() == name.lower():
                data_source = d
                break

        return data_source

    def create_data_source(self, name: str, provider_id: str) -> dict:
        """Create a new Data Source for the given Provider ID.

        Args:
            name (str): Name for new Data Source
            provider_id (str): Unique identifier for the Provider

        Returns:
            dict: dictionary of new Data Source
        """
        datasource = self.__perform_post(f"/api/v1/providers/custom/{provider_id}/datasources", {"name": name, "id": provider_id})
        return datasource['value']

    def create_datasource(self, name, provider_id):
        """ Legacy function for backwards compatibility
        ..Deprecated::
        """
        return self.create_data_source(name, provider_id)

    def delete_data_source(self, data_source_id: str, provider_id: str) -> dict:
        """Delete existing Data Source by ID.

        Deleting a Data Source will delete all entity data from the Data Source

        Args:
            data_source_id (str): ID of Data Source to delete
            provider_id (str): ID of Provider for Data Source

        Returns:
            dict: API response
        """
        response = self.__perform_delete(f"/api/v1/providers/custom/{provider_id}/datasources/{data_source_id}")
        return response

    def push_metadata(self, provider_name: str, data_source_name: str, metadata: dict, save_json: bool = False) -> dict:
        """Push an OAA payload dictionary to Veza.

        Publishes the supplied `metadata` dictionary representing an OAA payload to the specified provider and
        data source. The function will create a new data source if it does not already exist, but requires the Provider to be
        created ahead of time.

        Optional flag `save_json` will write the payload to a local file before push for log or debug. Output file name
        will be a timestamped file of the format `{data source name}-{%Y%m%d-%H%M%S}.json`

        Args:
            provider_name (str): Name of existing Provider
            data_source_name (str): Name for Data Source, will be created if doesn't exist.
            metadata (dict): Dictionary of OAA payload to push.
            save_json (bool, optional): Save the OAA JSON payload to a local file before push. Defaults to False.

        Raises:
            OAAClientError: If any API call returns an error including errors processing the OAA payload.

        Returns:
            dict: API response from push including any warnings if returned.
        """

        provider = self.get_provider(provider_name)
        if not provider:
            raise OAAClientError("NO_PROVIDER", f"Unable to locate provider {provider_name}, cannot push without existing provider")
        data_source = self.get_data_source(data_source_name, provider["id"])
        if not data_source:
            self.create_datasource(data_source_name, provider["id"])
            data_source = self.get_data_source(data_source_name, provider["id"])

        if save_json:
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            out_name = f"{data_source_name}-{ts}.json"
            with open(out_name, "w") as f:
                f.write(json.dumps(metadata, indent=2))

        if self.enable_compression:
            log.debug("Compressing payload")
            metadata_bytes = json.dumps(metadata).encode()
            metadata_size = sys.getsizeof(metadata_bytes)
            compressed_bytes = gzip.compress(metadata_bytes)
            del metadata_bytes

            encoded = base64.b64encode(compressed_bytes).decode()
            encoded_size = sys.getsizeof(encoded)
            del compressed_bytes
            log.debug(f"Compression complete, payload size in bytes: {metadata_size:,}, encoded compressed: {encoded_size:,}")
            payload = {"id": provider["id"], "data_source_id": data_source["id"], "json_data": encoded, "compression_type": "GZIP"}
        else:
            payload = {"id": provider["id"], "data_source_id": data_source["id"], "json_data": json.dumps(metadata)}

        payload_size = sys.getsizeof(payload["json_data"])
        if payload_size > 100_000_000:
            raise OAAClientError("OVERSIZE", message=f"Payload size exceeds maximum size of 100MB: {payload_size:,} bytes, compression enabled: {self.enable_compression}")

        log.debug(f"Final payload size: {payload_size:,} bytes")
        result = self.__perform_post(f"/api/v1/providers/custom/{provider['id']}/datasources/{data_source['id']}:push", payload)

        return result

    def push_application(self, provider_name: str, data_source_name: str, application_object: Union[CustomApplication, CustomIdPProvider], save_json=False) -> dict:
        """Push an OAA Application Object (such as CustomApplication).

        Extract the OAA JSON payload from the supplied OAA class (e.g. CustomApplication, CustomIdPProvider) and push to
        the supplied Data Source.

        The Provider must be a valid Provider (created ahead of time). A new data source will be created
        if it does not already exist.

        Optional flag `save_json` will write the payload to a local file before push for log or debug. Output file name
        is formatted with a timestamp: `{data source name}-{%Y%m%d-%H%M%S}.json`

        Args:
            provider_name (str): Name of an existing Provider.
            data_source_name (str): Name for Data Source (will be created if it doesn't exist).
            application_object (Class): OAA object to extract the payload from
            save_json (bool, optional): Save the JSON payload to a local file before push. Defaults to False.

        Raises:
            OAAClientError: If any API call returns an error (including errors processing the OAA payload).

        Returns:
            dict: API response from push, including any warnings that are returned.
        """
        metadata = application_object.get_payload()
        return self.push_metadata(provider_name, data_source_name, metadata, save_json=save_json)

    def api_get(self, api_path: str) -> Union[list, dict]:
        """Perform Veza API GET operation.

        Call GET on supplied API path for the Veza instance and return the results. Results of API will either be list or
        dictionary depending on if the API destination.

        - For API endpoints that return a list like `/api/v1/providers/custom` function will return a list of entities or an
        empty list if the API returns no results.
        - For API endpoints that are a specific ID such as `/api/v1/providers/custom/<uuid>` function will return the
        dictionary result of the JSON returned by the API.

        Args:
            api_path (str): API path relative to Veza URL (example `/api/v1/providers`).

        Raises:
            OAAClientError: If API operation does not complete successfully

        Returns:
            Union[list, dict]: Returns list or dict based on API destination
        """
        return self.__perform_get(api_path)

    def __perform_get(self, api_path):
        headers = {"authorization": f"Bearer {self.api_key}"}

        api_path = api_path.lstrip("/")
        response = requests.get(f"{self.url}/{api_path}", headers=headers, timeout=60, verify=self.verify_ssl)
        if response.ok:
            return response.json()
        else:
            # TODO: handle non json response
            try:
                error = response.json()
            except RequestsJSONDecodeError:
                log.error("Unable to process API error response as JSON, raising generic response")
                raise OAAClientError("ERROR", response.reason, response.status_code)
            # process JSON response
            message = error.get("message", "Unknown error during GET")
            code = error.get("code", "UNKNOWN")
            raise OAAClientError(code, message, status_code=response.status_code, details=error.get("details", []))


    def api_post(self, api_path: str, data: dict) -> dict:
        """Perform Veza API POST operation.

        Call POST on the supplied Veza instance API path, including the data payload. The API response will be returned as
        dictionary.

        Args:
            api_path (str): API path relative to Veza URL example `/api/v1/providers`
            data (dict): dictionary object included as JSON in body of POST operation

        Raises:
            OAAClientError: If API operation does not complete successfully

        Returns:
            dict: API response as dictionary
        """
        return self.__perform_post(api_path, data)

    def __perform_post(self, api_path, data):
        if not isinstance(data, dict):
            raise OAAClientError("INVALID_DATA", "data must be dictionary type for post")

        headers = {"Authorization": f"Bearer {self.api_key}"}

        api_path = api_path.lstrip("/")
        response = requests.post(f"{self.url}/{api_path}", headers=headers, json=data, timeout=300, verify=self.verify_ssl)
        if response.ok:
            return response.json()
        else:
            try:
                error = response.json()
            except RequestsJSONDecodeError as e:
                log.error("Unable to process API error response as JSON, raising generic response")
                raise OAAClientError("ERROR", f"{response.reason} - {response.url}", status_code=response.status_code)
            # process JSON response
            message = error.get("message", "Unknown error during POST")
            code = error.get("code", "UNKNOWN")
            raise OAAClientError(code, message, status_code=response.status_code, details=error.get("details", []))



    def api_delete(self, api_path:str) -> dict:
        """Perform REST API DELETE operation.

        Args:
            api_path (str): API Path API path relative to Veza URL

        Returns:
            dict: API response from call
        """
        return self.__perform_delete(api_path)

    def __perform_delete(self, api_path: str) -> dict:

        headers = {"Authorization": f"Bearer {self.api_key}"}

        api_path = api_path.lstrip("/")
        response = requests.delete(f"{self.url}/{api_path}", headers=headers, timeout=60, verify=self.verify_ssl)
        if response.ok:
            return response.json()
        else:
            try:
                error = response.json()
            except RequestsJSONDecodeError:
                log.error("Unable to process API error response as JSON, raising generic response")
                raise OAAClientError("ERROR", f"{response.reason} - {response.url}", response.status_code)
            # process JSON response
            message = error.get("message", "Unknown error during DELETE")
            code = error.get("code", "UNKNOWN")
            raise OAAClientError(code, message, status_code=response.status_code, details=error.get("details", []))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--auth-file", help="Config file with authentication information")
    parser.add_argument("--host", help="URL endpoint for Veza Deployment")
    parser.add_argument("--user", help="Username to connect as")
    parser.add_argument("--provider", required=True, help="Provider definition json file, will create if doesn't exist")
    parser.add_argument("metadata", help="Metadata json file to push, uses name of file as datasource name")
    args = parser.parse_args()

    host = None
    user = None
    password = None
    token = None

    if args.auth_file:
        if not os.path.isfile(args.auth_file):
            print(f"Error: Unable to locate auth file {args.auth_file}", file=sys.stderr)
            sys.exit(1)
        auth_config = oaautils.load_json_from_file(args.auth_file)

        host = auth_config['host']
        user = auth_config['user']
        if "token" in auth_config:
            token = auth_config['token']
        elif "password" in auth_config:
            password = auth_config['password']
    else:
        host = args.host
        user = args.user

    provider_metadata = oaautils.load_json_from_file(args.provider)

    try:
        provider_name = provider_metadata["name"]
        custom_template = provider_metadata['custom_template']
    except KeyError as e:
        raise Exception(f"Missing value in app template: {e}")

    try:
        con = OAAClient(host, api_key=token)
        provider = con.get_provider(provider_name)
        if provider:
            print("-- Found existing provider")
        else:
            print(f"++ Creating Provider {provider_name} of type {custom_template}")
            provider = con.create_provider(provider_name, custom_template)
        print(f"-- Provider: {provider['name']} ({provider['id']})")
        # utilize the file name as the datasource name
        data_source_name = os.path.splitext(os.path.basename(args.metadata))[0]

        print("-- Pushing metadata")
        metadata = oaautils.load_json_from_file(args.metadata)
        response = con.push_metadata(provider_name, data_source_name, metadata)
        if response.get("warnings", None):
            print("-- Push succeeded with warnings:")
            for e in response["warnings"]:
                print(f"  - {e}")
    except OAAClientError as e:
        print(f"-- Error: {e.error}: {e.message} ({e.status_code})", file=sys.stderr)
        if hasattr(e, "details"):
            for d in e.details:
                print(f"  -- {json.dumps(d, indent=2)}")
    return


if __name__ == "__main__":
    main()
