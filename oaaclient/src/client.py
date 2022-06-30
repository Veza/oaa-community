#!env python3
from datetime import datetime
from enum import Enum
import argparse
import json
import os
import re
import requests
import sys


class OAAClientError(Exception):
    def __init__(self, error, message, status_code=None, details=[]):
        Exception.__init__(self, f"{error}: {message}")
        self.error = error
        self.message = message
        self.status_code = status_code
        self.details = details


class OAAClient():
    def __init__(self, url, api_key: str = None, username: str = None, token: str = None):
        if not re.match(r"^https:\/\/.*", url):
            self.url = f"https://{url}"
        else:
            self.url = url

        # for development purposes only sometimes system is run without signed certificates,
        # disable certificate verification only if OAA_UNSAFE_HTTPS OS env variable is set to true
        self.verify_ssl = True
        unsafe_https = os.getenv("VEZA_UNSAFE_HTTPS", "")
        if unsafe_https.lower() == "true":
            self.verify_ssl = False
        self.url.rstrip("/")

        self.username = username

        if api_key:
            self.api_key = api_key
        else:
            self.api_key = token

        if not self.url:
            raise OAAClientError("MISSING_URL", "URL cannot be None")
        if not self.api_key:
            raise OAAClientError("MISSING_AUTH", "API key cannot be None")

        # test connection to validate host and credentials
        providers = self.get_provider_list()

    def get_provider_list(self):
        ''' return list of provider dictionaries '''
        providers = self.__perform_get("/api/v1/providers/custom")
        return providers['values']

    def get_provider(self, name):
        ''' get single provider entry by name, returns dictionary '''
        providers = self.get_provider_list()
        provider = None
        for p in providers:
            if p["name"].lower() == name.lower():
                provider = p
                break

        return provider

    def create_provider(self, name, custom_template):
        ''' create a new provider, returns new provider dictionary returned by API '''
        provider = self.__perform_post("/api/v1/providers/custom", {"name": name, "custom_template": custom_template})
        return provider['value']

    def get_data_sources(self, provider_id):
        ''' returns list of datasources for a given provider ID, returns list of dictionary entries '''
        response = self.__perform_get(f"/api/v1/providers/custom/{provider_id}/datasources")
        return response['values']

    def get_data_source(self, name, provider_id):
        ''' get datasource by name for given provider ID, returns dictionary '''
        data_sources = self.get_data_sources(provider_id)
        data_source = None
        for d in data_sources:
            if d["name"].lower() == name.lower():
                data_source = d
                break

        return data_source

    def create_datasource(self, name, provider_id):
        ''' create a new datasource under given provider ID, returns dictionary from API '''
        datasource = self.__perform_post(f"/api/v1/providers/custom/{provider_id}/datasources", {"name": name, "id": provider_id})
        datasource['name'] = name
        return datasource

    def push_metadata(self, provider_name, data_source_name, metadata, save_json=False):
        """ Push a metadata update for custom application,
        Automatically gets provider ID and datasource ID from names.
        Provider must exists, will datasource dynamically if necessary.
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

        payload = {"id": provider["id"], "data_source_id": data_source["id"], "json_data": json.dumps(metadata)}
        result = self.__perform_post(f"/api/v1/providers/custom/{provider['id']}/datasources/{data_source['id']}:push", payload)

        return result

    def push_application(self, provider_name, data_source_name, application_object, save_json=False):
        """ Push a CustomApplication object to OAA API. Method handels seralizing the objection into the OAA JSON
        """
        metadata = application_object.get_payload()
        return self.push_metadata(provider_name, data_source_name, metadata, save_json=save_json)

    def api_get(self, api_path):
        return self.__perform_get(api_path)

    def __perform_get(self, api_path):
        ''' helper function to perfom authenticated API get '''
        headers = {"authorization": f"Bearer {self.api_key}"}

        api_path = api_path.lstrip("/")
        response = requests.get(f"{self.url}/{api_path}", headers=headers, timeout=10, verify=self.verify_ssl)
        if response.ok:
            return response.json()
        else:
            # TODO: handle non json response
            try:
                error = response.json()
                if "message" in error:
                    message = error['message']
                else:
                    message = "Unknown error in GET"
                if "code" in error:
                    code = error['code']
                else:
                    code = "UNKNOWN"
                raise OAAClientError(code, message, status_code=response.status_code)
            except json.decoder.JSONDecodeError:
                raise OAAClientError("ERROR", response.reason, response.status_code)

    def api_post(self, api_path, data):
        return self.__perform_post(api_path, data)

    def __perform_post(self, api_path, data):
        ''' helper function to perform authenticated API post '''
        if not isinstance(data, dict):
            raise OAAClientError("INVALID_DATA", "data must be dictionary type for post")

        headers = {"Authorization": f"Bearer {self.api_key}"}

        # headers['Content-Encoding'] = 'gzip'
        # headers['Content-Type'] = "application/javascript"
        #
        # data_gz = zlib.compress(json.dumps(data).encode('utf-8'))

        api_path = api_path.lstrip("/")
        response = requests.post(f"{self.url}/{api_path}", headers=headers, json=data, timeout=10, verify=self.verify_ssl)
        if response.ok:
            return response.json()
        else:
            try:
                error = response.json()
                if "message" in error:
                    message = error['message']
                else:
                    message = "Unknown error during POST"
                if "details" in error:
                    details = []
                    for e in error['details']:
                        details.append(e)
                raise OAAClientError(error['code'], message, status_code=response.status_code, details=details)
            except json.decoder.JSONDecodeError:
                raise OAAClientError("ERROR", f"{response.reason} - {response.url}", response.status_code)


##
# OAA uploader logic
##
def load_json_from_file(json_path):
    ''' Helper function to load a JSON form file since its done in multiple places '''
    try:
        with open(json_path) as f:
            data = json.load(f)
    except json.decoder.JSONDecodeError as e:
        raise Exception(f"Unable to process JSON from {json_path}: {e}")
    except OSError as e:
        raise Exception(f"Error reading file {json_path}: {e}")

    return data


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
        auth_config = load_json_from_file(args.auth_file)

        host = auth_config['host']
        user = auth_config['user']
        if "token" in auth_config:
            token = auth_config['token']
        elif "password" in auth_config:
            password = auth_config['password']
    else:
        host = args.host
        user = args.user

    provider_metadata = load_json_from_file(args.provider)

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
        metadata = load_json_from_file(args.metadata)
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
