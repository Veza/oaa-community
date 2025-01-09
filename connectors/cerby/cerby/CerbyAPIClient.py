import requests
import os
from .CerbyUser import CerbyUser

class CerbyAPIClient:
    def __init__(self):
        self.users = []
        self.applications = []
        self.base_url = f"https://{os.environ['CERBY_WORKSPACE']}.cerby.com"
        self.api_key = os.environ["CERBY_API_KEY"]
        self.headers = {"x-api-key": self.api_key}

    def get_users(self):
        return self.users

    def load_users(self):
        user_response = self.get_request("/users")
        for user in user_response:
            self.users.append(CerbyUser(
                id=user["id"],
                first_name=user["attributes"]["firstName"],
                last_name=user["attributes"]["lastName"],
                email=user["attributes"]["email"]
            ))

    def get_applications(self):
        return self.applications

    def get_request(self, path):
        response = requests.get(f"{self.base_url}{path}", headers=self.headers)
        response.raise_for_status()
        return response.json()

    def post_request(self, url, body):
        response = requests.post(url, data=body)
        response.raise_for_status()
        return response.json()