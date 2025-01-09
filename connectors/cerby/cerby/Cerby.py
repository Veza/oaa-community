from .CerbyAPIClient import CerbyAPIClient
from .ApplicationStore import ApplicationStore
from .CerbyApplication import CerbyApplication


class Cerby:
    def __init__(self):
        self.client = CerbyAPIClient()
        self.application_store = ApplicationStore()
        self.users = {}
        self._load_users()
        self._load_applications()

    def _load_users(self):
        users_data = self.client.get_request("/api/v1/users")
        self._process_users(users_data)
        while users_data["links"]["next"]:
            users_data = self.client.get_request(users_data["links"]["next"])
            self._process_users(users_data)

    def _process_users(self, users_data):
        for user in users_data["data"]:
            user_id = user["id"]
            self.users[user_id] = {
                "id": user_id,
                "firstName": user["attributes"]["firstName"],
                "lastName": user["attributes"]["lastName"],
                "email": user["attributes"]["email"],
                "status": user["attributes"]["status"],
            }

    def _load_applications(self):
        app_data = self.client.get_request("/api/v1/accounts")
        self._process_applications(app_data)
        while app_data["links"]["next"]:
            app_data = self.client.get_request(app_data["links"]["next"])
            self._process_applications(app_data)

    def _process_applications(self, app_data):
        for account in app_data["data"]:
            account_id = account["id"]
            try:
                self.application_store.register_application(
                    app_name=account["attributes"]["application"], app_id=account_id
                )
                self._load_application_users(account_id)
            except Exception:
                self.application_store.unregister_application(account_id)

    def get_users(self):
        return self.users

    def get_user_by_id(self, user_id):
        return self.users[user_id]

    def get_applications(self):
        return self.application_store.list_applications()

    def get_application_by_id(self, app_id) -> CerbyApplication:
        return self.application_store.get_application(app_id)

    def get_application_users(self, app_id):
        return self.application_store.get_application(app_id).list_users()

    def _load_application_users(self, app_id):
        uri_path = f"/api/v1/integrations/{app_id}/users"
        cerby_application = self.get_application_by_id(app_id)
        try:
            app_user_data = self.client.get_request(uri_path)
            for app_user in app_user_data["data"]:
                cerby_application.add_user(
                    app_user["id"], attributes=app_user["attributes"], entitlements=None
                )
        except Exception:
            self.application_store.unregister_application(app_id)

    def __repr__(self):
        return f"Cerby(users={len(self.users)})"