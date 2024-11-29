import os
import sys
import logging
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, OAAPermission

class VezaClient:
    def __init__(
        self, application_name="FullCerbyIntegration", application_type="integration"
    ):
        """
        Initializes the Cerby Integration instance and sets up the Veza API connection.
        """
        self.veza_api_key = os.getenv("VEZA_API_KEY")
        self.veza_url = os.getenv("VEZA_URL")

        if None in (self.veza_api_key, self.veza_url):
            raise EnvironmentError(
                "Missing required environment variables: VEZA_API_KEY or VEZA_URL"
            )

        self.client = OAAClient(url=self.veza_url, api_key=self.veza_api_key)
        self.integration = CustomApplication(
            name=application_name, application_type=application_type
        )

        self.applications = {}
        self.app_ids = []

    def define_permissions(self):
        """
        Defines permissions for the custom integration.
        """
        self.integration.add_custom_permission(
            "admin", [OAAPermission.DataRead, OAAPermission.DataWrite]
        )
        self.integration.add_custom_permission("operator", [OAAPermission.DataRead])

    def add_resources(self, app_id, app_name, app_type):
        self.applications[app_id] = self.integration.add_resource(
            name=app_name,
            resource_type=app_type,
            description=app_name,
            unique_id=app_id,
        )

    def persist_app_id(self, app_id):
        self.app_ids.append(app_id)

    def add_user(self, display_name, email, user_id):
        self.integration.add_local_user(
            display_name, identities=email, unique_id=user_id
        )

    def add_group(self, group_name):
        self.integration.add_local_group(group_name)

    def add_user_to_group(self, username, group_name):
        self.integration.local_users[username].add_group(group_name)

    def add_permission_to_application(self, username, permission, application_id):
        application_target = self.applications[application_id]
        self.integration.local_users[username].add_permission(
            permission=permission,
            resources=[application_target],
        )

    def push_to_veza(self):
        """
        Pushes the application to Veza.
        """
        provider_name = "Cerby"
        provider = self.client.get_provider(provider_name)
        if provider:
            logging.info("-- Found existing provider")
        else:
            logging.info(f"++ Creating Provider {provider_name}")
            provider = self.client.create_provider(provider_name, "application")
        logging.info(f"-- Provider: {provider['name']} ({provider['id']})")

        try:
            response = self.client.push_application(
                provider_name,
                data_source_name=f"{self.integration.name} ({self.integration.application_type})",
                application_object=self.integration,
            )
            if response.get("warnings", None):
                logging.warning("-- Push succeeded with warnings:")
                for e in response["warnings"]:
                    logging.warning(f"  - {e}")
        except OAAClientError as e:
            logging.error(
                f"-- Error: {e.error}: {e.message} ({e.status_code})", file=sys.stderr
            )
            if hasattr(e, "details"):
                for d in e.details:
                    logging.error(f"  -- {d}", file=sys.stderr)

    def get_resources(self):
        return self.integration.app_dict()