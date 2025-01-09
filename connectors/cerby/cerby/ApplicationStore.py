from .CerbyApplication import CerbyApplication
import logging

class ApplicationStore:
    def __init__(self):
        self.applications = {}

    def register_application(self, app_name, app_id):
        if app_id in self.applications:
            logging.info(f"Application '{app_id}' already registered.")
        else:
            self.applications[app_id] = CerbyApplication(app_name, app_id)

    def unregister_application(self, app_id):
        self.applications.pop(app_id, None)

    def get_application(self, app_id) -> CerbyApplication:
        if app_id not in self.applications:
            raise ValueError(f"Application '{app_id}' is not registered.")

        return self.applications[app_id]

    def list_applications(self):
        return list(self.applications.keys())

    def __repr__(self):
        return f"ApplicationStore(applications={list(self.applications.keys())})"