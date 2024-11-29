import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class CerbyApplication:
    """
    Manages an application's users and their entitlements.
    """

    def __init__(self, name: str, id: str) -> None:
        self.name = name
        self.id = id
        self.users: Dict[str, Dict[str, List[str]]] = {}

    def add_user(self, user_id: str, attributes: Dict[str, str], entitlements: Optional[List[str]] = None) -> None:
        """
        Adds a user to the application.

        :param user_id: The ID of the user.
        :param attributes: A dictionary of user attributes.
        :param entitlements: A list of entitlements for the user.
        """
        self.users[user_id] = {
            "attributes": attributes,
            "entitlements": entitlements or [],
        }
        logger.info(f"User '{user_id}' added to '{self.name}' with attributes: {attributes} and entitlements: {entitlements}")

    def update_entitlements(self, user_id: str, entitlements: List[str]) -> None:
        """
        Updates the entitlements for a user.

        :param user_id: The ID of the user.
        :param entitlements: A list of new entitlements for the user.
        :raises KeyError: If the user is not found.
        """
        if user_id not in self.users:
            raise KeyError(f"User '{user_id}' not found in '{self.name}'.")
        self.users[user_id]["entitlements"] = entitlements
        logger.info(f"Updated entitlements for user '{user_id}' in '{self.name}': {entitlements}")

    def remove_user(self, user_id: str) -> None:
        """
        Removes a user from the application.

        :param user_id: The ID of the user.
        :raises KeyError: If the user is not found.
        """
        if user_id not in self.users:
            raise KeyError(f"User '{user_id}' not found in '{self.name}'.")
        del self.users[user_id]
        logger.info(f"User '{user_id}' removed from '{self.name}'.")

    def list_users(self) -> Dict[str, Dict[str, List[str]]]:
        """
        Lists all users in the application.

        :return: A dictionary of users.
        """
        return self.users

    def __repr__(self) -> str:
        return f"Application(name='{self.name}', id='{self.id}', users={len(self.users)})"

    def get_name(self) -> str:
        """
        Gets the name of the application.

        :return: The name of the application.
        """
        return self.name

    def get_id(self) -> str:
        """
        Gets the ID of the application.

        :return: The ID of the application.
        """
        return self.id