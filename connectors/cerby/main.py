import argparse
import os
import logging
from veza.Veza import VezaClient
from cerby import Cerby

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_env_variables():
    """
    Retrieve and validate required environment variables.
    Returns a dictionary of environment variables if all are set, otherwise logs an error and returns None.
    """
    cerby_workspace = os.getenv("CERBY_WORKSPACE")
    cerby_api_key = os.getenv("CERBY_API_KEY")
    veza_api_key = os.getenv("VEZA_API_KEY")
    veza_url = os.getenv("VEZA_URL")

    if None in (cerby_workspace, cerby_api_key, veza_api_key, veza_url):
        logging.error("Missing required environment variables.")
        logging.error(
            "Please set CERBY_WORKSPACE, CERBY_API_KEY, VEZA_API_KEY, and VEZA_URL before running the script."
        )
        return None

    return {
        "cerby_workspace": cerby_workspace,
        "cerby_api_key": cerby_api_key,
        "veza_api_key": veza_api_key,
        "veza_url": veza_url
    }

def sync_users(cerby_client, veza_client):
    """
    Sync users from Cerby to Veza.
    """
    for user_id in cerby_client.get_users():
        user = cerby_client.get_user_by_id(user_id)
        display_name = "{} {}".format(user["firstName"], user["lastName"])
        veza_client.add_user(display_name, user["email"], user["id"])

def sync_applications(cerby_client, veza_client):
    """
    Sync applications from Cerby to Veza.
    """
    for application_id in cerby_client.get_applications():
        application = cerby_client.get_application_by_id(application_id)
        veza_client.add_resources(
            application.get_id(), application.get_name(), "account"
        )

def push_to_veza(veza_client):
    """
    Push all synchronized data to Veza.
    """
    veza_client.push_to_veza()

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Cerby to Veza CLI tool")
    parser.add_argument(
        "--sync-all", action="store_true", help="Sync users, applications, and permissions, then push to Veza"
    )
    parser.add_argument(
        "--sync-users", action="store_true", help="Sync users from Cerby to Veza"
    )
    parser.add_argument(
        "--sync-applications",
        action="store_true",
        help="Sync applications from Cerby to Veza",
    )
    parser.add_argument(
        "--push", action="store_true", help="Push all synchronized data to Veza"
    )
    args = parser.parse_args()

    # Retrieve and validate environment variables
    env_vars = get_env_variables()
    if env_vars is None:
        return

    # Initialize clients
    cerby_client = Cerby()
    veza_client = VezaClient()

    # Perform actions based on command-line arguments
    if args.sync_all:
        logging.info("Syncing all: users, applications, and permissions, then pushing to Veza...")
        sync_users(cerby_client, veza_client)
        sync_applications(cerby_client, veza_client)
        # TODO: Placeholder for permissions syncing; replace with actual logic if needed
        logging.info("Syncing permissions (not implemented in this script)...")
        push_to_veza(veza_client)

    elif args.sync_users:
        logging.info("Syncing users from Cerby to Veza...")
        sync_users(cerby_client, veza_client)

    elif args.sync_applications:
        logging.info("Syncing applications from Cerby to Veza...")
        sync_applications(cerby_client, veza_client)

    elif args.push:
        logging.info("Pushing data to Veza...")
        push_to_veza(veza_client)

    if not any([args.sync_users, args.sync_applications, args.push, args.sync_all]):
        parser.print_help()

if __name__ == "__main__":
    main()