"""

`oaaclient` utility functions.

Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.

helper functions commonly used by OAA integrations
"""
import base64
import json
import os


def log_arg_error(log: object, arg: str = None, env: str = None) -> None:
    """Helper function for logging errors when loading parameters

    Helper function used to create consistent messages in connectors when required parameters can be set at command
    line or as environment variables.

    Message can include information on parameter and/or environment variable but must provide one.

    Args:
        log (object): logging facility object to log to
        arg (str, optional): Command line option for parameter such as `--veza-url`. Defaults to None.
        env (str, optional): OS Environment variable for parameter such as `VEZA_URL`. Defaults to None.

    Raises:
        Exception: if neither `arg` or `env` are supplied
    """

    if arg and env:
        log.error(f"Unable to load required parameter, must supply {arg} or set OS environment variable {env}")
    elif arg and not env:
        log.error(f"Unable to load required parameter, must supply {arg}")
    elif env:
        log.error(f"Unable to load required parameter, must set OS environment variable {env}")
    else:
        raise Exception("Must provide arg or env to include in error message")
    return


def load_json_from_file(json_path: str) -> dict:
    """Load JSON from file

    Args:
        json_path (str): path to JSON file on disk

    Raises:
        Exception: Unable to process JSON
        Exception: Error reading JSON file

    Returns:
        dict: JSON decoded to dictionary
    """
    try:
        with open(json_path) as f:
            data = json.load(f)
    except json.decoder.JSONDecodeError as e:
        raise Exception(f"Unable to process JSON from {json_path}: {e}")
    except OSError as e:
        raise Exception(f"Error reading file {json_path}: {e}")

    return data

def encode_icon_file(icon_path: str) -> str:
    """ read an icon file to a base64 encoded string

    Args:
        icon_path (str): Path to icon file on disk

    Returns:
        str: base64 encoding of file
    """

    with open(icon_path, "rb") as f:
        b64_icon = base64.b64encode(f.read())

    return b64_icon.decode()
