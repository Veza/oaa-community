"""
helper functions commonly used by OAA integrations
"""


def log_arg_error(log: object, arg: str = None, env: str = None) -> None:
    """ helper function to generate consistent log messages when required parameter cannot be loaded """

    if arg and env:
        log.error(f"Unable to load required parameter, must supply {arg} or set OS environment variable {env}")
    elif arg and not env:
        log.error(f"Unable to load required parameter, must supply {arg}")
    elif env:
        log.error(f"Unable to load required parameter, must set OS environment variable {env}")
    else:
        raise Exception("Must provide arg or env to include in error message")
    return
