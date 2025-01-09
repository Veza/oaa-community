# Veza OAA Connector for Cerby

Python connector to query Cerby applications and users and push authorization data using the Open Authorization API.

- [Overview](#overview)
- [Setup and Installation](#setup-and-installation)
- [Running the Connector](#running-the-connector)
- [Notes](#notes)

## Overview

This connector utilizes the Cerby API to extract information about applications and users. The extracted metadata payload is then pushed to a Veza instance for parsing. Application permissions are mapped for each individual user.

### Custom Application Mappings

This connector uses the OAA Application template to map applications and identities to permissions. The following table shows how Custom Application entities correspond to Cerby entities:

| Cerby       | OAA Custom Application Template |
| ----------- |---------------------------------|
| application | Custom Resource                 |
| user        | Local User                      |

### Custom Properties

The following properties are set based on the Cerby properties:

| Entity     | Property       | Description                                      |
| ---------- | -------------- | ------------------------------------------------ |
| User       | `status`       | Status of the user (active/inactive)             |
| Application| `description`  | Description of the application                   |

## Setup and Installation

### Cerby Setup Instructions

You will need to create a Cerby API key to grant the OAA connector access to your Cerby instance and pull the necessary information.

1. Navigate to **Settings** > **API Keys** in your Cerby instance.
2. Click **Add New** and provide a name for the API key.
3. Copy the generated API key, which will only be shown once.

### Veza Setup Instructions

Generate a Veza user API key by navigating to **Administration** -> *API Keys*. Choose *Add New*. Give the key a name and copy the token, which will only be shown once.

## Running the Connector

Ensure pip is up-to-date, dependencies will fail to install unless pip >= 21.0. Install the requirements with Python 3.8+: 

```shell
pip3 install -r requirements.txt
```

Store the Cerby and Veza API keys as environment variables:

```shell
export CERBY_WORKSPACE=your_cerby_workspace
export CERBY_API_KEY=your_cerby_api_key
export VEZA_API_KEY=your_veza_api_key
export VEZA_URL=https://<your-org>.vezacloud.com
```

Run the connector:

```shell
./main.py --sync-all
```

### Parameters
| CLI Parameter  | Environment Variable | Description                                                                         |
| -------------- | -------------------- | ----------------------------------------------------------------------------------- |
| `--sync-all`   | n/a                  | Sync users, applications, and permissions, then push to Veza                        |
| `--sync-users` | n/a                  | Sync users from Cerby to Veza                                                       |
| `--sync-applications` | n/a           | Sync applications from Cerby to Veza                                                |
| `--push`       | n/a                  | Push all synchronized data to Veza                                                  |

## Notes
Once entities have been synchronized, call the `--push` command to push the data to Veza. This will create the necessary entities and relationships in the Veza instance.

### Cerby Endpoints Used

The connector calls the Cerby APIs:

* `/api/v1/users` - List of users
* `/api/v1/accounts` - List of applications

For more information, see the [Cerby API reference](https://docs.cerby.com/api).