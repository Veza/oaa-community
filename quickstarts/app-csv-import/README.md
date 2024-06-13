# Example OAA Application from CSV Source

This sample application reads group, role, and user data from CSV files, and submits the data to the Veza Open Authorization API.

## Overview

This connector reads privilege data from CSV files and expects some column headers to be present in the source files.

## Source Files

This connector loads data from the following files:

|File Name              | Required / Optional | Description                                         |
|---------------------- |---------            |---------------------------------------------------- |
|`users.csv`            | Required            | The list of application users                       |
|`groups.csv`           | Optional            | The list of user group assignments                  |
|`roles.csv`            | Required            | The list of user/group role assignments             |
|`role_permissions.csv` | Optional            | The list of role permission assignments             |
|`permissions.csv`      | Optional            | The list of permissions defined by the application  |

### Users (users.csv)

Contains user account information - one user per line

|Column       | Required / Optional | Description                                                      |
|------------ |---------            |------------------------------------------------------------------|
|`user_name`  | Required            | The username of the user                                         |
|`created_at` | Optional            | The timestamp at which the user was created                      |
|`email`      | Optional            | The email address of the user                                    |
|`full_name`  | Optional            | The full name (given name + surname) of the user                 |
|`is_active`  | Optional            | Set to "true" or "false" to denote if the user account is active |
|`last_login` | Optional            | The timestamp of the user's last login                           |

### Groups (groups.csv)

Contains group information - one user group assignment per line

|Column       | Required / Optional | Description                                    |
|------------ |-------------------- |------------------------------------------------|
|`group_id`   | Required            | The ID / shortname of the group                |
|`user_name`  | Required            | The username of the user assigned to the group |
|`group_name` | Optional            | The full display name of the group             |

### Roles (roles.csv)

Contains role information - one assignment per line
Note: One or both of `group_id` and `user_name` must be present per-line

|Column       | Required / Optional     | Description          |
|------------ |------------------------ |--------------------- |
|`role_name`  | Required                | The name of the role |
|`group_id`   | See Above               | The id of the group  |
|`user_name`  | See Above               | The name of the user |

### Role Permissions (role_permissions.csv)

Contains role permission information - one role permission assignment per line

|Column        | Required / Optional | Description                         |
|------------  |---------            |------------------------------------ |
|`permission`  | Required            | The permission assigned to the role |
|`role_name`   | Required            | The name of the role                |

### Permissions (permissions.csv)

Maps application-defined permissions to Veza canonical permissions - one permission per line

|Column             | Required / Optional | Description                         |
|-----------------  |---------            |------------------------------------ |
|`permission`       | Required            | The permission name                 |
|`oaapermission`    | Required            | The Veza canonical permission name  |

Note: See [OAA Permission Types](#oaa-permission-types) for allowed `oaapermission` values

#### OAA Permission Types

| Type          | Description                                                                       |
|-------------- |---------------------------------------------------------------------------------- |
|DataRead       | The entity can read data from the application or resource                         |
|DataWrite      | The entity can create, write, or delete data from the application or resource     |
|MetadataRead   | The entity can read metadata from the application or resource                     |
|MetadataWrite  | The entity can create, write, or delete metadata from the application or resource |
|Nondata        | All other non data/metadata permissions                                           |

## Setup

## Veza Setup Instructions

This connector requires a valid Veza Push API token to interact with your Veza instance.

1. Generate an API token for your Veza user. For detailed instructions consult the Veza User Guide.

## Running the Connector
There are multiple options to run the connector. Instructions are included for running from the command line. 
These instructions could be adapted to AWS Lambda, GitHub actions and a variety of other platforms.

### Command Line
Ensure pip is up-to-date; dependencies will fail to install unless pip >= 21.0. 
Install the requirements with Python 3.8+: pip3 install -r requirements.txt

1. Export the appropriate environmental variables. Variables not set can be passed via arguments at run time.
```
export VEZA_API_KEY="Zdkemfds..."
```
1. Run the connector:

    `app_csv_import.py --veza-url https://example.vezatrial.ai` --application-name ExampleApp