# Looker OAA Connector

## Overview

OAA connector for Google Looker focusing on Looker Models and Connections. Discovers Looker users and groups and provides authorization
data for the Looker Models and database connections users can access based on their Looker roles.

### OAA Application Mappings

This connector uses the OAA Application template. The following table shows how Looker entities are mapped
to the template.

Looker     | OAA Application
---------- | -----------------
Users      |  Local User
Group      |  Local Group  
Role       |  Local Role
Model Set  |  Custom Resource `model_set`
Model      |  Custom Sub-resource `model` under `model_set`
Connection |  Custom sub-resource `connection` under `model`

### Attributes

Looker connector extracts the following attributes:

User:
  * `id` - Looker ID
  * `verified_looker_employee` - Boolean for user is identified as an employee of Looker who has been verified via Looker corporate authentication
  * `presumed_looker_employee` - Boolean for User is identified as an employee of Looker
  * `is_active` - Status of Looker account

Group:
  * `id` - Looker ID number

Model Set:
  * `id` - Looker ID number
  * `built_in` - Boolean for if model set is built in
  * `all_access` - Boolean if the model set is configured to include all models

Connection:
  * `dialect` - JDBC dialect connection is configured as
  * `host` - Database connection host
  * `username` - Database connection user name


## Setup
### Prerequisite
1. Generate a Looker API3 key for a user with sufficient privileges to see all users, roles and models.
2. Generate a Veza API key. See [Veza User Guide](https://app.gitbook.com/@veza.com/s/user-guide/interface-overview/administration/api-keys) for detailed instructions.

### Command Line
1. With Python 3.8+ install the requirements either into a virtual environment or otherwise:
    ```
    pip3 install -r requirements.txt
    ```

2. Export the Veza API keys and Looker connection information to the OS environment.

    ```
    export VEZA_API_KEY="XXXX...."
    export LOOKERSDK_BASE_URL="https://<customername>.cloud.looker.com"
    export LOOKERSDK_CLIENT_ID="XXXX...."  
    export LOOKERSDK_CLIENT_SECRET="XXXXX....."
    ```
3. Run the connector

    ```
    ./oaa_looker.py --veza-url https://<customer>.vezacloud.com
    ```

    Optionally export the Veza URL to the environment as `VEZA_URL` and run with no parameters required.
