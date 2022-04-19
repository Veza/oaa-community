# OAA connector for Zendesk

Python connector for discovering Zendesk users, groups and role assignments.

## Overview

This connector uses the Zendesk API to retrieve the lists of users and map out their group and role assignments. Zendesk uses a mix of built and custom roles. Built in roles need to be defined in the OAA connector code and will need to be maintained if there are changes in the Zendesk platform. Custom roles are retrieved through the API. OAA connector does not discover Zendesk end-user (customer) accounts.

### Generic Application Mappings

This connector uses the OAA Application template to map applications and identities to permissions. The following table shows how Custom Application entities correspond to Zendesk entities:

Zendesk         | Generic Application
----------------|--------------------
Zendesk Account | Application
User            | local user
Group           | local user
Role            | local role

### Attributes
Zendesk connector extracts the following attributes

User:
  * `created_at`
  * `last_login_at`
  * `is_active` - Boolean if account state, `false` if suspended
  * `id` - Zendesk ID for user
  * `display_name` - accounts display name if set
  * `role` - The user's simplified role type, "end-user", "agent", or "admin"

Group:
  * `id` - Zendesk ID for group
  * `description` - If group has description set

## Setup
### Zendesk Setup Instructions
1. Generate a Zendesk API key for a user with sufficient privileges to see all users. See [Zendesk Help ](https://support.zendesk.com/hc/en-us/articles/4408889192858-Generating-a-new-API-token) for complete steps.

### Veza Setup Instructions
1. Generate an API key for your Veza user. See [Veza User Guide](https://app.gitbook.com/@veza.com/s/user-guide/interface-overview/administration/api-keys) for detailed instructions.

### Command Line
1. With Python 3.8+ install the requirements either into a virtual environment or to the system:
  ```
  pip3 install -r requirements.txt
  ```

1. Set the Veza API key and Zendesk API key as environment variables. All other parameters can be passed as either environment variables or command line arguments.
  ```
  export VEZA_API_KEY=<Veza API key>
  export ZENDESK_API_KEY=<Zendesk API key>
  ```

1. Run the code, provide any parameters not exported as command line arguments:

   ```
   ./oaa_zendesk.py --zendesk-url <customer.zendesk.com> --zendesk-user <me@example.com> --veza-url <customer.vezacloud.com>
   ```

#### Parameters
Parameter        | Environment Variable Name | Value
-----------------| --------------------------|---------------------------------------------------------------
`--zendesk-url`  | `ZENDESK_URL`             | URL of Zendesk Account
`--zendesk-user` | `ZENDESK_USER`            | Username of the Zendesk account the API key was generated for  
`n/a`            | `ZENDESK_API_KEY`         | API key generated for Zendesk  
`--veza-url`   | `VEZA_URL`              | URL of Veza deployment  
`n/a`            | `VEZA_API_KEY`          | API key generated for Veza
`--verbose`      | `n/a`                     | Optional, enable verbose output and debug information  
`--save-json`    | `n/a`                     | Optional, save OAA payload to JSON file locally for debugging  
