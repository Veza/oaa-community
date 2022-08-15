# OAA Connector for Salesforce Lightning

## Overview

### Generic Application Mappings
This connector uses the OAA Application template to map applications and identities to permissions.
The following table shows how Custom Application entities correspond to Salesforce.com entities:

| Salesforce.com        | Generic Application  |
| --------------------- | -------------------- |
| instance              | application          |
| object type           | application resource |
| permissions set       | local group          |
| permissions set group | local group          |
| user                  | local user           |

### Limitations
This connector iterates object types and permissions sets to determine user access levels.
It does **not** attempt to iterate individual items and discover manually set permissions on those objects.

* Discovery is limited to object types and does not iterate individual objects
* Discovery does not include salesforce user profiles
* Profile-based permissions sets are displayed as permissions granted directly to the user whose profile granted them

## Setup
### Salesforce.com Prerequisites

This connector connects to the Salesforce Lightning API initially using the username-password authentication flow.

Subsequent requests after this initial connection are made using the OAuth2 token retrieved after initial login.

* First, ensure that the account that will be used with this application is enabled for API access.
If an appropriate user and Permissions Set with API access enabled already exist, skip to **Create a Connected App**

### Create a New User for API Access
* In a browser, navigate to the **Setup** section in Salesforce with an administrative account
* In the left-hand navigation pane, under the **ADMINISTRATION** heading, expand **Users** and click **Users** below it
* At the top of the **Users** table, click **New User** to create a new user
* Fill in appropriate details for the user account:
  * **Profile**: Read Only

### Create an API Access Permissions Set
* In a browser, navigate to the **Setup** section in Salesforce with an administrative account
* In the left-hand navigation pane, under the **ADMINISTRATION** heading, expand **Users** and click **Permissions Sets**
* <find one>
* At the top-left hand of the **Permissions Sets** table, click **New** to create a new Permissions Set
  * Provide a **Label** and optional **Description**
  * The **API Name** field will be automatically populated by the **Label** category but can be overridden if needed
  * Leave the **License** dropdown field set to **--None--**
  * Click **Save** to create the Permissions Set
* On the resulting Permissions Set overview page, click **System Permissions**
* Click **Edit** on the resulting page, then check the following fields:
  * **API Enabled**: this enables access to the Salesforce.com API
  * **View All Profiles**: required to gather user information
  * **View ALL Users**: required to gather user information
* At the top of the main pane, click **Save**
* Once returned to the **Permissions Sets** table, locate the newly created Permissions Set and click it
* In the details view, click **Manage Assignments** at the top of the main pane
* Click **Add Assignments** at the top of the screen
* Locate the user that will make API calls to the Salesforce endpoint, click the checkbox next to the account, then click **Assign** at the top of the table
* Click **Done**

### Create a Connected App
* In a browser, navigate to the **Setup** section in Salesforce with an administrative account
* In the left-hand navigation pane, under the **PLATFORM TOOLS** heading, expand **Apps**, then click **App Manager**
* At the top-right corner of the main pane, click **New Connected App**
  * Under the **Basic Information** heading, complete the following:
    * **Connected App Name**: a unique name for the application (ex: Salesforce OAA)
    * **API Name**: this will be automatically populated by the field above but can be overridden
  * Under the **API (Enable OAauth Settings)** header, click the checkbox to **Enable OAuth Settings**
    * In the **Callback URL** field, enter `https://localhost`
    * In the **Selected OAuth Scopes** field, click **Full access (full)** then click **>** to add it to the selected scopes
  * Click **Save** at the bottom of the page
  * Click **Continue** to confirm the creation of the new Connected App
* From the **Setup** page, in the left-hand navigation pane, under the **PLATFORM TOOLS** heading, expand **Apps**, then click **App Manager**
* Locate the newly created Connected App, click the drop-down arrow next to its name, then click **View**
* Copy the **Consumer Key** and **Consumer Secret**

### Allow Network Access
* In a browser, navigate to the **Setup** section in Salesforce with an administrative account
* In the left-hand navigation pane, under the **SETTINGS** heading, expand **Security**, then click **Network Access**
* Ensure that the public IP address of the computer that will run this application is included in the trusted IP ranges.
* If it is not:
  * At the top of the table in the main pane, click **New**
  * Enter the public IP address of the computer as both the **Start IP Address** and **End IP Address**
  * Enter a description that denotes that this is in use for the Salesforce OAA application
  * Click **Save**

### Veza Prerequisites
1. Generate an [API key](https://docs.veza.com/api/authentication) for your Veza user.

### Command Line
1. Ensure `pip` is up-to-date; dependencies will fail to install unless `pip >= 21.0`
2. With Python 3.8+, install the application requirements either into a virtual environment or globally:
   ```
   pip3 install -r requirements.txt
   ```
3. Set environmental variables required for Veza and Salesforce.com access:

   Mac, Linux
   ```
   export VEZA_API_KEY="<veza_api_key>"
   export SFDC_CLIENT_ID="<sfdc_client_id>"
   export SFDC_CLIENT_SECRET="<sfdc_client_secret>"
   export SFDC_PASSWORD="<sfdc_password>"
   ```

   Windows CMD
   ```
   set VEZA_API_KEY=<veza_api_key>
   set SFDC_CLIENT_ID=<sfdc_client_id>
   set SFDC_CLIENT_SECRET=<sfdc_client_secret>
   set SFDC_PASSWORD=<sfdc_password>
   ```

4. Run the application:
   Mac, Linux
   ```
   ./oaa_salesforce.py --veza-url <veza_url> --sfdc-user <sfdc_user>
   ```

   Windows
   ```
   python oaa_salesforce.py --veza-url <veza_url> --sfdc-user <sfdc_user>
   ```

   Depending on how Python is instealled in the Windows environment the command may be `python3` or `py`


   Optionally, all parameters can be passed via OS environmental variables. For example on a Mac/Linux machine:
   ```
   export VEZA_API_KEY="<veza_api_key>"
   export VEZA_URL="<veza_url>"
   export SFDC_CLIENT_ID="<sfdc_client_id>"
   export SFDC_CLIENT_SECRET="<sfdc_client_secret>"
   export SFDC_USER="<sfdc_user>"
   export SFDC_PASSWORD="<sfdc_password>"
   ./oaa_salesforce.py
   ```

### Parameters
| CLI Parameter      | Environment Variable | Description                                                                         |
| ------------------ | -------------------- | ----------------------------------------------------------------------------------- |
| `--veza-url`       | `VEZA_URL`           | URL of Veza system                                                                  |
|                    | `VEZA_API_KEY`       | API key for Veza connection                                                         |
| `--sfdc-client-id` | `SFDC_CLIENT_ID`     | Client ID configured for Salesforce Connected App                                   |
|                    | `SFDC_CLIENT_SECRET` | Secret key for Connected App                                                        |
| `--sfdc-user`      | `SFDC_USER`          | Salesforce username for connection                                                  |
|                    | `SFDC_PASSWORD`      | Salesforce user password                                                            |
| `--filter-objects` |                      | Optional list of Salesforce object types to limit discovery too separated by spaces |
| `--all-users`      |                      | Discover all Salesforce users, default to only `standard` users                     |
| `--debug`          |                      | Enable verbose debug output                                                         |
| `--save-json`      |                      | Save OAA Payload as local JSON file before upload                                   |