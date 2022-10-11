# OAA Slack Connector

Enables Veza to show Slack Users who are a member of the Workspace, and their workspace roles. Supports Slack free, Pro and Business+ plans.

The connector provides insight into the users that are part of your Slack Workspace including guest users (single and multi channel), can correlate Slack
users with corporate identities such as Okta and AzureAD.

For organizations that do not use Single Sign On to Slack the connector can validate that users have enabled two-factor authentication on their accounts.

### Custom Application Mappings

| Slack      | Veza                 |
| ---------- | -------------------- |
| Workspace  | Application Instance |
| User       | Local User           |
| User Group | Local Group          |


### Properties
The following properties are collected:

| Entity | Property              | Description                                                                                                            |
| ------ | --------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| User   | `slack_name`          | User's `real_name_normalized` property                                                                                 |
| User   | `email`               | User's email if available                                                                                              |
| User   | `has_mfa`             | Describes whether two-factor authentication is enabled for this user. Does not apply to users who sign in through SSO. |
| User   | `is_restricted`       | Indicates whether or not the user is a guest user.                                                                     |
| User   | `is_ultra_restricted` | Indicates whether or not the user is a single-channel guest.                                                           |
| User   | `bot_id`              | Bot ID for Bot Users                                                                                                   |
| Group  | `is_deleted`          | True if User Group is deleted                                                                                          |

## Setup

### Slack Setup Instruction

Slack authentication is performed through creating a Slack App and granting the necessary `read` scopes to the application.

1. [Create a new App for your Slack Workspace](https://api.slack.com/authentication/basics)
2. Under **Oauth & Permissions** in the new app add the following **User Token Scopes**
    - `teams:read`
    - `usergroups:read`
    - `users.profile:read`
    - `users:read`
    - `users:read.email`
3. Copy the **OAuth Tokens for Your Workspace**, it should start `xoxp-`
4. Install the App into your Workspace

### Veza Setup Instructions

1. Generate a Veza user API key by navigating to **Administration** -> *API Keys*. Choose *Add New*. Give the key a name and copy the token, which will only be shown once.

## Running the Connector

### Command Line
1. Install the requirements `pip3 install -r requirements.txt`
2. Set the secrets:

   ```shell
   export SLACK_TOKEN="xoxp-XXXXXXXXX"
   export VEZA_API_KEY="ZXldTcj...JCWGU3Qlo1OHR3RTBfc00yN3lfSFk="
   ```

3. Run the connector:
   ```shell
   ./oaa_slack.py --veza-url https://<your-org>.vezacloud.com
   ```

### Parameters
| CLI Parameter    | Environment Variable | Description                                       |
| ---------------- | -------------------- | ------------------------------------------------- |
| `--veza-url`     | `VEZA_URL`           | URL of Veza system                                |
|                  | `VEZA_API_KEY`       | API key for Veza connection                       |
|                  | `SLACK_TOKEN`        | Slack OAuth Token for the app                     |
| `--skip-deleted` |                      | Do not collect deleted users                      |
| `--debug`        |                      | Enable verbose debug output                       |
| `--save-json`    |                      | Save OAA Payload as local JSON file before upload |