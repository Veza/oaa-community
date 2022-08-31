# Veza OAA Connector for Bitbucket Cloud

Python connector for Bitbucket Cloud to collect repository permissions for the Veza Open Authorization (OAA) API.

## Overview

This connector usese the Bitbucket REST API to retrieve information on user access to repositories in in a Bitbucket
Cloud workspace. The connector will discover all member users of the workspace and all repositories (by project). Each
users permission to the repositories will be collected.

## Veza OAA Generic Application Mappings

This connector uses the OAA Application template for modeling identites to permissions.

| Bitbucket Cloud | OAA Application          | Notes                                           |
| --------------- | ------------------------ | ----------------------------------------------- |
| Workspace       | Application              |                                                 |
| User            | Local User               |                                                 |
| Project         | Resource, type `Project` |                                                 |
| Repository      | Subresource, `Repo`      | Repositories are sub-resources of their Project |

## Limitations

To support mapping Bitbucket users to corporate identities the connector can make use of the Atlassian API to retrieve
email addresses. Doing so requires a separate set of credentials from the Bitbucket API credentials. Follow the
instructions bellow to configure and provide the credentials.

## Setup
### Bitbucket Credentials Setup
1. Create an [App Password](https://support.atlassian.com/bitbucket-cloud/docs/app-passwords/) for a Bitbucket user with Admin permissions
   1. Select **Read** for the following permissions: Account , Workspace Membership, Project, Repositories

### Atlassian Credentials Setup (Optional)
1. Generate an [Atlassian API token](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/) for the same account

### Veza API Key
1. Generate an API key for your Veza user. API keys can be managed in the Veza interface under Administration -> API Keys. For detailed instructions consult the Veza User Guide.

## Running the Connector

### Command Line
1. With Python 3.8 or higher install the requirements either to a virtual environment, user or system.

   ```shell
   pip3 install -r requirements.txt
   ```

2. Set the Veza API key and Bitbucket authorization environment variables. All other parameters can either be passed as environment variables or command line arguments.

    ```shell
    export VEZA_API_KEY=<Veza API key>
    export BITBUCKET_USER=<Bitbucket User>
    export BITBUCKET_APP_KEY=<Bitbucket App key>
    ```

    > Note: for Windows environments use the `set` command instead of `export` and do not include quotation marks around the parameter values

3. Run the connector
   ```shell
    ./oaa_bitbucket.py --workspace <workspace name> --veza-url <URL to Veza instance>
   ```

## Application Parameters & Environment Variabls
| Parameter     | Environment Variable  | Required | Notes                                                              |
| ------------- | --------------------- | -------- | ------------------------------------------------------------------ |
| `--workspace` | `BITBUCKET_WORKSPACE` | Yes      | Name of Bitbucket workspace                                        |
| n/a           | `BITBUCKET_USER`      | Yes      | Bitbucket user for connection                                      |
| n/a           | `BITBUCKET_APP_KEY`   | Yes      | App key generated for Bitbucket user                               |
| `--veza-url`  | `VEZA_URL`            | Yes      | URL of Veza instance                                               |
| n/a           | `VEZA_API_KEY`        | Yes      | Veza API key                                                       |
| n/a           | `ATLASSIAN_LOGIN`     | No       | For discovering Bitbucket user identity emails using Atlassian API |
| n/a           | `ATLASSIAN_API_KEY`   | No       | Optional Atlassian API key for Atlassian API                       |
| `--save-json` | n/a                   | No       | Save the OAA JSON to file before upload                            |
| `--debug`     | `OAA_DEBUG`           | No       | Enable OAA debug, for environment variable set to any value        |