# Veza OAA Connector for Bitbucket Cloud

Python connector for Bitbucket Cloud to collect repository permissions for the Veza Open Authorization (OAA) API.

## Overview

This connector uses the Bitbucket REST API to retrieve information on user access to repositories in in a Bitbucket
Cloud workspace. The connector will discover all member users of the workspace and all repositories (by project). Each
users permission to the repositories will be collected.

## Veza OAA Generic Application Mappings

This connector uses the OAA Application template for modeling identities to permissions.

| Bitbucket Cloud | OAA Application          | Notes                                           |
| --------------- | ------------------------ | ----------------------------------------------- |
| Workspace       | Application              |                                                 |
| User            | Local User               |                                                 |
| Project         | Resource, type `Project` |                                                 |
| Repository      | Subresource, `Repo`      | Repositories are sub-resources of their Project |

## Limitations

To discover group permissions on repositories the connector requires **Admin** API access for repositories. This is
optional and can be omitted. If the **Admin** permission is not provided the connector will fall back on discovering
user's effective permissions which can be slower and shows all users effective permission on the repository even if
gained through group membership.

To support mapping Bitbucket users to corporate identities the connector can make use of the Atlassian API to retrieve
email addresses. Doing so requires a separate set of credentials from the Bitbucket API credentials. Follow the
instructions bellow to configure and provide the credentials.

## Setup
### Bitbucket Credentials Setup

1. Create an Oauth Consumer by navigating to the Workspace Settings then **OAuth consumers** under **Apps and Features** and clicking the **Add Consumer** button.
2. Configure the following parameters for the new Consumer:
   1. **Name**
   2. **Callback URL** - Required value but not used, set to `http://localhost`
   3. Check the box for `This is a private consumer`
   4. Under Permissions Check the following boxes:
      1. **Account - Read**
      2. **Workspace Membership - Read**
      3. **Projects - Read**
      4. **Repositories - Admin**

      The Repositories Admin permission is required to discover repository permissions by group membership (e.g. the Developers group has write access). Without Admin permission, all permission discovery is user based. The connector can be ran with only Read permission on Repository but it will be significantly slower and may encounter timeout issues at larger deployments.

3. After the Consumer is created click on the consumer to view its **Key** and **Secret**

> Previous versions of the connector utilized user App Keys for authentication. This method is still supported but no longer the recommended method. If Oauth Connector credentials are being utilized any previous App Keys should be deleted.

### Atlassian Credentials Setup (Optional)
The Bitbucket connector uses the Atlassian API to retrieve user email addresses to enable Bitbucket user to IdP linking. If you do not configure and provide Atlassian credentials the connector can run
but will not collect identity information for Bitbucket users.

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
    export BITBUCKET_CLIENT_KEY=<Bitbucket Oauth Client Key>
    export BITBUCKET_CLIENT_SECRET=<Bitbucket Oauth Client Secret>
    ```

    > Note: for Windows environments use the `set` command instead of `export` and do not include quotation marks around the parameter values

3. Run the connector
   ```shell
    ./oaa_bitbucket.py --workspace <workspace name> --veza-url <URL to Veza instance>
   ```

## Application Parameters & Environment Variabls
| Parameter     | Environment Variable      | Required | Notes                                                              |
| ------------- | ------------------------- | -------- | ------------------------------------------------------------------ |
| `--workspace` | `BITBUCKET_WORKSPACE`     | Yes      | Name of Bitbucket workspace                                        |
| n/a           | `BITBUCKET_CLIENT_KEY`    | Yes*     | Bitbucket Oauth Client Key                                         |
| n/a           | `BITBUCKET_CLIENT_SECRET` | Yes*     | Bitbucket Oauth Client Secret                                      |
| n/a           | `BITBUCKET_USER`          | No       | Bitbucket user for connection (legacy)                             |
| n/a           | `BITBUCKET_APP_KEY`       | No       | App key generated for Bitbucket user  (legacy)                     |
| `--veza-url`  | `VEZA_URL`                | Yes      | URL of Veza instance                                               |
| n/a           | `VEZA_API_KEY`            | Yes      | Veza API key                                                       |
| n/a           | `ATLASSIAN_LOGIN`         | No       | For discovering Bitbucket user identity emails using Atlassian API |
| n/a           | `ATLASSIAN_API_KEY`       | No       | Optional Atlassian API key for Atlassian API                       |
| `--save-json` | n/a                       | No       | Save the OAA JSON to file before upload                            |
| `--debug`     | `OAA_DEBUG`               | No       | Enable OAA debug, for environment variable set to any value        |

> * `BITBUCKET_CLIENT_KEY` and `BITBUCKET_CLIENT_SECRET` are not required if using `BITBUCKET_USER` and `BITBUCKET_APP_KEY`