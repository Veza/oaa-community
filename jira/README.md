# Veza OAA Connector for Jira Cloud

Python connector for retrieving projects, groups, users, and permissions from Jira Cloud and submitting them to the Veza Open Authorization (OAA) API.

## Overview

This connector connects to the Jira Cloud API using an API token.

The `jira_user` account used by this connector must have read-only permissions to all projects to discover, in order to enumerate projects and related permissions.

Once extracted, the metadata payload will be pushed to the Veza instance for parsing.
Global permissions and project permissions are mapped for users and groups.

## Jira Cloud API Endpoints

The base URL for all Jira Cloud API interactions is `https://<your_instance_name>/rest/api/3`.
The following table describes the API endpoints used by this connector.

Endpoint                                 | Description
-----------------------------------------|-----------------------------------------------------
`group/bulk`                             | lists Jira Cloud groups
`permissions`                            | lists Jira Cloud permissions
`project/<project_key>/role`             | lists roles for the given project key
`project/<project_key>/permissionscheme` | gets detailed permissions for the given project key
`project/<project_key>/role/<role_id>`   | gets detailed membership for the given project role
`project/search`                         | lists Jira Cloud projects
`users/search`                           | lists Jira Cloud users

For more information, see the [Jira Cloud API Docmuentation](https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro/#about)

## Veza OAA Generic Application Mappings

This connector uses the generic OAA application template to map applications and identities to permissions.
The following table shows how Generic Application entities correspond to Jira Cloud entities.

Jira Cloud    | OAA Generic Application | Notes
--------------|-------------------------|-------------------------------------------------------
group         | local group             |
jira instance | application             |
project       | application resource    |
project role  | local group             | Displayed in Veza as `<project name> - <role name>`
user          | local user              |

> Because roles are defined on a per-project basis (and role names may be duplicated across a Jira Cloud instance) project roles are translated
 as ``<project name> - <role name>``

## Limitations
Atlassian and Jira support adding groups to groups to reduce duplication of entitlements but do not return the details on group assignments
within groups via their public API. The OAA Connector will show all users that are members of a group directly or indirectly but will not know if
the user is directly assigned or inherited through a group membership.

## Setup
### Jira Cloud Setup Instructions

This connector requires a valid Atlassian API token to interact with the Jira Cloud instance.

1. Log in to [Atlassian API token page](https://id.atlassian.com/manage/api-tokens) with the account to be used by this connector
1. Click __Create API token__
1. From the dialog that appears, enter a meaningful label for the token and click __Create__
1. Click __Copy to clipboard__ and retain the token for use with this connector

**Note** Once the API token dialog is closed, it is not possible to view the token again.
Ensure that it is copied to a safe location before dismissing the dialog.

## Veza Setup Instructions

This connector requires a valid Veza Push API token to interact with your Veza instance.

1. Generate an API token for your Veza user. For detailed instructions consult the Veza User Guide.

## Running the Connector
There are multiple options to run the connector. Instructions are included for running from the command line and building a Docker container. These instructions could be adapted
to Lamda, GitHub actions and a variety of other platforms.

### Command Line
1. Export the appropriate environmental variables. Variables not set can be passed via arguments at run time.
```
export VEZA_API_KEY="Zdkemfds..."
export JIRA_TOKEN="lsjflmmxvn..."
...
```
1. Run the connector:

    `jira_veza_oaa.py --jira_url https://example.atlassian.net --vezaurl https://example.vezatrial.ai`

### Docker
A `Dockerfile` to build a container is included in the repository. Running the container will perform the Jira discovery and OAA push then exit. Schedule the container to run on a regular interval.

1. Build the container. Must be run from the parent directory (repository root) in order to include the `oaaclient` code.

  ```
  docker build . -f ./jira/Dockerfile -t oaa_jira
  ```

1. To run the container, all required parameters must be provided as environment variables.

  ```
  docker run --rm \
    -e JIRA_USER="atlassian_api_user@example.com" \
    -e JIRA_TOKEN="qoierxmvkfnbsdflkjqwe" \
    -e VEZA_URL="https://customer.vezacloud.com" \
    -e JIRA_URL="https://customer.atlassian.net" \
    -e VEZA_API_KEY="ZXlKaGJHY2lPaUpJVXpJM.....=" \
    oaa_jira
  ```

## Application Parameters / Environmental Variables

Parameter   | Environmental Variable | Required | Notes
------------|------------------------|----------|---------------------------------------------------------------------------------
N/A         | `VEZA_API_KEY`         | true     | the API token which which to connect to the Veza instance
`veza_url`  | N/A                    | true     | the url of the Veza instance to which the metadata will be uploaded
N/A         | `JIRA_TOKEN`           | true     | the API token with which to connect to the Jira Cloud instance
`jira_url`  | N/A                    | true     | the url of the Jira Cloud instance
`jira_user` | `JIRA_USER`            | true     | the user with which to connect to the Jira Cloud instance
`save_json` | N/A                    | false    | save a copy of the metadata JSON uploaded to the Veza instance to this directory
