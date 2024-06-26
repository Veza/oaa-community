# Veza OAA connector for Github

Python connector to query Github organization members and repositories and push authorization data using the Open Authorization API.

- [Overview](#overview)
- [Setup and installation](#setup)
- [Running the Connector](#running-the-connector)
- [Notes](#notes)

## Overview

This connector utilizes the Github API using a Github App for authorization. The Github App must be created and configured for the target organization (steps below) prior to running. It will need Read-Only permissions on select resources to allow the connector to enumerate organization repositories, members, and teams.

Once extracted, the metadata payload is pushed to a Veza instance for parsing. Repository permissions are mapped for each individual member (user) or team (group) including outside collaborators.

### Custom Application Mappings

This connector uses the OAA Application template to map applications and identities to permissions. The following table shows how Custom Application entities correspond to GitHub entities:

| GitHub                        | Generic Application  |
| ----------------------------- | -------------------- |
| organization                  | Application          |
| members                       | Local User           |
| team                          | Local Group          |
| organization owners           | Local Role           |
| default repository permission | Local Role           |
| repository                    | Application Resource |

### Custom Properties

The following properties are set based on the GitHub properties

| Entity     | Property                   | Description                                                                                    |
| -----------| ---------------------------| -----------------------------------------------------------------------------------------------|
| User       | `OutsideCollaborator`      | Boolean for users who are not a member of the org and invited to one or more repositories      |
| User       | `profile_name`             | The name the user has set in their profile                                                     |
| User       | `emails`                   | List of emails discovered for the user                                                         |
| Repository | `private`                  | Boolean `true` if repository is not public                                                     |
| Repository | `visibility`               | Repo visibility, may be `public`, `private` or `internal`                                      |
| Repository | `default_branch`           | Default branch for repository                                                                  |
| Repository | `default_branch_protected` | Boolean `true` if any protections enabled on default branch                                    |
| Repository | `allow_forking`            | Boolean if private forks are allowed                                                           |
| Repository | `is_fork`                  | Boolean if repository is fork of another                                                       |

### Reports
Connect will automatically populate a Veza Insights Queries and Report with GitHub related quires on first run. Queries created include:

  - GitHub Users
  - GitHub Outside Collaborators
  - GitHub Public Repositories
  - GitHub Public Repositories Excluding Forks
  - GitHub Users with Organization Admin
  - GitHub Users mapped to Okta Identities
  - GitHub Users without Okta Identity
  - GitHub Users with inactive Okta Accounts
  - GitHub Users with AzureAD Identity
  - GitHub Users without AzureAD Identity
  - GitHub Users with inactive AzureAD Accounts

## Setup

### GitHub Setup Instructions

You will need to create a Github App to grant the OAA connector access your organization and pull the necessary information.

To register a new application within an organization you administrate, open GitHub **Settings** > **Organizations**. Click *Settings* next to the name of the organization containing the members, repositories, and permissions to extract.

1. On the Organization's settings page, choose **Developer Settings** > **GitHub Apps** > *Add New*
2. Complete the following fields
   * “GitHub App name” - must be unique (e.g. `YourOrg-OAA-GitHub-Connector-01`)
   * “Homepage URL” - Not used but required by GitHub. Provide an address such as the URL of your Veza instance (e.g. `https://yourorg.vezacloud.com`)
   * No other fields are required
3. Assign the required permissions to the application. Add the following permissions as “Read-Only”
   * Repository permissions - Administration
   * Organization permissions - Members
   * Organization permissions - Administration
4. For *Where can this app be installed?*, choose *Only on this account*
5. Click *Create GitHub App* to open the app settings page

Note the “App ID” towards the top. Click *Generate a private key* to download the .pem key file. These will be used to authenticate when running the connector.

> See [Creating a GitHub App](https://docs.github.com/en/developers/apps/building-github-apps/creating-a-github-app) in the GitHub documentation for more information.

Install the App into the Organization(s) you want to discover:

1. Open the app settings page (**Settings** > **Developer settings** > **GitHub Apps** > `your-application`)
1. Click *Install* next to the organization name
1. Choose *All Repositories*, unless you want to exclude specific resources
1. Click *Install* and approve the permissions

> If you aren't an org admin, you can create the app under your personal **Developer Settings** > **GitHub Apps** > *Add New*. Choose *Any Account* when choosing where the new app can be installed. You will need to *Request* installation to any organization you are a member of, which an administrator must approve.

### Veza Setup Instructions

Generate a Veza user API key by navigating to **Administration** -> *API Keys*. Choose *Add New*. Give the key a name and copy the token, which will only be shown once.

## Running the connector

There are multiple options for running the connector. It can be run at the command line, as a container, or as an AWS Lambda function.

### Command Line

Ensure pip is up-to-date, dependencies will fail to install unless pip >= 21.0. Install the requirements with Python 3.8+: 

```shell
pip3 install -r requirements.txt
```

Store the Veza username and Veza API key as environment variables:

```shell
export VEZA_API_KEY=ZXldTcj...JCWGU3Qlo1OHR3RTBfc00yN3lfSFk=
```

Run the connector:

```shell
./oaa_github.py \
--app-id <GitHub App ID e.g. 123456> \
--key-file path/to/connector.private-key.pem \
--org <GitHub Org Name e.g. demo-org> \
--veza-url https://<your-org>.vezacloud.com
```

Optionally, the GitHub key can be loaded from the OS environment as a base64-encoded string. Open the `*.pem` file and encode its contents with the command:

```shell
export GITHUB_KEY_BASE64=$(cat path/to/private-key.pem | base64)
```

When `GITHUB_KEY_BASE64` is set, the `--key-file` argument is not required.

To connect GitHub Enterprise instance provide the URL to use for GitHub API calls:

```shell
./oaa_github.py \
--app-id <GitHub App ID e.g. 123456> \
--key-file path/to/connector.private-key.pem \
--org <GitHub Org Name e.g. demo-org> \
--github-url <https://yourgithub.example.com> \
--veza-url https://<your-org>.vezacloud.com
```

### Container

A `Dockerfile` to build a container is included in the repository that can be used with the `docker build` command.

  `docker build . -t oaa_github:latest`

To run the container, all required parameters must be provided as environment variables. The GitHub key can be included by mounting the file or as a base64 encoded string.

Run by mounting a .pem key file:

  ```shell
  docker run --rm \
  -v ~/keys/GitHub-key.pem:/oaa/key.pem \
  -e GITHUB_ORG=<org> \
  -e GITHUB_APP_ID=<app ID> \
  -e GITHUB_KEY=/oaa/key.pem \
  -e VEZA_URL=https://<Veza URL> \
  -e VEZA_API_KEY=<Veza API Key> \
  oaa-github
  ```

Run using Base64-encoded key as variable:

  ```shell
  docker run --rm \
  -e GITHUB_ORG=<org> \
  -e GITHUB_APP_ID=<app ID> \
  -e GITHUB_KEY_BASE64=<b64 encoded key> \
  -e VEZA_URL=https://<Veza URL> \
  -e VEZA_API_KEY=<Veza API Key> \
  oaa-github
  ```

### Parameters
| CLI Parameter  | Environment Variable | Description                                                                         |
| -------------- | -------------------- | ----------------------------------------------------------------------------------- |
| `--org`        | `GITHUB_ORG`         | Name of GitHub organization to discover                                             |
| `--app-id`     | `GITHUB_APP_ID`      | ID of GitHub app to use for authentication                                          |
| `--key-file`   | `GITHUB_KEY`         | Path to private key for GitHub App authentication                                   |
| n/a            | `GITHUB_KEY_BASE64`  | Base64 encoded key file as string. Optional as alternative to passing key file path |
| `--github-url` | `GITHUB_URL`         | Optional URL for GitHub Enterprise connection                                       |
| `--veza-url`   | `VEZA_URL`           | URL for Veza instance                                                               |
| n/a            | `VEZA_API_KEY`       | Veza API key                                                                        |
| `--user-map`   | `GITHUB_USER_MAP`    | Optional path to CSV file for GitHub user name to identity mapping                  |
| `--save-json`  | n/a                  | Save OAA JSON payload to file                                                       |
| `--debug`      | `OAA_DEBUG`          | Optional flag to enable verbose debug logging                                       |

## Notes

### Unknown Teams

The OAA connector for GitHub reads the list of teams configured in the organization. When listing teams that have access to the repository, if a repository returns a team that is not part of the organization, the connector will halt with an error. This error can be ignored by setting the environment variable `GITHUB_IGNORE_UNKNOWN_TEAMS` to any value.

### User Identity Mapping

The GitHub OAA Connector will attempt to retrieve emails for each user to use as an identity in linking the GitHub user
account with IdP users (Okta, AzureAD and OneLogin). However, GitHub limits exposure of user emails to only email
addresses that match the verified domain(s) for the organization. If the user does not have an email configured that
matches a verified domain the OAA Connector will not be able to retrieve an email for the user.

To resolve additional identity associates the connector can take a csv of GitHub user names and email identities
to add to the data pulled from the GitHub API. To provide mapping file use the `--user-map <file_path>`
option at run time with a path to a local file or S3 object. For S3 objects use the URI path, e.g.
`s3://mybucket/object/key.txt`.

File format should be `GitHub User, email identity` with one GitHub user per line, no header.

User identities that cannot be mapped to a discovered IdP user will be output as warnings at the end. The GitHub
local user will still be created

### GitHub Endpoints Used

The connector calls the GitHub APIs:

* `orgs/{org_name}` - Organization information
* `orgs/{org_name}/members` - List of members for an organization
* `orgs/{org_name}/teams` - List of teams for an organization
* `orgs/{org_name}/teams/{team}/members` - List for members for a given team
* `orgs/{org_name}/repos` - List of organization repositories
* `/repos/{org_name}/{repo}/teams` - Team permissions for repository
* `/repos/{org_name}/{repo}/collaborators?affiliation=direct` - List of team members with direct permissions (not via team, default or org admin status)
* `/repos/{org_name}/{repo}/branches/{branch_name}/protection` - Determine if merge protections are configured on branch, only for default branch
* Github App authentication and authorization APIs

For more information, see the [GitHub API reference](https://docs.github.com/en/rest/overview/endpoints-available-for-github-apps).
