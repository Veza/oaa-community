# Veza OAA connector for Github

Python connector to query Github organization members and repositories and push authorization data using the Open Authorization API.

For additional OAA documentation, see the [Veza User Guide](https://docs.veza.com/oaa/)

## Overview

This connector utilizes the Github API using a Github App for authorization. The Github App must be created and configured for the target organization (steps below) prior to running.

Read-Only permissions for the necessary resources are required to allow the connector to enumerate the organization's repositories, members, and teams.

Once extracted, the metadata payload will be pushed to your Veza instance for parsing. Repository permissions are mapped for each individual member (user) or team (group) including outside collaborators.

### GitHub API Endpoints Called

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

### Generic Application Mappings

This connector uses the OAA Application template to map applications and identities to permissions. The following table shows how Custom Application entities correspond to GitHub entities:

Github                        | Generic Application
------------------------------|---------------------
organization                  | Application
members                       | Local User
team                          | Local Group
organization owners           | Local Role
default repository permission | Local Role
repository                    | Application Resource

### Custom Properties
The following properties are set based on the GitHub properties

Entity     | Property                   | Description
-----------|----------------------------|-----------------------------------------------------------------------------------------------
User       | `OutsideCollaborator`     | Boolean for users who are not a member of the org that are invited to one or more repositories
User       | `profile_name`             | The name the user has set in their profile
User       | `emails`                   | List of emails discovered for the user
Repository | `private`                  | Boolean `true` if repository is not public
Repository | `visibility`               | Repo visibility, may be `public`, `private` or `internal`
Repository | `default_branch`           | Default branch for repository, branch name tested `default_branch_protected`
Repository | `default_branch_protected` | Boolean `true` if any protections enabled on default branch
Repository | `allow_forking`            | Boolean if private forks are allowed
Repository | `is_fork`                  | Boolean if repository is fork of another

### Limitations

#### User Identity Mapping
The GitHub OAA Connector will attempt to retrieve emails for each user to use as an identity in linking the GitHub user
account with IdP users (Okta, AzureAD and OneLogin). However, GitHub limits exposure of user emails to only email
addresses that match the verified domain(s) for the organization. If the user does not have an email configured that
matches a verified domain the OAA Connector will not be able to retrieve an email for the user.

To resolve additional identiy associates the connector can take a csv of GitHub user names and email identities
to add to the data pulled from the GitHub API. To provide mapping file use the `--user-map <file_path>`
option at run time with a path to a local file or S3 object. For S3 objects use the URI path, e.g.
`s3://mybucket/object/key.txt`.

File format should be `GitHub User, email identity` with one GitHub user per line, no header.

User identities that cannot be mapped to a discovered IdP user will be output as warnings at the end. The GitHub
local user will still be created.

## Setup
### Github Setup Instructions

1. Create a new Github App. This application will be used to grant the OAA connector access the organization and pull the necessary information. All privileges should be assigned Read-Only.
 * Full Github documentation can be found [here](https://docs.github.com/en/developers/apps/building-github-apps/creating-a-github-app).
 * **Note:** Do not use “OAuth Apps”
 1. Complete the following fields
    * “GitHub App name” - name of the app (Veza OAA, for example)
    * “Homepage URL” - Not used but required by GitHub. Provide an address such as the URL of your Veza instance.
    * No other fields are required.
  1. After creation, note the “App ID” towards the top. Generate and download a Private Key towards the bottom of the page. These two form the authentication for the App.
1. Assign the required permissions to the application. Add the following permissions as “Read-Only”
  * Repository permissions - Administrator
  * Organization permissions - Members
  * Organization permissions - Administration
1. Install the App into the Organization(s).

### Veza Setup Instructions
1. Generate an API key for your Veza user. See [Veza User Guide](https://docs.veza.com/interface-overview/administration/api-keys) for detailed instructions.

## Running

There are multiple options for running the connector. It can be run at the command line, as a container or as an AWS Lambda function.

### Command Line
1. Ensure pip is up-to-date, dependencies will fail to install unless pip >= 21.0
1. With Python 3.8+ install the requirements either into a virtual environment or otherwise:
  * `pip3 install -r requirements.txt`
1. Set the Veza username and Veza API key in the environment
    ```
    export OAA_USER=<Veza user email>
    export VEZA_API_KEY=<Veza API key>
    ```
1. Run the code:

  `./oaa_github.py --app-id <Github App ID>  --key-file <path/to/Github-AppName.pem> --org <Github Org> --veza-url <name>.vezacloud.com`

  Optionally the GitHub key can be loaded from the OS environment as a base64 encoded value.
  ```
  export GITHUB_KEY_BASE64=<base64 encoding of key>
  ```
  `./oaa_github.py --app-id <Github App ID> --org <Github Org> --veza-url <name>.vezacloud.com`

### Container
A `Dockerfile` to build a container is included in the repository..
1. Build the container. Must be run from the parent directory (repository root) in order to include the `oaaclient` code.
  * `docker build . -f ./github/Dockerfile -t oaa_github`
1. To run the container, all required parameters must be provided as environment variables. The GitHub key can be included by mounting the file or as a base64 encoded string.

  **Run by mounting a .pem key file**
  ```
  docker run --rm \
  -v ~/keys/GitHub-key.pem:/oaa/key.pem \
  -e GITHUB_ORG=<org> \
  -e GITHUB_APP_ID=<app ID> \
  -e GITHUB_KEY=/oaa/key.pem \
  -e VEZA_URL=https://<Veza URL> \
  -e OAA_USER=<user email> \
  -e VEZA_API_KEY=<Veza API Key> \
  oaa_github
  ```

  **Run using Base64-encoded key as variable**
  ```
  docker run --rm \
  -e GITHUB_ORG=<org> \
  -e GITHUB_APP_ID=<app ID> \
  -e GITHUB_KEY_BASE64=<b64 encoded key> \
  -e VEZA_URL=https://<Veza URL> \
  -e OAA_USER=<user email> \
  -e VEZA_API_KEY=<Veza API Key> \
  oaa_github
  ```

## Additional Properties

- The OAA connector for GitHub reads the list of teams configured in the organization. If a repository returns a team
  that is not part of the organization in the list of teams that have access to the repository this will result in the
  connector stopping discovery with an error. The error can be ignored by setting the environment variable
  `GITHUB_IGNORE_UNKNOWN_TEAMS` to any value.
