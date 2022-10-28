# OAA Connector for GitLab

## Overview

Python connector for querying GitLab to discover Users, Groups and Projects. Provides authorization data for each group and projects. Supports both self-hosted and SaaS GitLab deployments.

This connector authenticates to the GitLab deployment using a read-only access token. The connector will discover all groups, sub-groups, and projects the token is authorized to access. For self-hosted (non-SaaS)  environments, an admin token can be used to discover all groups and additional user information.

See [setup](#setup) for more details.


### Generic Application Mappings

This connector uses the OAA Application template to map applications and identities to permissions. The following table shows how Custom Application entities correspond to GitLab entities:

| GitLab         | Generic Application  |
| -------------- | -------------------- |
| deployment     | Application          |
| Users          | Local User           |
| GitLab Admin   | Local Role           |
| Logged in User | Local Role           |
| project        | Application Resource |

GitLab groups and sub-groups are represented both by a `Local Group` for membership and by a `Resource` or `Sub-Resource` to show
user's role in the group and associated permissions (e.g. Developer, Owner, Guest).

### Attributes
| Entity  | Property        | Values                                                                |
| ------- | --------------- | --------------------------------------------------------------------- |
| User    | `bot`           | Boolean for bot users\*                                                 |
| User    | `gitlab_id`     | Unique GitLab user ID number                                          |
| User    | `is_licensed`   | State of GitLab license usage                                         |
| User    | `state`         | Account state `active`, `blocked`, `deactivated`                      |
| User    | `is_active`     | True if account state is `active`                                     |
| User    | `created_at`    | Time user account was created                                         |
| User    | `last_login_at` | Time of last user login to GitLab\* |
| Project | `visibility`    | Project visibility, `private`, `internal`, `public`                   |
| Project | `gitlab_id`     | Unique GitLab project ID number                                       |


### Limitations
* Attributes above marked with `*` are only available on self-hosted with an admin token
* Does not currently process external users

## Setup
### GitLab Setup Instructions
1. Generate a [GitLab access token](https://docs.gitlab.com/ee/security/token_overview.html) under GitLab *Edit profile* > * Access Tokens*.
  * For self-hosted it is recommended to generate a personal access token for an Admin-level user to enable full discovery.
  * For GitLab SaaS a group token is recommended for best results. Personal access tokens for group Owner can also be used.
* Assign the access token `read_api` access only
* Assign the token a name and expiration date
* Save the generated token

### Veza Setup Instructions
1. Generate an API key for your Veza user. API keys can be managed in the Veza interface under Administration -> API Keys. For detailed instructions consult the Veza User Guide.

### Command Line
1. With Python 3.8+ install the requirements either into a virtual environment or otherwise:
    ```
    pip3 install -r requirements.txt
    ```

2. Set the Veza Veza API key and GitLab token in the environment

    ```
    export VEZA_API_KEY=<Veza API key>
    export GITLAB_ACCESS_TOKEN=<GitLab access token>
    ```

3. Run the code:

    ```
    ./oaa_gitlab.py --gitlab-url <URL for GitLab> --veza-url <Veza URL>
    ```

    Optionally, all parameters can be passed via OS environment variables

    ```
    export GITLAB_URL=<GitLab URL>
    export GITLAB_ACCESS_TOKEN=<GitLab Access Token>
    export VEZA_URL=<Veza URL>
    export VEZA_API_KEY=<Veza API key>
    ./oaa_gitlab.py
    ```

   > `GITLAB_URL` will default to `https://gitlab.com` if not set. For self-hosted you must set the `GITLAB_URL` environment variable or `--gitlab-url` at run time.
