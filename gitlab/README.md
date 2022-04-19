# OAA Connector for GitLab

Python connector for querying GitLab deployment to discover users and projects. Provides authorization data for each projects users.

For additional OAA documentation, see the [Veza User Guide](https://docs.veza.com/oaa/)

## Overview

This connector authenticates to the GitLab deployment using a read-only access token for an admin user to discover all users, groups and projects configured on the deployment. Each user's access (if access is allowed) to projects is determined based on their group memberships, direct assignments and visibility properties of the project.


### Generic Application Mappings

This connector uses the OAA Application template to map applications and identities to permissions. The following table shows how Custom Application entities correspond to GitLab entities:

GitLab | Generic Application
------------ | -------------
deployment | Application
Users | Local User
Group | Local Group
GitLab Admin | Local Role
Logged in User | Local Role
project | Application Resource

### Attributes
Entity  | Property        | Values
------- |---------------- |-------
User    | `bot`           | Boolean for bot users
User    | `gitlab_id`     |  Unique GitLab user ID number  
User    | `is_licensed`   | State of GitLab license usage  
User    | `state`         | Account state `active`, `blocked`, `deactivated`
User    | `is_active`     | True if account state is `active`  
User    | `created_at`    | Time user account was created  
User    | `last_login_at` | Time of last user login to GitLab  
Project | `visibility`    | Project visibility, `private`, `internal`, `public`
Project | `gitlab_id`     |  Unique GitLab project ID number  

### Limitations
* Based on API limitations project discovery is limited to 50,000 projects.
* Does not currently process external users
* Projects are not grouped by their Groups and Sub-groups, all projects are listed using their full path name
* Does not track bot user permissions

## Setup
### GitLab Setup Instructions
1. Generate an access token for a user with admin permissions, this can be an existing user or a new user created for this role
* Assign the access token `read_api` access only
* Assign the token a name and experation date
* Save the generated token

### Veza Setup Instructions
1. Generate an API key for your Veza user. See [Veza User Guide](https://app.gitbook.com/@veza.com/s/user-guide/interface-overview/administration/api-keys) for detailed instructions.

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
    ./oaa_gitlab.py --gitlab-url <URL for GitLab> --veza-url <Veza URL> --veza-user <Veza User>
    ```

    Optionally, all parameters can be passed via OS environment variables

    ```
    export GITLAB_URL=<GitLab URL>
    export GITLAB_ACCESS_TOKEN=<GitLab Access Token>
    export VEZA_URL=<Veza URL>
    export VEZA_USER=<Veza User>
    export VEZA_API_KEY=<Veza API key>
    ./oaa_gitlab.py
    ```
