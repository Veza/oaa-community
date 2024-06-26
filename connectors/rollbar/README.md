# Veza Rollbar Connector

Veza Connector for Rollbar. Enables discovery of Rollbar Users along with Accounts, Teams, Projects, and Roles.

### Veza Application Mapping

| Rollbar       | OAA Application  |
| ------------- | ---------------- |
| Rollbar.com   | Application      |
| Users         | Local User       |
| Projects      | Custom Resources |
| Teams         | Local Group      |
| Access Level  | Local Role       |


### Discovered Properties

| Entity       | Property       | Description                                                   |
| ------------ | -------------- | --------------------------------------------------------------|
| User         | `id`           | User's ID provided by Rollbar.                                |
| User         | `name`         | User's name.                                                  |
| User         | `email`        | User's email address.                                         |
| Project      | `id`           | Project's ID provided by Rollbar.                             |
| Project      | `name`         | Name of the Project.                                          |
| Project      | `status`       | Status of the Project.                                        |
| Project      | `created_at`   | Date of Project creation.                                     |
| Project      | `modified_at`  | Last modification date of Project.                            |
| Role         | `id`           | Id of the Role.                                               |
| Role         | `name`         | Name of the Role.                                             |
| Team         | `id`           | Id of the Team.                                               |
| Team         | `name`         | Name of the Team.                                             |

## Setup

### Rollbar

1. The integration requires a Rollbar [Account Access Token](https://docs.rollbar.com/reference/getting-started-1#account-access-tokens) scoped for read-only account-level operations.
2. Create one under **{Account name} Settings** > **Account Access Tokens**.
3. Enable the `read` scope for the token.
4. Save the token when it appears and use it to run the integration.

### Veza

1. Generate an API key for your Veza user. API keys can be managed in the Veza interface under Administration -> API Keys.

## Running the Connector

### Command Line

1. Install the requirements:

    ```
    pip3 install -r requirements.txt
    ```
2. Set the Secrets:
    ```
    export VEZA_API_KEY="ZXldTcj...JCWGU3Qlo1OHR3RTBfc00yN3lfSFk="
    export ROLLBAR_ACCESS_TOKEN="XXXXXXXXXXXXXXXXXXXXXXXX"
    ```
3. Run the connector:
    ```
    ./veza_rollbar.py --veza-url https://<your-org>.vezacloud.com
    ```

### Parameters

| CLI Parameter                   | Environment Variable          | Description                                                                       |
| ------------------------------- | ----------------------------- | --------------------------------------------------------------------------------- |
| `--veza-url`                    | `VEZA_URL`                    | URL of Veza system                                                                |
|                                 | `VEZA_API_KEY`                | API key for Veza connection                                                       |
|                                 | `ROLLBAR_ACCESS_TOKEN`        | Rollbar Account Access Token                                                      |
| `--debug`                       | N/A                           | Enable verbose debug output                                                       |
| `--save-json`                   | N/A                           | Save OAA Payload as local JSON file before upload                                 |
