# PagerDuty OAA Connector

The OAA Connector for PagerDuty collections information on users that are configured in PagerDuty, their base role
for the PagerDuty application and their Teams and Team role.

## Connector Details

This connector uses the PagerDuty API to extract the identity and authorization information for users. Users are
connected by identity based on their email address configured in PagerDuty.

PageDuty Teams are represented both as a local group and a resource. If the User has a Team Role it is represented on
the resource. The Local Group can be used for purely membership quries, the role assignments to thre resource should be
used to audit a user's permission within a PagerDuty Team.

### OAA Application Mappings
| PagerDuty | Application                       |
| --------- | --------------------------------- |
| User      | Local User                        |
| Teams     | Local Group, Resource type `team` |

### Entity Properties
The following properties are collect by the connector:

| Entity     | Property             | Description                                         |
| ---------- | -------------------- | --------------------------------------------------- |
| Local User | `identity_unique_id` | PagerDuty unique user ID                            |
| Local User | `email`              | The email address configured for the PagerDuty user |
| Local User | `is_billed`          | Boolean value if user is a billed user in PagerNow  |
| `team`     | `default_role`       | the default for new users assigned to the Team      |
| `team`     | `description`        | Team description, truncated to 256 characters       |
| `team`     | `pagerduty_id`       | Unique PagerDuty ID for Team                        |
| `team`     | `summary`            | Summary value for Team                              |


## Setup
### PagerDuty
1. Generate a General Access REST API key with read-only permission following the [PagerDuty documentation](https://support.pagerduty.com/docs/api-access-keys#section-generate-a-general-access-rest-api-key)

### Veza Setup Instructions
1. Generate an API key for your Veza user. API keys can be managed in the Veza interface under Administration -> API Keys. For detailed instructions consult the Veza User Guide.

## Running from Command Line
1. With Python 3.8+ install the requirements

    ```shell
    pip install -r requirements.txt
    ```

2. Export the Veza and PagerDusty API keys to the environment variables

    ```shell
    export VEZA_API_KEY="<Veza API Key>"
    export PAGERDUTY_API_KEY="<PagerDuty API Key>"
    ```

3. Run the connector

    ```shell
    ./oaa_pagerduty.py --veza-url <Veza URL>
    ```

### Parameters
| CLI Parameter | Environment Variable | Description                                           |
| ------------- | -------------------- | ----------------------------------------------------- |
| `--veza-url`  | `VEZA_URL`           | URL for Veza instance                                 |
| n/a           | `VEZA_API_KEY`       | Veza API key                                          |
| n/a           | `PAGERDUTY_API_KEY`  | PagerDuty API key                                     |
| `--save-json` | n/a                  | Save the OAA payload locally to a file for inspection |
| `--debug`     | `OAA_DEBUG`          | Enable verbose debug logging                          |
