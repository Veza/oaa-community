# Python SDK for Veza Open Authorization API

The `oaaclient` package provides types, functions, and a command-line interface for the [Open Authorization API](https://github.com/Veza/oaa-community). You can use it to format and publish user, resource, and authorization metadata for processing by a Veza instance.

For example usage, please see the `samples` directory.

## Using the SDK

The `oaaclient` SDK includes the following components:

* `[oaaclient.client](./oaaclient/client.py)`: Veza API communication (data provider management, payload push, etc.). Requires an API key for authentication.
* `[oaaclient.templates](oaaclient/templates.py)`: Classes for modeling and generating OAA payload.
* `[oaaclient.utils](oaaclient/utils.py)`: Additional utility functions.

### Sample Workflow

Create the Veza API connection and a new custom application:

```python
from oaaclient.client import OAAClient
from oaaclient.templates import CustomApplication, OAAPermission

# creates a connection class to communicate with Veza
veza_con = OAAClient(url=veza_url, token=veza_api_key)

# creates a new Custom Application model
custom_app = CustomApplication(name="Sample App", application_type="sample")
```

Once the `CustomApplication` class is instantiated, you can use the public methods to populate the new app with local users, groups, resources, and permissions metadata:

```python
custom_app.add_custom_permission("owner", [OAAPermission.DataRead, OAAPermission.DataWrite])
jane = custom_app.add_local_user("jane", identities="jane@example.com")
resource1 = custom_app.add_resource(name="Resource 1", resource_type="thing")
jane.add_permission(permission="owner", resources=[resource1])
```

Once all identities, permissions and resources are modeled, the client connection handles the final push to Veza:

```python
veza_con.push_application(provider, data_source_name, application_object=custom_app)
```

See the [samples](../samples) directory for complete examples of how to use the `oaaclient` SDK.

## Command Line Use

The oaaclient can also be used as a command line tool for pushing completed OAA payloads to Veza for testing and debugging, without needing to make the API requests "by hand."

You will need the following JSON files:

1. `provider.json` - must contain the provider name and template to use (`application` or `idp`).

   ```json
   {
     "name": "ProviderName",
     "custom_template": "application"
   }
   ```

2. `auth.json` - defines the Veza host and API key to use

     ```json
     {
       "host": "https://demo.vezacloud.com",
       "token": "ZXlKaGJHY2lPaUpJ....."
     }
     ```

3. `payload.json` - The complete OAA JSON body to submit. For full reference see the Veza documentation. This format must match the schema (template) selected in `provider.json`.

Once the above files are created, the payload can be pushed with the following command:

```bash
oaaclient  --provider provider.json --auth auth.json payload.json
```

The client will read the files and push the payload to Veza. The client will automatically create any required custom provider and data sources.

## Additional documentation

Connector source code and `oaaclient` modules are thoroughly annotated, for reference when building your own integrations.

For additional information on developing a custom OAA integration, please contact your Veza support team for access to the *User Guide*.
