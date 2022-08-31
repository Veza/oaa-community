# Python SDK for Veza Open Authorization API

The `oaaclient` package provides data models, methods and a command-line interface for using the [Open Authorization API](https://github.com/Veza). You can use it to format and publish user, resource, and authorization metadata for processing by a Veza instance.

For example usage, please see the `samples` directory.

### What is OAA?

The Open Authorization API is used to submit authorization metadata for custom applications to a Veza instance for parsing and inclusion in the Entity Catalog.

- A typical OAA-based integration will use APIs to query the source application for information about users, resources, and permissions, along with other authorization entities such as groups and roles.
- This data payload is published to Veza as a JSON object. The `oaaclient` modules simplify building the required JSON model and pushing the payload to Veza via the REST API.
- Any application or identity provider added using OAA becomes fully available for search, rules and alerts, and access reviews, similar to any officially-supported integration.

## Using the SDK

The `oaaclient` SDK includes the following components:

- `oaaclient.client`: Veza API communication (data provider management, payload push, etc.). Requires an API key for authentication.
- `oaaclient.templates`: Classes for modeling and generating an OAA payload.
- `oaaclient.utils`: Additional utility functions (icon encoding, etc.).

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

```shell
oaaclient  --provider provider.json --auth auth.json payload.json
```

The client will read the files and push the payload to Veza. The client will automatically create any required custom provider and data sources.

## Handling Errors

The `OAAClient` class handles API connections to Veza. If there are errors connecting or the API returns errors
`OAAClient` will raise an `OAAClientError` exception. If the payload does not conform to the template requirements the
`OAAClientError.details` will contain a list of any issues encountered.

```python
    try:
        response = veza_con.push_application(provider_name=provider_name,
                                             data_source_name=data_source_name,
                                             application_object=custom_app,
                                            )
        if response.get("warnings"):
            print("Push succeeded with warnings:")
            for w in response["warnings"]:
                print(w)
    except OAAClientError as e:
        print(f"Error: {e.error}: {e.message} ({e.status_code})", file=sys.stderr)
        if hasattr(e, "details"):
            for d in e.details:
                print(d, file=sys.stderr)
```

## Additional documentation

Since any given source application or service will have different methods for retrieving entities, authorization, and other required metadata, each OAA connector will be slightly different. You should consult the API documentation for your application when considering how you will source the information, and refer to existing Veza-supported OAA connectors for real-world examples.

Connector source code and `oaaclient` modules are thoroughly annotated, for reference when building your own integrations.

For additional information on developing a custom OAA integration, please contact your Veza support team for access to the *User Guide*.
