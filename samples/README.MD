# OAA Samples

This directory includes annotated samples for using the `oaaclient` Python SDK.
These examples can be used as a starting point for building new connectors for custom applications.
A brief description of each sample is included below. You can also check the [official connectors](https://github.com/Veza/oaa-community) for additional real-world examples, and to check if an integration already exists for your use case.

## Sample App - `sample-app.py`

The most common OAA use case is to model local identities, data sources, and permissions within an application that contains sensitive information, such as a database, ticket desk, or SCM platform. This sample app uses the `CustomApplication` class to create an OAA payload for a typical application including users, groups, roles and resources.

## Sample IdpP - `sample-idp.py`

Customers that utilize custom Identity Providers, or one that doesn't have a native Veza integration, can use the OAA Custom IdP template to add entities to the data catalog. This sample app generates a custom payload containing users, groups, and identity metadata, using the `CustomIdPProvider` class.

It additionally demonstrates OAA support for AWS role entitlements, for use cases where customers have alternate methods of enabling users to assume AWS roles that cannot be discovered by Veza's native AWS integration.
