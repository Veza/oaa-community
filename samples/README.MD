# OAA Samples

This directory includes annotated samples for using the `oaaclient` Python SDK.

These examples can be used as a starting point for building new connectors for custom applications.

Brief descriptions are included below. You should also refer to the current list of Veza-supported connectors for real-world examples, and to check if an integration already exists for your use case.

## Sample App - `sample-app.py`

OAA is most commonly used to model local identities, data sources, and permissions within an application containing sensitive information such as a database, ticket desk, or SCM platform. This sample app uses the `CustomApplication` class to create an OAA payload for a typical application that includes users, groups, roles, and resources.

## Sample IdP - `sample-idp.py`

Customers that utilize a custom Identity Provider (or an IdP that doesn't have a native Veza integration) can use the OAA Custom IdP template to describe federated users and groups. This sample app generates a custom payload containing users, groups, and identity metadata, using the `CustomIdPProvider` class.

It additionally demonstrates OAA's support for AWS role entitlements, for scenarios where customers employ methods of enabling users to assume AWS roles that cannot be discovered by Veza's native AWS integration.

## IdP Import CSV - `idp-import-csv.py`

Sample app for importing Custom Identity Provider users from a CSV file.

This example can be used as a simple starting point for
an OAA data source importer. Demonstrates use of `CustomIdPProvider` to create IdP users and assign properties using an input file with with the column headings:

`identity,name,full_name,is_active,is_guest,manager_id`
