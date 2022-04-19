# OAA Samples

This directory includes samples of using the OAA Python SDK. Samples can be used as a base for building connectors
for applications not available in the OAA Community. A breif description of each sample is bellow and each one
contains comments to explain the uses of the OAA Python SDK.


## Sample App - `sample-app.py`

Uses the `CustomApplication` class to model a typical application including users, groups, roles and resources.


## Sample IdpP - `sample-idp.py`

For customers that have Identity Providers not natively supported by Veza, the OAA Custom IdP template can be used
to model identity. The `CustomIdPProvider` class models an IdP for users and groups. It additionally includes support
for AWS role entitlements for use cases where customers have alternate methods of enabling users to assume AWS roles
that cannot be discovered by Veza's native discovery.
