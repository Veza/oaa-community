# Contributing

If you are interested in contributing improvements or new connectors to the OAA Community please follow the standard
fork-and-pull workflow.

1. Fork this repository to your personal workspace
2. Create a new branch for your changes
3. Submit a pull request, we will review your changes and merge your changes.

Please ensure that any conflicts with the current `main` branch have been resolved prior to opening the pull request.

## New Connectors
Any new connectors should follow these basic guidelines:

* The new connector must be in its own folder named after the service or application the connector is for.
* The folder must contain a `README.md` file that includes the following:
  - Explanation of what the connector does, what entities it collects and any limitations.
  - Setup instructions for the application/service, such as how to configure any required API credentials.
  - Instructions for running the connector including any environment setup that might be needed
* Connectors must not have any customer specific hard-coded values such as host names, account IDs or API keys. The connector must be re-usable for other community members.
* Connectors should follow general best practices for the language they are written in.

## Improvements and Fixes
If extending an existing connector or fixing an issue please include an explanation of the issue and how the change was
validated with the pull request. If extending the information collected by an existing connector please include the
update to the connector's `README.md` file as part of the pull request.

## Review
All pull requests will be reviewed by Veza and subject to approval. Veza may incorporate the changes in a new branch as
part of testing and validation before merging. 
