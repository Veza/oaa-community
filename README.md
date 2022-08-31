![Veza Logo](images/Veza_Lockup_Amethyst.png)
# Open Authorization API Community

To help customers get up and running quickly using Open Authorization API (OAA) we created the Veza OAA Community. This
repository includes libraries for developing new connectors, several pre-built connectors, examples and documentation.
The connectors in the repository (for GitHub, for JIRA, for Zendesk, etc.) are ready for immediate use by following the
instruction in each connectors README.

Veza customers and partners can use the community as a resource for developing their own connectors and tooling, and are
encouraged to contribute to add support for new sources or improve existing ones.

## Veza Overview
Veza is the data security platform built on the power of authorization. Our platform is purpose-built for multi-cloud
environments to help you use and share your data more safely. Veza makes it easy to dynamically visualize, understand
and control who can and should take what action on what data. We organize authorization metadata across identity
providers, data systems, cloud service providers, and applications — all to address the toughest data security
challenges of the multi-cloud era. To learn more, please visit us at veza.com.

## Open Authorization API

Sometimes, you might want to integrate Veza to an app or system that we don’t yet support natively. You might have a
custom or homegrown SaaS or on-prem app - for example, a customer service or support app that holds or accesses
sensitive data - for which you want to see and manage authorization. Our Open Authorization API (OAA) enables a BYO-app
model to integrate with Veza. The Open Authorization API (OAA) enables Veza customers and partners to integrate custom
and other 3rd party applications and data systems using a standard interface.

In addition to the OAA, there is a small chunk of code that runs outside of the Veza SaaS infrastructure: the connector.
The connector has 3 jobs: it needs to pull authorization data from the target system (i.e., app, data storage system, or
service), transform that data into a format Veza can understand, and call the Veza API to import the data into Veza.

Using OAA and connectors, organizations can parse and upload authorization metadata for apps not natively supported by
Veza, and create a more complete view of permissions across cloud/data/identity systems to answer the question: “who can
and should take what action on what data?”

## How OAA Works
OAA works by providing a mechanism to upload authorization information from a target system to Veza in a standardized
format. To integrate a new system, you utilize that system's API (or other interfaces) to enumerate the identities,
permissions and resources that you want available in Veza. This information must then be formatted according to the OAA
JSON schema and uploaded to Veza using the OAA REST API.

![Flow Diagram](images/flow.png)

Veza processes this schema mapping to integrate metadata from the new target system into its Authorization Metadata
Graph, which maps which identities have what permissions to what resources. Veza combines this information with
discovered data from Identity providers to expand group memberships and correlate identities. Identities can be local to
that application or linked to external Identity Providers (IdP) like Okta or AzureAD. The Veza schema can capture and
represent both standard Effective Permissions (Create, Read, Update, and Delete) as well as system-specific permissions
(like “Admin” or “Operator”).

Once a target application or system is integrated via OAA into Veza, it acts like any other data source. OAA-integrated
systems are fully available for the purpose of Veza search, governance workflows, reports, alerts, and more.

## Getting Started

To use an existing connector see the README file in the connector directory. Each README will contain an
overview and instructions for how to use the connector. Download the code and follow the setup instructions to use the
connector in your application.

To get started developing your own connectors:
* Consult the Open Authorization API section of the Veza User Guide
* See the samples directory:
  * `sample-app.py` - sample generic application, suitable for most apps.
  * `sample-idp.py` - sample custom identity provider, for IdPs and other identity related services
* Use the `oaaclient` SDK for developing your own connectors in Python

## Connectors

The Community repository includes the following existing connectors, each connector is in its own directory with
instructions.

Connector  | Support Level  | Language | Notes
-----------|----------------|----------|-----------------------------------------------------------------------------
GitHub     | Veza Supported | Python   | Support for GitHub Cloud for discovery organization's repository permissions
GitLab     | Veza Supported | Python   | Discovery for GitLab project permissions
Jira       | Veza Supported | Python   | Jira Cloud support for projects
Looker     | Veza Supported | Python   | Looker User authorization for models and connections
PagerDuty  | Veza Supported | Python   | PagerDuty user roles and teams
Salesforce | Veza Supported | Python   | User role and permission assignments for Salesforce
Zendesk    | Veza Supported | Python   | Zendesk user to role assignments

### Support Levels
#### Veza Supported
A connector that is fully supported by Veza. Veza is committed to the functionality of the connector and will fix
issues based on severity and demand. Veza tests the connector prior to any updates posted to the community.

#### Community Supported
A connector that has been contributed to the community and reviewed by Veza. Veza may not be able to provide full
support for the connector and may not have the ability to test the connector. Any improvements or fixes to the
connector will come through the community.

## Contributing

If you are interested in contributing improvements or new connectors see our [guide](docs/CONTRIBUTING.md)

## Join Us on Slack
Join us on Slack at [veza-oaa-community](https://join.slack.com/t/veza-world/shared_invite/zt-17d9quyiq-20JMp0ikZ0pVNz_e5W5j7Q)
