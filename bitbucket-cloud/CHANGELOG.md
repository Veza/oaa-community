# Bitbucket Cloud Changelog

## 2023/7/13
* Added support for refreshing OAuth token

## 2023/6/28
* User emails are stored as property `email` if discovered in addition to adding as user identity.
* Fixes for Project and Repository descriptions that are longer and OAA template maximum length. Descriptions are truncated to 256 characters.
* Added Veza Insights Report creator to connector. Connector will automatically create a Bitbucket Cloud Report with a number of prebuilt quires on first run. To populate the report with existing systems run the connector with --create-report or using oaaclient-report-builder report-bitbucket-security.json from this folder.
* Collected new property `is_collaborator` to identify users who have collaborator permission

## 2023/6/22
* Collect branch restrcition information for default branch. The following new properties are collected:
  - Repository `default_branch_protected`, `allow_auto_merge_when_builds_pass`, `require_passing_builds_to_merge`, `enforce_merge_checks`, `require_approvals_to_merge`, `require_default_reviewer_approvals_to_merge`, `require_tasks_to_be_completed`
* Added new configuration parameter `--skip-branch-restriction-discovery`, see [README](README.md) for details.

## 2023/2/16
* Ensure that optional Atlassian user has required permissions to browse users for collecting user identities.

## 2023/2/6
* Changes to Bitbucket group discovery.
* Support for Oauth authentication workflow

## 2023/2/2
* Added retry logic to Bitbucket API calls and improved error logging

## 2023/1/20
* Add support for `collaborator` workspace permission

## 2023/1/19
* Updated Docker image base to `python:3.10-alpine`

## 2023/1/18
* Removed `oaaclient` symlink and added `oaaclient` dependency to requirements file. Run `pip install -r requirements.txt` to install `oaaclient` package
* Added `Dockerfile` for creating Docker container of connector

## 2022/12/14
* Support for discovering Bitbucket groups and group based repository permissions. To discover group repository
  permissions the Bitbucket App Password must have **Admin** permission on the repositories. See [README](README.md)
  for more information.
* Discovery time optimization by increasing Bitbucket API page length requested for repository authorizations
