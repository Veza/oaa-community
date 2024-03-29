# GitHub Connector Change Log

## 2022/2/9
* Added Veza Insights Report creator to connector. Connector will automatically create a GitHub Report with a number of prebuilt quires on first run. To populate the report with existing
  systems run the connector with `--create-report` or using `oaaclient-report-builder report.json` from this folder.
* Requires upgrade of the `oaaclient` to `1.1.0`

## 2022/1/23
* Removed `oaaclient` symlink and added `oaaclient` dependency to requirements file. Run `pip install -r requirements.txt` to install `oaaclient` package

## 2022/12/16
* Improved logging output
* Fix for org name case sensitivity

## 2022/11/28
* GitHub authorization token refresh when necessary

## 2022/11/03
* Support passing GitHub URL as command line argument (`--github-url`) or environment variable (`GITHUB_URL`) for GitHub Enterprise

## 2022/09/23
* Updated README and error messages

## 2022/09/21
* Added retries to GitHub API calls

## 2022/8/24
* Fix for GitHub teams discovery

## 2022/7/1
* Set GitHub provider icon to GitHub mark logo

## 2022/6/23
* Retrieve emails for users that match organization verified domains using GitHub GraphAPI
* Retreived emails are added as identities for users to enable matching to IdP if configured
* New GitHub user proprties for `emails`, `created_at` and `profile_name`
* New GitHub repository property `is_fork`
* Users that are members of nested groups no longer additionally show as direct members of parent groups

## 2022/6/10
* Update role names to align with GitHub user experience.
  * GitHub role "Push" is now "Write"
  * GitHub role "Pull" is now "Read"
  * GitHub organization owners role is now "Org Owners" from "Org Admins"

## 2022/5/31
* Added support for GitHub nested teams
* Fixed bug in reading organization default repository permissions
* Added handler for edge case where repository permissions can contain unknown teams

## 2022/5/25
* Converted log output to `logging` module for better output and improved messages for clarity

## 2022/4/26
* Truncate repository description length to 256, the maximum supported length for OAA resource descrition.

## 2022/4/18
* OS environment variable `OAA_TOKEN` changed to `VEZA_API_KEY`
* Added new custom properties to extraction:
  - Repository `visibility`, `default_branch`, `default_branch_protected` and `allow_forking`, see [README](README.md) for details.
