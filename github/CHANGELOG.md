# GitHub Connector Change Log

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
