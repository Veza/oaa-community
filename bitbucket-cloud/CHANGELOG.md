# Bitbucket Cloud Changelog

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
