# Bitbucket Cloud Changelog
## 2023/1/18
* Removed `oaaclient` symlink and added `oaaclient` dependency to requirements file. Run `pip install -r requirements.txt` to install `oaaclient` package
* Added `Dockerfile` for creating Docker container of connector

## 2022/12/14
* Support for discovering Bitbucket groups and group based repository permissions. To discover group repository
  permissions the Bitbucket App Password must have **Admin** permission on the repositories. See [README](README.md)
  for more information.
* Discovery time optimization by increasing Bitbucket API page length requested for repository authorizations
