# GitLab Connector Change Log

## 2022/10/27
* Updates to support both GitLab self-hosted and SaaS with connector
* GitLab Groups are now represented by both a Local Group and a Resource with Projects as sub-resources
  * Sub-groups are also represented as sub-resources when present
* Removed requirement for token to be for admin user. Group tokens and non-admin user tokens are also supported.
* GitLab URL value now defaults to `https://gitlab.com` if not set

## 2022/08/04
* Improved error handling and logging

## 2022/4/18
* OS environment variable `COOKIE_API_TOKEN` changed to `VEZA_API_KEY`
