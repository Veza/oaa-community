# Jira Connector Change Log

## 2022/10/24
* Fix for issue with names not being unique. Jira unique IDs are now used when registering users and groups.

## 2022/10/11
* Fix for issue with long descriptions. Project descriptions are now truncated to 256 characters if needed.

## 2022/9/20
* Fix for possible issue with plugin project permissions
* Publish Custom Application name will now contain the Jira instance URL

## 2022/8/29
* Logging updates and improvements

## 2022/4/18
* OS environment variable `COOKIE_TOKEN` changed to `VEZA_API_KEY`
* Connector name changed from `jira_cookie_oaa.py` to `oaa_jira.py`
