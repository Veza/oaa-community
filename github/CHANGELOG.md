# GitHub Connector Change Log

## 2922/5/25
* Converted log output to `logging` module for better output and improved messages for clarity

## 2022/4/26
* Truncate repository description length to 256, the maximum supported length for OAA resource descrition.

## 2022/4/18
* OS environment variable `OAA_TOKEN` changed to `VEZA_API_KEY`
* Added new custom properties to extraction:
  - Repository `visibility`, `default_branch`, `default_branch_protected` and `allow_forking`, see [README](README.md) for details.
