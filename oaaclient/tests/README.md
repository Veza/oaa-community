# OAA Client Tests

## Running tests

Tests are managed by `tox`. To run all tests invoke `tox` from the `ooaclient` directory

By default `tox` with try to run python 3.8, 3.9 and 3.10, a coverage report and flake8 (exit-zero). You can run a single environment with `tox -e py38` for speed.

### Testing with a Veza instance

By default the tests all run stand-alone and do not require a Veza instance to connect to.

To run the complete tests, which include pushing a payload to Veza, set the OS environment variables `PYTEST_VEZA_HOST` and `VEZA_API_KEY` with the hostname and API key respectively.

> If testing with a local instance of Veza using unsigned certificates set `VEZA_UNSAFE_HTTPS=true`

### Test Timeouts

Tests validate Veza parsing after OAA push have a default timeout. If the data source does not change from the pending
state within the timeout the test will fail. The timeout can be over-ridden with the OS environment variable
`OAA_PUSH_TIMEOUT` which is a number in seconds for the timeout.
