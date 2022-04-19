# OAA Client Tests

## Running test
Tests are managed by `tox`, to run all tests invoke `tox` from the `ooaclient` directory

By default `tox` with try to run python 3.8, 3.9 and 3.10, a coverage report and flake8 (exit-zero). You can run a single environment with `tox -e py38` for speed. 

## Testing with Veza Instance
By default the tests all run stand-alone and do not require a Veza instance to connect to. To run the complete tests
which include pushing payload to Veza set the OS environment variables `PYTEST_VEZA_HOST` and `VEZA_API_KEY` with
the hostname and API key respectively. If testing with a local instance of Veza with unsigned certificates set `VEZA_UNSAFE_HTTPS=true`
