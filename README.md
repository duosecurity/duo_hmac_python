# Overview

This repository provides an implementation of Duo's current API authentication scheme independent of any HTTP/REST client.

Currently this supports the Auth API, Admin API, and Accounts API.

It is a pure python library with no third-party runtime dependencies, so it should be suitable in any Python HTTP client you wish to use.

## Tested Against Python Versions
* 3.8
* 3.9
* 3.10
* 3.11

## Requirements

Duo_hmac_python requires Python 3.8 or higher.

# Installation

Install from [PyPi](https://pypi.org/project/duo_hmac/)
```
pip install duo_hmac
```

# Usage

Instantiate a DuoHmac object with your API credentials from the Duo Admin Panel.
```
from duo_hmac.duo_hmac import DuoHmac

duo = DuoHmac(IKEY, SKEY, API_HOST)
```

See the Duo API reference documentation for the details of the API calls:
* [Duo Admin API](https://duo.com/docs/adminapi)
* [Duo Auth API](https://duo.com/docs/authapi)
* [Duo Accounts API](https://duo.com/docs/accountsapi)

Then provide the API call information according to the documentation for the API call you wish to use:
* HTTP Method
* Path of the API call
* (Optional) API call parameters
* (Optional) Any additional headers

The values returned are:
* The uri, query string included, to use for the API call
* The request body, if any
* The full set of header values that need to be sent
```
url, body, headers = duo.get_authentication_components(METHOD, API_PATH, PARAMETERS, HEADERS)
```

## Helper scripts

Two CLI helper scripts are provided in this repository.  Provide your Duo API credentials in the duo.conf file to use these scripts.

### Check Credentials

This script supports Admin or Auth API credentials.  

It will attempt to authenticate against the Duo APIs and report if your credentials were valid.  If this script fails, it is likely the credentials are incorrect, or there are problems connecting to Duo.
```
./check_credentials.py
```
or
```
python -m check_credentials
```

### Generate Curl Call

This script supports Admin, Auth, or Accounts API credentials.

This script accepts API call information via CLI flags and outputs a curl command that can make an API request.  This is useful for exploring the APIs, or determining the correct authentication header for an API call.

Use the -h flag to see usage instructions
```
./generate_curl_call.py -h
```
or
```
python -m generate_curl_call -h
```

# Development

For this library, Duo accepts GitHub issues as bug reports or for proposed changes.  If you want to contribute via a PR, please ensure you include new tests as appropriate, and that the tests all pass.  Please also confirm that your code meets the PEP8 style standards.  You can run the tests and linter as noted below.

## Testing

```
python -m unittest discover test/
```

## Linting

```
python -m flake8
```