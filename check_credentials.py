#! /bin/python3

import configparser
import json

import requests

from duo_hmac import duo_hmac

CONFIG_FILE = "duo.conf"
DUO_SECTION = "duo"
IKEY_KEY = "ikey"
SKEY_KEY = "skey"
API_HOST_KEY = "api_host"


def main():
    # Read from config or error out
    ikey, skey, api_host = _read_config()
    duo = duo_hmac.DuoHmac(ikey, skey, api_host)

    # Try to call 'check' and look at return
    status_code, json_content = _attempt_api_call(duo, "/auth/v2/check")

    if status_code == 200:
        print("Your credentials successfully called the Auth API")
        return

    if not json_content:
        print(f"API call failed with status {status_code}")
        return

    if json_content["code"] != 40301:
        print(f"API call failed with status {status_code}: {json_content['message']}")
        return

    # if 40301, creds are probably admin; try settings endpoint
    status_code, json_content = _attempt_api_call(duo, "/admin/v1/settings")

    if status_code == 200:
        print("Your credentials successfully called the Admin API")
    elif json_content:
        print(f"API call failed with status {status_code}: {json_content['message']}")
    else:
        print(f"API call failed with status code {status_code}")


def _attempt_api_call(duo, path):
    uri, _, headers = duo.get_authentication_components("GET", path, {}, {})

    response = requests.get(f"https://{uri}", headers=headers)

    status_code = response.status_code
    json_content = json.loads(response.content)

    return status_code, json_content


def _read_config():
    cp = configparser.ConfigParser()
    cp.read(CONFIG_FILE)

    if not cp.sections():
        raise FileNotFoundError(
            f"Config file {CONFIG_FILE} seems to be missing or empty."
        )

    if "duo" not in cp.sections():
        raise ValueError(
            f"Config file {CONFIG_FILE} seems to be missing a '{DUO_SECTION}' section."
        )

    ikey = cp[DUO_SECTION][IKEY_KEY]
    if not ikey:
        raise ValueError(
            f"Missing entry for '{IKEY_KEY}' in {CONFIG_FILE} '{DUO_SECTION}'"
        )

    skey = cp[DUO_SECTION][SKEY_KEY]
    if not skey:
        raise ValueError(
            f"Missing entry for '{SKEY_KEY}' in {CONFIG_FILE} '{DUO_SECTION}'"
        )

    api_host = cp[DUO_SECTION][API_HOST_KEY]
    if not api_host:
        raise ValueError(
            f"Missing entry for '{API_HOST_KEY}' in {CONFIG_FILE} '{DUO_SECTION}'"
        )

    return ikey, skey, api_host


if __name__ == "__main__":
    main()
