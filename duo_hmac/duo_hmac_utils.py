# SPDX-FileCopyrightText: 2024 Cisco Systems, Inc. and/or its affiliates
# SPDX-License-Identifier: MIT

import email.utils
import json

from typing import Protocol


def prepare_parameters(
    parameters: dict, params_go_in_body: bool
) -> tuple[dict[bytes, list[bytes]], str]:
    """
    Prepare the parameters: JSONize them if they'll go in the body,
    or normalize them if they'll go in the query string.
    """
    # Default values
    qs_parameters: dict = {}
    body: str = None

    if params_go_in_body:
        body = jsonize_parameters(parameters)
    else:
        qs_parameters = normalize_parameters(parameters)

    return (qs_parameters, body)


def jsonize_parameters(parameters: dict) -> str:
    """Turn a parameter dictionary into a JSON string"""
    if parameters is None:
        # Is this the best choice?  Should we return None instead (or allow
        # json.dumps to return None)?
        parameters = {}

    return json.dumps(parameters, sort_keys=True, separators=(",", ":"))


def normalize_parameters(parameters: dict) -> dict[bytes, list[bytes]]:
    """
    Return copy of params with everything stringified and listified
    """
    if parameters is None:
        return {}

    # urllib cannot handle unicode strings properly. quote() excepts,
    # and urlencode() replaces them with '?'.
    def encode(value):
        if isinstance(value, bool):
            if value:
                value = "true"
            else:
                value = "false"
        elif isinstance(value, int):
            value = str(value)
        if isinstance(value, str):
            return value.encode("utf-8")
        return value

    def to_list(value):
        if value is None or isinstance(value, str):
            return [value]
        return value

    return dict(
        (encode(key), [encode(v) for v in to_list(value)])
        for (key, value) in list(parameters.items())
    )


def extract_x_duo_headers(in_headers: dict[str, str]) -> dict[str, str]:
    """Extract all headers that start with 'x-duo' from the provided input headers"""
    if in_headers is None:
        return {}

    return {
        key: value
        for (key, value) in in_headers.items()
        if key.lower().startswith("x-duo")
    }


class DateStringProvider(Protocol):
    def get_rfc_2822_date_string(self) -> str: ...


class UTCNowDateStringProvider(DateStringProvider):
    def get_rfc_2822_date_string(self) -> str:
        return email.utils.formatdate()
