# SPDX-FileCopyrightText: 2024 Cisco Systems, Inc. and/or its affiliates
# SPDX-License-Identifier: MIT

from typing import Dict, Optional


def validate_headers(headers: Optional[Dict[str, str]]) -> None:
    if headers is None:
        headers = {}

    problems = []

    headers_seen = set()

    for key, value in headers.items():
        if key is None:
            problems.append("'None' is not a valid header name.")
            continue
        if value is None:
            problems.append("'None' is not a valid header value")
            continue
        if "\x00" in key:
            problems.append(f"Null characters are not valid in header name {key}")
            continue
        if "\x00" in value:
            problems.append(f"Null characters are not valid in header value {value}")
            continue

        key_lower = key.lower()
        if key_lower.startswith("x-duo"):
            if key_lower in headers_seen:
                problems.append(
                    f"Duplicate x-duo headers are not supported, \
                      {key_lower} is duplicated."
                )
            else:
                headers_seen.add(key_lower)

    if problems:
        problem_string = "\n".join(problems)
        raise ValueError(problem_string)
