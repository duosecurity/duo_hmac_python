# SPDX-FileCopyrightText: 2024 Cisco Systems, Inc. and/or its affiliates
# SPDX-License-Identifier: MIT

import unittest

from duo_hmac import duo_hmac, duo_hmac_utils

IKEY = "DIABCDEFGHIJKLMNOPQR"
SKEY = "testtesttesttesttesttesttesttesttesttest"
API_HOST = "api-xxxxxxxx.duosecurity.com"
API_PATH = "/api/path"

HTTP_GET = "GET"
HTTP_POST = "POST"

DATE_STRING = "Fri, 24 May 2024 12:00:00 -0000"


class TestDateStringProvider(duo_hmac_utils.DateStringProvider):
    def get_rfc_2822_date_string(self) -> str:
        return DATE_STRING


class TestHmac(unittest.TestCase):
    def setUp(self) -> None:
        self.hmac = duo_hmac.DuoHmac(IKEY, SKEY, API_HOST, TestDateStringProvider())

        return super().setUp()

    def assert_components(
        self, method, params, headers, expected_uri, expected_body, expected_headers
    ):
        actual_uri, actual_body, actual_headers = (
            self.hmac.get_authentication_components(method, API_PATH, params, headers)
        )
        self.assertEqual(expected_uri, actual_uri)
        self.assertEqual(expected_body, actual_body)
        self.assertDictEqual(expected_headers, actual_headers)

    # For all tests, the expected Authorization header was calculated using
    # duo_client_python

    def test_get_no_params_no_headers(self):
        expected_uri = f"{API_HOST}{API_PATH}"
        expected_body = None
        expected_headers = {
            "x-duo-date": DATE_STRING,
            "Authorization": "Basic RElBQkNERUZHSElKS0xNTk9QUVI6YzQ1NDYzOWQ3NWI0ZTNkOTliOGIxZDVlNDFjZDdiYjJkMmQ4YmE1NWY2ODExZjc4NmRmYjBlZGQ0ZmFjZDJmM2E1ZTZkNmM4MzdmMzFmNjgyNjcwNjMyNWI0ZWQ3ZGNkYzVmMTExNjQ5NDhlNTdhNzAzMmE1MjQ5OTBlMDE1ODM=",  # noqa: E501
        }

        self.assert_components(
            HTTP_GET, None, None, expected_uri, expected_body, expected_headers
        )

    def test_post_no_params_no_headers(self):
        expected_uri = f"{API_HOST}{API_PATH}"
        expected_body = "{}"
        expected_headers = {
            "x-duo-date": DATE_STRING,
            "Content-type": "application/json",
            "Authorization": "Basic RElBQkNERUZHSElKS0xNTk9QUVI6MTJhMDVkNzgzYjJlNThlMzZmMzdkZjhhNjkwNzgzNTQ5NmZiZTIwZmIzZDA0YjE1MDM2YzgyYjE2OTRmYzU4ZDFjMDQ1MWI5MzdmYjliYTZlN2MyYjQ0ZDg5YjQ3M2FmNzA4MTY2MTgzZDIxNmFlYTEzZTUyNzQyYTU3ZjIzOWY=",  # noqa: E501
        }

        self.assert_components(
            HTTP_POST, None, None, expected_uri, expected_body, expected_headers
        )

    def test_get_one_param_no_headers(self):
        expected_uri = f"{API_HOST}{API_PATH}?foo=bar"
        expected_body = None
        expected_headers = {
            "x-duo-date": DATE_STRING,
            "Authorization": "Basic RElBQkNERUZHSElKS0xNTk9QUVI6ODhmZTgwZjNiMjQyYjk5MmY0YjMwMTQwOGQ1MjRhODg2Mjc0ZDNlZDBjNGM3YmQxODRlMWI0ZmYzNzhlNjhlYTA1ZDk0MzNjMDk5MzgwNzhjNDk1MTdhNmM0MjY0Yzk1MGJlOWZmNWNjMjhhZDJkNDQ4Y2VhMjRiYzkzODg3Y2E=",  # noqa: E501
        }

        in_params = {"foo": "bar"}
        self.assert_components(
            HTTP_GET, in_params, None, expected_uri, expected_body, expected_headers
        )

    def test_post_one_param_no_headers(self):
        expected_uri = f"{API_HOST}{API_PATH}"
        expected_body = '{"foo":"bar"}'
        expected_headers = {
            "x-duo-date": DATE_STRING,
            "Content-type": "application/json",
            "Authorization": "Basic RElBQkNERUZHSElKS0xNTk9QUVI6NjQzNzcwYWYzMTAwNmM1ODRhNzU4ZDkyNjI1MGU0NmE5MGQ3OTEwMGQyMWY3YTAzMTNjM2U3N2Q2NGZhM2M1ZDJjOTRlMmM5MDgxYTJiNjUzNDNjYzNkNWYyZWQyMWY3MzAwZWE1MGIwMDY0MGNiMTc2MGYzMjMxOTIzMDdkMzc=",  # noqa: E501
        }

        in_params = {"foo": "bar"}
        self.assert_components(
            HTTP_POST, in_params, None, expected_uri, expected_body, expected_headers
        )

    def test_get_multi_param_multi_headers(self):
        expected_uri = f"{API_HOST}{API_PATH}?foo=bar&one=1&bool=true"
        expected_body = None
        expected_headers = {
            "x-duo-foo": "bar",
            "x-duo-bar": "foo",
            "non-duo-bar": "duo",
            "x-duo-date": DATE_STRING,
            "Authorization": "Basic RElBQkNERUZHSElKS0xNTk9QUVI6ZDQ2NTU2NzI2ODAwNDE1ZGM3OGNlZmMzZmI0ZTExZGNmM2VlMTM0MjkwNGYyNzZlZDVjOGUzNDI3ODc4YmQ1Mzc2ZWE2YzU1NTFiOTBiZjcwN2ZhYjUzZjZmMWQyMGExMTQ4OTg4OTg3MDVkMjgyNjg4MjRlZGQwYmU1ZjFkNTM=",  # noqa: E501
        }

        in_params = {"foo": "bar", "one": "1", "bool": "true"}
        in_headers = {
            "x-duo-foo": "bar",
            "x-duo-bar": "foo",
            "non-duo-bar": "duo",
        }
        self.assert_components(
            HTTP_GET,
            in_params,
            in_headers,
            expected_uri,
            expected_body,
            expected_headers,
        )

    def test_post_multi_params_multi_headers(self):
        expected_uri = f"{API_HOST}{API_PATH}"
        expected_body = '{"bool":"true","foo":"bar","one":"1"}'
        expected_headers = {
            "x-duo-foo": "bar",
            "x-duo-bar": "foo",
            "non-duo-bar": "duo",
            "x-duo-date": DATE_STRING,
            "Content-type": "application/json",
            "Authorization": "Basic RElBQkNERUZHSElKS0xNTk9QUVI6ZGVmN2I3MzU5YjAzOTk1NDNiNjFkM2QxYTQyNTJjMTkwOGViNDg2MDM5MTY4YWE3ZDFjOTM1NDVmMDUyZTEyMTA2MmU0ZDBkM2NhZTgwZjBmMTI1ZGM0OTdjNDNjNTNiNjJjOWRiNThjYWNkMjEzOTRhM2IxN2FkOTcyZTM3OTM=",  # noqa: E501
        }

        in_params = {"foo": "bar", "one": "1", "bool": "true"}
        in_headers = {
            "x-duo-foo": "bar",
            "x-duo-bar": "foo",
            "non-duo-bar": "duo",
        }
        self.assert_components(
            HTTP_POST,
            in_params,
            in_headers,
            expected_uri,
            expected_body,
            expected_headers,
        )

    def test_post_non_string_parameter_types(self):
        expected_uri = f"{API_HOST}{API_PATH}"
        expected_body = '{"bool":"true","foo":"bar","one":"1"}'
        expected_headers = {
            "x-duo-date": DATE_STRING,
            "Content-type": "application/json",
            "Authorization": "Basic RElBQkNERUZHSElKS0xNTk9QUVI6NjhjYWI2YTQyYmUyMTZhMGUwNTU3NzJlZDhkODg3MGIzODNmYzk4NmVlNGJkN2I5MjM0Njg5ZTIzOWJlNjc3YzhlZGY2MWUzM2VhZGRkODNlMmI5NDE0Yzk4ZmYzMGJmY2EwYmYyZTFmNDQ4MzEwNzRmNWM0NzRiZjRhZjlmZDc=",  # noqa: E501
        }

        in_params = {"foo": "bar", "one": "1", "bool": "true"}
        self.assert_components(
            HTTP_POST, in_params, None, expected_uri, expected_body, expected_headers
        )

    # As written, non-string parameters don't work for GET calls.  This is
    # arguably a bug but test the existing behavior for now
    def test_unsupported_get_parameter_types(self):
        in_params1 = {
            "foo": "bar",
            "integer": 1,
        }

        in_params2 = {"foo": "bar", "boolean": True}

        with self.assertRaises(TypeError):
            self.hmac.get_authentication_components(HTTP_GET, API_PATH, in_params1)

        with self.assertRaises(TypeError):
            self.hmac.get_authentication_components(HTTP_GET, API_PATH, in_params2)
