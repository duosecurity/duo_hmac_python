# SPDX-FileCopyrightText: 2024 Cisco Systems, Inc. and/or its affiliates
# SPDX-License-Identifier: MIT

import unittest

from duo_hmac import duo_hmac_validation


class TestValidateHeaders(unittest.TestCase):
    empty_header_tests = [
        ("Empty dictionary", {}),
        ("None dictionary", None),
    ]

    def test_empty_headers_success(self):
        for test_name, input in self.empty_header_tests:
            with self.subTest(test_name):
                # Should not throw an error
                duo_hmac_validation.validate_headers(input)

    def test_valid_headers_success(self):
        input_headers = {
            "header name 1": "header value 1",
            "header name 2": "header value 2",
            "x-duo-header": "x-duo-value",
            "X-Duo-fOO": "x-duo-bar",
        }

        # Should not throw an error
        duo_hmac_validation.validate_headers(input_headers)

    bad_key_or_value_test_cases = [
        ("None key", {None: "none key"}),
        ("None value", {"none value": None}),
        ("Null character in key", {"\x00" + "null": "value"}),
        ("Null character in value", {"key": "\x00" + "null"}),
    ]

    def test_bad_key_or_value(self):
        for test_name, input in self.bad_key_or_value_test_cases:
            with self.subTest(test_name):
                with self.assertRaises(ValueError):
                    duo_hmac_validation.validate_headers(input)

    def test_duplicate_detection(self):
        input_headers = {
            "x-duo-a": "A",
            "X-duo-a": "B",
        }

        expected_duplicates = ["x-duo-a"]

        with self.assertRaises(ValueError) as ve:
            duo_hmac_validation.validate_headers(input_headers)
            print(ve.msg)

            for expected_duplicate in expected_duplicates:
                assert f"{expected_duplicate} is duplicated" in ve.exception.msg
