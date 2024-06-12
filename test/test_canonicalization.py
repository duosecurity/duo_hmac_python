# SPDX-FileCopyrightText: 2024 Cisco Systems, Inc. and/or its affiliates
# SPDX-License-Identifier: MIT

import json
import random
import unittest

from duo_hmac import duo_canonicalize

# Test values
DATE_STRING = "date_string"
HTTP_GET = "GET"
HTTP_POST = "POST"
API_HOST = "test.duosecurity.com"
API_PATH = "/test/the/api"
EMPTY_STRING = ""
# sha512 hash of the empty string; calculated with an external tool
EMPTY_STRING_HASH = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"  # noqa: E501
# sha512 hash of the "empty json" string '{}'; calculated with an external tool
EMPTY_JSON_HASH = "27c74670adb75075fad058d5ceaf7b20c4e7786c83bae8a32f626f9782af34c9a33c2046ef60fd2a7878d378e29fec851806bbd9a67878f3a9f1cda4830763fd"  # noqa: E501

# With GET and no parameters, body, or header, expect:
#   provided date string
#   http method in caps
#   api host in lowercase
#   api path in original case
#   an empty line since there are no query string parameters
#   the sha512 of the empty string since there is no body
#   the sha512 of the empty string since there are no headers
EXPECTED_GET_NO_PARAMS = f"{DATE_STRING}\n{HTTP_GET}\n{API_HOST}\n \
                           {API_PATH}\n{EMPTY_STRING}\n{EMPTY_STRING_HASH}\n \
                           {EMPTY_STRING_HASH}"
# For POST with no parameters, empty body, no headers, the main difference
# is line 6, where we expect the hash of empty json
EXPECTED_POST_NO_PARAMS = f"{DATE_STRING}\n{HTTP_POST}\n{API_HOST}\n \
                            {API_PATH}\n{EMPTY_STRING}\n{EMPTY_JSON_HASH}\n \
                            {EMPTY_STRING_HASH}"


class TestGenerateCanonicalStringBasics(unittest.TestCase):
    # Test the handling of the date string, method, host, and path.
    # The parameter, body, and headers all have dedicated canonicalization
    # methods, tested separately
    def test_get_no_parameter(self):
        actual = duo_canonicalize.generate_canonical_string(
            DATE_STRING, HTTP_GET, API_HOST, API_PATH, None, None, None
        )
        self.assertEqual(EXPECTED_GET_NO_PARAMS, actual)

    def test_post_no_parameter(self):
        actual = duo_canonicalize.generate_canonical_string(
            DATE_STRING, HTTP_POST, API_HOST, API_PATH, None, "{}", None
        )
        self.assertEqual(EXPECTED_POST_NO_PARAMS, actual)

    def test_method_capitalization(self):
        actual = duo_canonicalize.generate_canonical_string(
            DATE_STRING, HTTP_GET.lower(), API_HOST, API_PATH, None, None, None
        )
        self.assertEqual(EXPECTED_GET_NO_PARAMS, actual)

    def test_host_capitalization(self):
        actual = duo_canonicalize.generate_canonical_string(
            DATE_STRING, HTTP_GET, API_HOST.upper(), API_PATH, None, None, None
        )
        self.assertEqual(EXPECTED_GET_NO_PARAMS, actual)


class TestCanonicalizeParameters(unittest.TestCase):

    empty_test_cases = [
        ("Empty dict parameters", {}),
        ("None dict parameters", None),
    ]

    def test_empty_parameters(self):
        for test_name, input in self.empty_test_cases:
            with self.subTest(test_name):
                expected = ""
                actual = duo_canonicalize.canonicalize_parameters(input)

                self.assertEqual(expected, actual)

    test_cases = [
        ("One parameter", {b"realname": [b"First Last"]}, "realname=First%20Last"),
        (
            "Two parameters",
            {b"realname": [b"First Last"], b"username": [b"root"]},
            "realname=First%20Last&username=root",
        ),
        (
            'Mixed "type" parameters',
            {b"words": [b"First Last"], b"success": [b"true"], b"digit": [b"5"]},
            "digit=5&success=true&words=First%20Last",
        ),
        (
            "Test similar keys",
            {
                b"foo_bar": [b"2"],
                b"foo": [b"1"],
            },
            "foo=1&foo_bar=2",
        ),
        (
            "Test ascii printable characters",
            {
                b"digits": [b"0123456789"],
                b"letters": [b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"],
                b"punctuation": [b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"],
                b"whitespace": [b"\t\n\x0b\x0c\r "],
            },
            "digits=0123456789&letters=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ&punctuation=%21%22%23%24%25%26%27%28%29%2A%2B%2C-.%2F%3A%3B%3C%3D%3E%3F%40%5B%5C%5D%5E_%60%7B%7C%7D~&whitespace=%09%0A%0B%0C%0D%20",  # noqa: E501
        ),
        (
            "Test unicode",
            {
                "\u469a\u287b\u35d0\u8ef3\u6727\u502a\u0810\ud091\xc8\uc170": [
                    "\u0f45\u1a76\u341a\u654c\uc23f\u9b09\uabe2\u8343\u1b27\u60d0"
                ],
                "\u7449\u7e4b\uccfb\u59ff\ufe5f\u83b7\uadcc\u900c\ucfd1\u7813": [
                    "\u8db7\u5022\u92d3\u42ef\u207d\u8730\uacfe\u5617\u0946\u4e30"
                ],
                "\u7470\u9314\u901c\u9eae\u40d8\u4201\u82d8\u8c70\u1d31\ua042": [
                    "\u17d9\u0ba8\u9358\uaadf\ua42a\u48be\ufb96\u6fe9\ub7ff\u32f3"
                ],
                "\uc2c5\u2c1d\u2620\u3617\u96b3F\u8605\u20e8\uac21\u5934": [
                    "\ufba9\u41aa\ubd83\u840b\u2615\u3e6e\u652d\ua8b5\ud56bU"
                ],
            },
            "%E4%9A%9A%E2%A1%BB%E3%97%90%E8%BB%B3%E6%9C%A7%E5%80%AA%E0%A0%90%ED%82%91%C3%88%EC%85%B0=%E0%BD%85%E1%A9%B6%E3%90%9A%E6%95%8C%EC%88%BF%E9%AC%89%EA%AF%A2%E8%8D%83%E1%AC%A7%E6%83%90&%E7%91%89%E7%B9%8B%EC%B3%BB%E5%A7%BF%EF%B9%9F%E8%8E%B7%EA%B7%8C%E9%80%8C%EC%BF%91%E7%A0%93=%E8%B6%B7%E5%80%A2%E9%8B%93%E4%8B%AF%E2%81%BD%E8%9C%B0%EA%B3%BE%E5%98%97%E0%A5%86%E4%B8%B0&%E7%91%B0%E9%8C%94%E9%80%9C%E9%BA%AE%E4%83%98%E4%88%81%E8%8B%98%E8%B1%B0%E1%B4%B1%EA%81%82=%E1%9F%99%E0%AE%A8%E9%8D%98%EA%AB%9F%EA%90%AA%E4%A2%BE%EF%AE%96%E6%BF%A9%EB%9F%BF%E3%8B%B3&%EC%8B%85%E2%B0%9D%E2%98%A0%E3%98%97%E9%9A%B3F%E8%98%85%E2%83%A8%EA%B0%A1%E5%A4%B4=%EF%AE%A9%E4%86%AA%EB%B6%83%E8%90%8B%E2%98%95%E3%B9%AE%E6%94%AD%EA%A2%B5%ED%95%ABU",  # noqa: E501
        ),
    ]

    def test_canonicalize_parameters(self):
        for test_name, input, expected in self.test_cases:
            with self.subTest(test_name):
                actual = duo_canonicalize.canonicalize_parameters(input)

                self.assertEqual(expected, actual)

    def test_parameter_sorting(self):
        test_keys = [
            b"one",
            b"two",
            b"three",
            b"four",
            b"five",
            b"six",
            b"seven",
            b"eight",
            b"nine",
        ]
        random.shuffle(test_keys)
        test_order_1 = {key: [key] for key in test_keys}
        random.shuffle(test_keys)
        test_order_2 = {key: [key] for key in test_keys}
        random.shuffle(test_keys)
        test_order_3 = {key: [key] for key in test_keys}

        actual_1 = duo_canonicalize.canonicalize_parameters(test_order_1)
        actual_2 = duo_canonicalize.canonicalize_parameters(test_order_2)
        actual_3 = duo_canonicalize.canonicalize_parameters(test_order_3)

        self.assertEqual(actual_1, actual_2)
        self.assertEqual(actual_2, actual_3)


class TestCanonicalizeBody(unittest.TestCase):
    empty_test_cases = [("Empty string body", ""), ("None string body", None)]

    def test_empty_body(self):
        for test_name, input in self.empty_test_cases:
            with self.subTest(test_name):
                expected = EMPTY_STRING_HASH
                actual = duo_canonicalize.canonicalize_body(input)

                self.assertEqual(expected, actual)

    # Each expected value was calculated with an external tool
    test_cases = [
        (
            "Ascii string body",
            "I am an ascii string",
            "c1710f1224e4973bfbb9ca1a297e63756a4b1736ebd1b646ba3d63a392b73d24a52ac8b4afb6eafca6dfe91f09e2e75117c377398a7d2f22136b05c038b94151",  # noqa: E501
        ),
        (
            "Unicode string body",
            "î ❤ ựṉịʗƠΔѤ",
            "b713c8cc2bfe672cf55133d81ca6fa802628c7c8968d444c186434146bcd0275a510d3fd725b0a8132882c4a60d8457420f252f84e4edd00fcf12aa7c4eb2246",  # noqa: E501
        ),
        (
            "JSON string body",
            json.dumps(
                {"foo": "bar", "baz": 1, "nested": {"objects": {"are": {"neat": True}}}}
            ),
            "cd97c6ef2f1db6a660f2b7b71235d16902d532e3a4b54afc07acebbf34a265d8f77c344706f3222bcb28009d8c4c5259daa388bddb7dcc1b163982dce6a0c1ec",  # noqa: E501
        ),
    ]

    def test_canonicalize_body(self):
        for test_name, input, expected in self.test_cases:
            with self.subTest(test_name):
                actual = duo_canonicalize.canonicalize_body(input)

                self.assertEqual(expected, actual)


class TestCanonicalizeXDuoHeaders(unittest.TestCase):
    empty_test_cases = [("Empty dict of headers", {}), ("None dict of headers", None)]

    def test_empty_headers(self):
        for test_name, input in self.empty_test_cases:
            with self.subTest(test_name):
                expected = EMPTY_STRING_HASH
                actual = duo_canonicalize.canonicalize_x_duo_headers(input)

                self.assertEqual(expected, actual)

    def test_case_insensitive(self):
        mixed_case_headers = {
            "x-duo-A": "header_value_1",
            "X-Duo-B": "header_value_2",
        }

        # Calculated with an external tool expecting lowercase header keys
        expected = "60be11a30e0756f2ee2afdce1db849b987dcf86c1133394bd7bbbc9877920330c4d78aceacbb377ab8cbd9a8efe6a410fed4047376635ac71226ab46ca10d2b1"  # noqa: E501
        actual = duo_canonicalize.canonicalize_x_duo_headers(mixed_case_headers)

        self.assertEqual(expected, actual)

    def test_header_sorting(self):
        test_keys = [
            "x-duo-one",
            "x-duo-two",
            "x-duo-three",
            "x-duo-four",
            "x-duo-five",
            "x-duo-six",
            "x-duo-seven",
        ]
        random.shuffle(test_keys)
        test_order_1 = {key: key for key in test_keys}
        random.shuffle(test_keys)
        test_order_2 = {key: key for key in test_keys}
        random.shuffle(test_keys)
        test_order_3 = {key: key for key in test_keys}

        actual_1 = duo_canonicalize.canonicalize_x_duo_headers(test_order_1)
        actual_2 = duo_canonicalize.canonicalize_x_duo_headers(test_order_2)
        actual_3 = duo_canonicalize.canonicalize_x_duo_headers(test_order_3)

        self.assertEqual(actual_1, actual_2)
        self.assertEqual(actual_2, actual_3)
