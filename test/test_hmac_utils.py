# SPDX-FileCopyrightText: 2024 Cisco Systems, Inc. and/or its affiliates
# SPDX-License-Identifier: MIT

import unittest

from duo_hmac import duo_hmac_utils


class TestJsonizeParameters(unittest.TestCase):
  # Only test empty inputs, because there's no point in testing json.dumps ourselves
  test_cases = [
    ('Test empty input', {}, '{}'),
    ('Test None input', {}, '{}'),
  ]

  def test_empty_input(self):
    for test_name, input, expected in self.test_cases:
      with self.subTest(test_name):
        actual = duo_hmac_utils.jsonize_parameters(input)
        self.assertEqual(expected, actual)


class TestNormalizeParameters(unittest.TestCase):
  empty_test_cases = [
    ('Empty parameters', {}),
    ('None parameters', None),
  ]
  def test_empty_parameters(self):
    for test_name, input in self.empty_test_cases:
      with self.subTest(test_name):
        actual = duo_hmac_utils.normalize_parameters(input)

        self.assertDictEqual({}, actual)

  unsupported_types_cases = [
    ('Integer value', {'string': 1}),
    ('Boolean value', {'string': True}),
  ]
  def test_unsupported_value_types(self):
    for test_name, input in self.unsupported_types_cases:
      with self.subTest(test_name):
        with self.assertRaises(TypeError):
          duo_hmac_utils.normalize_parameters(input)


  simple_type_test_cases = [
    ('None value', {'string': None}, {b'string': [None]}),
    ('String value', {'string': 'string'}, {b'string': [b'string']})
  ]
  def test_simple_value_types(self):
    for test_name, input, expected in self.simple_type_test_cases:
      with self.subTest(test_name):
        actual = duo_hmac_utils.normalize_parameters(input)

        self.assertDictEqual(expected, actual)

  list_type_test_cases = [
    ('Boolean 1-item list value', {'string': [True]}, {b'string': [b'true']}),
    ('Boolean multi-item list value', {'string': [True, False, True]}, {b'string': [b'true', b'false', b'true']}),
    ('Integer 1-item list value', {'string': [1]}, {b'string': [b'1']}),
    ('Integer multi-item list value', {'string': [1, 2, 3]}, {b'string': [b'1', b'2', b'3']}),
    ('String 1-item list value', {'string': ['string']}, {b'string': [b'string']}),
    ('String multi-item list value', {'string': ['st', 'ri', 'ng']}, {b'string': [b'st', b'ri', b'ng']}),
  ]
  def test_list_value_types(self):
    for test_name, input, expected in self.list_type_test_cases:
      with self.subTest(test_name):
        actual = duo_hmac_utils.normalize_parameters(input)

        self.assertDictEqual(expected, actual)

  def test_multiple_parameters(self):
    test_input = {
      'string1': 'string1',
      'string2': 'string2',
      'integer1': '1',
      'boolean1': 'true',
      'string_list': ['string3', 'string4', 'string5']
    }

    # Normalization doesn't care about ordering of the dict
    expected = {
      b'boolean1': [b'true'],
      b'string2': [b'string2'],
      b'string1': [b'string1'],
      b'integer1': [b'1'],
      b'string_list': [b'string3', b'string4', b'string5']
    }

    actual = duo_hmac_utils.normalize_parameters(test_input)
    self.assertDictEqual(expected, actual)

  # None of these make any sense, but they work!  Hopefully we can break them all some day by enforcing sensible typing
  edge_case_test_cases = [
    ('None 1-item list value', {'string': [None]}, {b'string': [None]}),
    ('None multi-item list value', {'string': [None, None]}, {b'string': [None, None]}),
    ('String tuple value', {'string': ('tu', 'ple')}, {b'string': [b'tu', b'ple']}),
    ('Integer tuple value', {'string': (1, 2)}, {b'string': [b'1', b'2']}),
    ('Mixed type tuple value', {'string': (1, '1', True)}, {b'string': [b'1', b'1', b'true']}),
    ('Mixed type list value', {'string': [1, '1', True]}, {b'string': [b'1', b'1', b'true']}),
    ('Dict type value', {'string': {'integer': 1, 'boolean': True, 'other_string': 'other_string'}}, {b'string': [b'integer', b'boolean', b'other_string']})
  ]
  def test_edge_cases(self):
    for test_name, input, expected in self.edge_case_test_cases:
      with self.subTest(test_name):
        actual = duo_hmac_utils.normalize_parameters(input)
        self.assertDictEqual(expected, actual)
  
  unicode_test_cases = [
    # Unicode code points and hex values
    # Š u0160 (hex c5 a0)
    # ț u021b (hex c8 9b)
    # ɍ u024d (hex c9 8d)
    # ì u00ec (hex c3 ac)
    # И u0418 (hex d0 98)
    # Ɠ u0193 (hex c6 93)
    ('Unicode string key', {'Šțɍ': 'ing'}, {b'\xc5\xa0\xc8\x9b\xc9\x8d': [b'ing']}),
    ('Unicode string value', {'str': 'ìИƓ'}, {b'str': [b'\xc3\xac\xd0\x98\xc6\x93']}),
    ('Unicode string key and value', {'Šțɍ': 'ìИƓ'}, {b'\xc5\xa0\xc8\x9b\xc9\x8d': [b'\xc3\xac\xd0\x98\xc6\x93']}),
    ('Unicode string list value', {'Šțɍ': ['ì', 'И', 'Ɠ']}, {b'\xc5\xa0\xc8\x9b\xc9\x8d': [b'\xc3\xac', b'\xd0\x98', b'\xc6\x93']})
  ]
  def test_unicode(self):
    for test_name, input, expected in self.unicode_test_cases:
      with self.subTest(test_name):
        actual = duo_hmac_utils.normalize_parameters(input)

        self.assertDictEqual(expected, actual)


class TestExtractXDuoHeaders(unittest.TestCase):
  test_cases = [
    ('Empty input', {}, {}),
    ('None input', None, {}),
    ('One x-duo header', {'x-duo-foo': 'bar'}, {'x-duo-foo': 'bar'}),
    ('One non-x-duo header', {'foo': 'bar'}, {}),
    ('Multiple all x-duo headers', {'x-duo-one': 'one', 'x-duo-two': 'two'}, {'x-duo-one': 'one', 'x-duo-two': 'two'}),
    ('Multiple no x-duo headers', {'one': 'one', 'two': 'two'}, {}),
    ('Multiple mixed headers', {'x-duo-one': 'one', 'two': 'two'}, {'x-duo-one': 'one'})
  ]
  def test_extract_x_duo_headers(self):
    for test_name, input, expected in self.test_cases:
      with self.subTest(test_name):
        actual = duo_hmac_utils.extract_x_duo_headers(input)
        self.assertDictEqual(expected, actual)

  def test_filtering_edge_cases(self):
    test_input = {
      'x-duo-': 'x-duo-',
      'x-duo-foo': 'foo',
      'xduo': 'xduo',
      'duo-foo': 'foo',
      'x-duo-x-duo-foo': 'foo',
      'duo-foo': 'x-duo-foo',
      'foo-x-duo': 'foo',
    }

    expected = {
      'x-duo-': 'x-duo-',
      'x-duo-foo': 'foo',
      'x-duo-x-duo-foo': 'foo',
    }
    actual = duo_hmac_utils.extract_x_duo_headers(test_input)
    self.assertEqual(expected, actual)

  def test_case_insensitive(self):
    test_input = {
      'X-duo-foo': 'foo',
      'x-duo-foo': 'foo',
      'X-DUO-foo': 'foo',
      'X-dUo-FOo': 'foo',
    }

    expected = {
      'X-dUo-FOo': 'foo',
      'x-duo-foo': 'foo',
      'X-DUO-foo': 'foo',
      'X-duo-foo': 'foo',
    }
    actual = duo_hmac_utils.extract_x_duo_headers(test_input)
    self.assertEqual(expected, actual)
