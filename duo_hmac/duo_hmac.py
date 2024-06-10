# SPDX-FileCopyrightText: 2024 Cisco Systems, Inc. and/or its affiliates
# SPDX-License-Identifier: MIT

import base64
import hashlib
import hmac
import urllib.parse


from . import duo_canonicalize, duo_hmac_utils, duo_hmac_validation

class DuoHmac():
  def __init__(self, ikey: str, skey: str, api_host: str, date_string_provider: duo_hmac_utils.DateStringProvider = None):
    self.ikey = ikey
    self.skey = skey
    self.api_host = api_host
    if date_string_provider is None:
      self.date_string_provider = duo_hmac_utils.UTCNowDateStringProvider()
    else:
      self.date_string_provider = date_string_provider
    
  def get_authentication_components(
      self,
      http_method: str,
      api_path: str,
      parameters: dict = None,
      in_headers: dict[str, str] = None
    ) -> tuple[str, str, dict[str, str]]:
    """
    Use the provided request components and calculate
      - The final url (host + path + query string)
      - The request body (if any)
      - The request headers (including the authorization header per Duo's HMAC specification)
    """
    duo_hmac_validation.validate_headers(in_headers)

    # We'll be manipulating the headers, so make a copy of them first just in case
    if in_headers is None:
      in_headers = {}
    else:
      in_headers = dict(in_headers)

    # We need the request timestamp in RFC 2822 format
    date_string = self.date_string_provider.get_rfc_2822_date_string()

    # Duo does not currently support splitting parameters between the query string and body.
    # Put parameters in the correct place depending on the http method 
    # (body for POST, PUT, and PATCH, query string otherwise)
    params_go_in_body = http_method.upper() in ('POST', 'PUT', 'PATCH')
    qs_parameters, body = duo_hmac_utils.prepare_parameters(parameters, params_go_in_body)

    # Always send the date string in x-duo-date
    in_headers['x-duo-date'] = date_string

    # Extract the x-duo headers
    x_duo_headers = duo_hmac_utils.extract_x_duo_headers(in_headers)

    # Calculate the Authorization header from the pieces of the request
    authn_header = self._generate_authentication_header(date_string, http_method, api_path, qs_parameters, body, x_duo_headers)

    # Assemble the final uri by appending the encoded query string, if any
    uri = f'{self.api_host}{api_path}'
    query_string = urllib.parse.urlencode(qs_parameters, doseq=True)
    if query_string:
      uri = f'{uri}?{query_string}'

    # Assemble final headers from input headers, authorization header, and content-type header
    out_headers = dict(in_headers)
    out_headers['Authorization'] = authn_header
    if params_go_in_body:
       out_headers['Content-type'] = 'application/json'

    return (uri, body, out_headers)

    
  def _generate_authentication_header(
      self,
      date_string: str,
      http_method: str,
      api_path: str,
      qs_parameters: dict[bytes, list[bytes]],
      body: str,
      x_duo_headers: dict[str, str]
    ) -> str:
    """
    Calculate the authentication header from the request components
    1. Generate the 'canonical string' of the request
    2. SHA512 signature of the canonical string, using the SKEY as the secret
    3. Hex digest the signature
    4. Append the hex digest to the IKEY, colon separated
    5. Encode the IKEY:hex in base 64
    6. Append the b64 to the string "Basic"
    """
    canon_string = duo_canonicalize.generate_canonical_string(date_string, http_method, self.api_host, api_path, qs_parameters, body, x_duo_headers)
    sig_hmac = self._sign_canonical_string(canon_string)

    auth = f"{self.ikey}:{sig_hmac.hexdigest()}"
    auth_bytes = auth.encode('utf-8')
    auth_b64 = base64.b64encode(auth_bytes)
    b64 = auth_b64.decode('utf-8')

    return f"Basic {b64}"

  def _sign_canonical_string(self, canon_string: str) -> hmac.HMAC:
    """ Generate the SHA512 signature of the canonical string using the SKEY as the shared secret """
    skey_bytes = self.skey.encode('utf-8')
    canon_bytes = canon_string.encode('utf-8')

    return hmac.new(skey_bytes, canon_bytes, hashlib.sha512)
