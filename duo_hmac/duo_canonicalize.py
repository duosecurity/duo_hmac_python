import hashlib
import urllib.parse


def generate_canonical_string(date_string: str, 
                              http_method: str, 
                              api_host: str, 
                              api_path: str, 
                              qs_parameters: dict[bytes, list[bytes]],
                              body: str,
                              duo_headers) -> str:
  """ 
  Create the "canonical string" of the request:
    Date string in RFC 2822 format
    HTTP method in uppercase
    API host in lowercase
    API path
    Canonicalized string of query string parameters, or empty line if none
    Hash of body as JSON string of body parameters, or hash of empty string if none
    Hash of 'x-duo' headers, or hash of empty string if none
  """
  canon_parts = [
    date_string,
    http_method.upper(),
    api_host.lower(),
    api_path,
    canonicalize_parameters(qs_parameters),
    canonicalize_body(body),
    canonicalize_x_duo_headers(duo_headers)
  ]
  return '\n'.join(canon_parts)


def canonicalize_parameters(parameters: dict[bytes, list[bytes]]) -> str:
  """ Canonicalize the parameters by sorting and formatting them """
  if parameters is None:
    return ''

  # This is normalized the same as for OAuth 1.0,
  # http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
  args = []
  for (key, vals) in sorted(
    (urllib.parse.quote(key, '~'), vals) for (key, vals) in list(parameters.items())):
    for val in sorted(urllib.parse.quote(val, '~') for val in vals):
      args.append(f'{key}={val}')
  return '&'.join(args)


def canonicalize_body(body: str) -> str:
  """ Canonicalize the body by encoding and hashing it """
  if body == None:
    body = ''
  return hashlib.sha512(body.encode('utf-8')).hexdigest()


def canonicalize_x_duo_headers(duo_headers: dict[str, str]) -> str:
  """  docstring """
  if duo_headers is None:
    duo_headers = {}
    
  # Lower the headers before sorting them
  lowered_headers = {}
  for header_name, header_value in duo_headers.items():
    header_name = header_name.lower() if header_name is not None else None
    lowered_headers[header_name] = header_value

  canon_list = []

  for header_name in sorted(lowered_headers.keys()):
    # Extract header value and set key to lower case from now on.
    value = lowered_headers[header_name]

    # Add to the list of values to canonicalize:
    canon_list.extend([header_name, value])

  canon = '\x00'.join(canon_list)
  return hashlib.sha512(canon.encode('utf-8')).hexdigest()
