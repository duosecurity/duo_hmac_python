#! /bin/python3

import argparse

from duo_hmac import duo_hmac

import check_credentials as cc

def get_arguments(parser):
  parser.add_argument('-m', choices=['get', 'post'], default='get', help="HTTP method")
  parser.add_argument('-a', help="API path", required=True)
  parser.add_argument('-p', default = [], help="API call parameters as k=v pairs", metavar="KEY=VALUE", nargs='*')
  args = parser.parse_args()

  args_dict = {
    'method': args.m.upper(),
    'path': args.a.lower(),
    'params': {p[0]: p[1] for p in [item.split('=') for item in args.p]},
  }

  return args_dict


def main():
  ikey, skey, host = cc._read_config()

  parser = argparse.ArgumentParser()
  args_dict = get_arguments(parser)

  hmac = duo_hmac.DuoHmac(ikey, skey, host)

  uri, body, headers = hmac.get_authentication_components(
    args_dict['method'], 
    args_dict['path'], 
    args_dict['params'],
  )

  headers_list = [f"{key}: {value}" for key, value in headers.items()]
  
  curl_command = "curl "

  curl_command = curl_command + f' -X {args_dict["method"]} '

  for header in headers_list:
    curl_command = curl_command + f' -H "{header}" '

  if body:
    curl_command = curl_command + f" -d '{body}' "

  curl_command = curl_command + f" https://{uri}"

  print(curl_command)  

if __name__=="__main__":
  main()