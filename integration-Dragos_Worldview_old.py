''' IMPORTS '''
import datetime
import time
import requests
import json
import os
import re

''' GLOBALS '''
SERVER     = demisto.params().get('server')
API_TOKEN  = demisto.params().get('credentials')['identifier']
API_SECRET = demisto.params().get('credentials')['password']
VERIFY_CERTIFICATES = False if demisto.params().get('unsecure') else True
DEFAULT_HEADERS = {
    "Content-Type": "application/json",
    "API-Token": API_TOKEN,
    "API-Secret": API_SECRET
}

if not SERVER.endswith('/'): SERVER += '/'

if not demisto.params().get('useProxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']



''' HELPERS '''
def http_request(method, url, headers):
  try:
    res = requests.request(method,
          url,
          verify=VERIFY_CERTIFICATES,
          headers=headers)

    if res.status_code == 200:
      return res.json()
      # 204 HTTP status code is returned when api rate limit has been exceeded
    elif res.status_code == 404:
      return {}
      res.raise_for_status()
  except Exception as e:
    raise e

''' COMMANDS '''
def file_command():
    args = demisto.args()
    hash = args.get('file')
    file_name = args['file']
    rating_threshold = int(args.get('ratingThreshold', -1))
    confidence_threshold = int(args.get('confidenceThreshold', -1))

    ec, indicators = _file(file_name, owners, rating_threshold, confidence_threshold)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': indicators,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('ThreatConnect File Report for: {}'.format(file_name), indicators, headerTransform=pascalToSpace),
        'EntryContext': ec,
    })


@logger
def _file(url_addr, owners, rating_threshold, confidence_threshold):
    indicators = get_indicators(url_addr, 'File', owners, rating_threshold, confidence_threshold, freshness=FRESHNESS)
    ec, indicators = create_context(indicators, include_dbot_score=True)

    return ec, indicators

if demisto.command() == 'test-module':
    # This call is made when pressing the integration test button.
    url = "{}products?page=1&page_size=1".format(SERVER)
    r = http_request GET url DEFAULT_HEADERS
    sys.exit(0)'
