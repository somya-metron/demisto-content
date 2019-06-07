import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import re
import requests
from distutils.util import strtobool

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

TOKEN = demisto.params().get('token')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] \
    if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# Service base URL
BASE_URL = SERVER + '/api/v3/'
# Headers to be sent in requests
HEADERS = {
    'Authorization': 'Token {}'.format(TOKEN),
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
# Remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=HEADERS
    )
    # Handle error responses gracefully
    if res.status_code not in {200}:
        return_error('Error in API call to Viper [%d] - %s' % (res.status_code, res.reason))
    return res.json()


def get_first(iterable, default=None):
    """
    Returns the first item for an iterable object

    :type iterable: ``obj``
    :param iterable: An iterable object, like a dict

    :type default: ``str``
    :param default:  The default property to return

    :return: First item within an iterable, or the default if not iterable
    :rtype: ``dict``
    """
    if iterable:
        for item in iterable:
            return item
    return default


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    samples = http_request('GET', 'test-auth/')
    if 'message' in samples:
        demisto.results('ok')
    else:
        return_error(samples)


def viper_search_command():

    #  Collect SHA56 hash from demisto details
    hash_value = demisto.args().get('file')
    hash_type = get_hash_type(hash_value)

    # search and return Viper data
    raw = viper_hash_search(hash_value)
    data = get_first(raw)

    # Do string manipulation in url to navigate to web interface
    analysis = '[Viper Database Entry](' + str(raw['links']['web']) + ')'

    # Grab tag strings & format tag strings
    pretty_tags = [tag['data']['tag'] for tag in raw['data']['tag_set']]

    # Table of data to populate Viper.File
    table = {
        'Viper ID': raw['data']['id'],
        'Created at': raw['data']['created_at'],
        'SHA256': raw['data']['sha256'],
        'SHA1': raw['data']['sha1'],
        'MD5': raw['data']['md5'],
        'ssdeep': raw['data']['ssdeep'],
        'Link': analysis,
        'Tags': pretty_tags
    }

    # Version of table for context data - no markdown formatting for url
    cd_table = {
        'Viper ID': raw['data']['id'],
        'Created at': raw['data']['created_at'],
        'SHA256': raw['data']['sha256'],
        'SHA1': raw['data']['sha1'],
        'MD5': raw['data']['md5'],
        'ssdeep': raw['data']['ssdeep'],
        'Link': raw['links']['web'],
        'Tags': pretty_tags
    }
    hr = tableToMarkdown('Viper Search Results', table)


    # If it's in Viper, it's bad - right?
    # dbot score:
    # 0 -> Unknown
    # 1 -> Good
    # 2 -> Suspicious
    # 3 -> Bad, mmkay
    dbot_score = 3
    dbot_output = {
        'Type': 'file',
        'Indicator': hash_value,
        'Vendor': 'Viper',
        'Score': dbot_score
    }

    # Build indicator output for file entry context
    file_output = {
        hash_type.upper(): hash_value,
        'ssdeep': raw['data']['ssdeep']
    }

    # If the dbot score is 3, the file is malicious
    if dbot_score == 3:
        file_output['Malicious'] = {
            'Vendor': 'Viper',
            'Description': raw['data']['tag_set']
        }

    # Entry Context
    ec = {
        'DBotScore': dbot_output,
        # This builds the 'Viper.File' context item - avoid duplicates with the value of the 'id' parameter
        'Viper.File': createContext(cd_table, id=raw.get('id'), removeNull=True),
        # Using DT selectors to prevent duplicate context entry data
        'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256)': file_output
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': table,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    })




def viper_hash_search(hash_value):
    url_fragment = 'project/default/malware/{}'.format(hash_value)
    response = http_request('GET',url_fragment,None,None)
    return response

''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
    elif demisto.command() == 'file':
        viper_search_command()

# Log exceptions
except Exception as e:
    LOG(e.message)
    LOG.print_log()
    raise
