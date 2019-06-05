import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
import re
from distutils.util import strtobool

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

API_TOKEN = demisto.params().get('apitoken')
API_SECRET = demisto.params().get('apisecret')
TOKEN = demisto.params().get('token')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] \
    if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']


BASE_URL = SERVER + '/api/v1/'                         # Service base URL
USE_SSL = not demisto.params().get('insecure', False)  # Should we use SSL
HEADERS = {                                            # Headers to be sent in requests
    'API-Token': API_TOKEN,
    'API-Secret': API_SECRET,
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

FILE_INDICATOR_TABLE_HEADERS = [
    'Value',
    'ActivityGroups',
    'ATTACKTechniques',
    'Pre-ATTACKTechniques',
    'KillchainStage',
    'Comment',
    'Confidence',
    'Score',
    'FirstSeen',
    'Updated',
    'Products',
    'UUID'
]

# Remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None):
    """
    A wrapper for requests lib to send our requests and handle requests and responses better

    :type method: ``str``
    :param method: HTTP method for the request.

    :type url_suffix: ``str``
    :param url_suffix: The suffix of the URL (endpoint)

    :type params: ``dict``
    :param params: The URL params to be passed.

    :type data: ``dict``
    :param data: The body data of the request.
    :return:
    """
    try:
        res = requests.request(
            method,
            BASE_URL + url_suffix,
            verify=USE_SSL,
            params=params,
            data=data,
            headers=HEADERS
        )
        if res.status_code not in {200}:
            return_error('Error in API call to Dragos WorldView [{}] - {}'.format(res.status_code, res.reason))
        return res.json()
    except requests.exceptions.RequestException as e:
        LOG(str(e))
        return_error(e)


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


def indicator_confidence_to_dbot_score(confidence):
    """
    Converts Dragos' indicator confidence to DBot score, based on table below.

    Dragos Confidence   DBot Score Name     DBot Score
    -----------------   ---------------     ---------
    Unknown             Unknown             0
    Low                 Suspicious          2
    Moderate            Suspicious          2
    High                Bad                 3

    :type confidence: ``str``
    :param confidence:

    :return: DBot score
    :rtype ``int``
    """
    if confidence.lower() in ('low', 'moderate'):
        score = 2
    elif confidence.lower() == 'high':
        score = 3
    else:
        score = 0
    return score


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    response = http_request('GET', 'products', {"page_size": 1}, None)
    if 'total' not in response or 'error' in response:
        return_error('Error retrieving test data.')
    else:
        demisto.results('ok')


def file_search_command():
    """
    Retrieves information for a given file hash from Dragos WorldView's REST API.

    :return: ``dict``
    """
    hash_value = demisto.args().get('file')
    hash_type = get_hash_type(hash_value)

    # API only supports md5, sha1, sha256 hashes.
    if hash_type.lower() not in {'md5', 'sha1', 'sha256'}:
        e_msg = 'Hash type supplied [{}] is not supported. Only MD5, SHA1, or SHA256 hashes are supported.'
        return_error(e_msg.format(hash_type))

    raw_response = file_search(hash_value, hash_type)
    response = get_first(raw_response['indicators'])

    # Exit if there was an HTTP error, or if there were no results from the API call
    if 'total' not in raw_response or 'error' in raw_response:
        return_error('Error retrieving results for indicator [{}]'.format(hash_value))
    elif 'total' in raw_response and (raw_response['total'] == 0):
        demisto.results('No information found for indicator [{}]'.format(hash_value))
        return 0

    dbot_score = indicator_confidence_to_dbot_score(response.get('confidence'))

    table = {
        'Value': response.get('value'),
        'ActivityGroups': response.get('activity_groups'),
        'AttackTechniques': response.get('attack_techniques'),
        'PreAttackTechniques': response.get('pre_attack_techniques'),
        'KillChain': response.get('kill_chain'),
        'Comment': response.get('comment'),
        'Confidence': response.get('confidence'),
        'Score': dbot_score,
        'FirstSeen': response.get('first_seen'),
        'Updated': response.get('updated'),
        'Products': get_first(response.get('products')),
        'UUID': response.get('uuid')
    }
    hr_title = 'Dragos WorldView - {}'.format(hash_value)
    hr = tableToMarkdown(hr_title, table)

    dbot_output = {
        'Type': 'file',
        'Indicator': hash_value,
        'Vendor': 'Dragos Worldview',
        'Score': dbot_score
    }

    # Build indicator output for file entry context
    file_output = {
        hash_type.upper(): hash_value
    }

    # If the dbot score is 3, the file is malicious
    if dbot_score == 3:
        file_output['Malicious'] = {
            'Vendor': 'Dragos Worldview',
            'Description': 'Confidence: {} Comment: {}'.format(response.get('confidence'), response.get('comment'))
        }

    ec = {
        'DBotScore': dbot_output,
        'Dragos.File': createContext(table, id=response.get('uuid'), removeNull=True),

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


def file_search(hash_value, hash_type):
    """
    Queries the REST API and passes results to file_search_command

    :type hash_value: ``str``
    :param hash_value:  File hash to be checked

    :type hash_type: ``str``
    :param hash_type:  The type of hash being retrieved (MD5, SHA1, SHA256)

    :return: JSON-ified HTTP Response from REST API
    :rtype: ``json``
    """
    params = {"type": hash_type, "value": hash_value}
    response = http_request('GET', 'indicators', params, None)
    return response


def ip_command():
    """
    Retrieves information for a given IP address from Dragos WorldView's REST API.

    :return: ``dict``
    """
    ip_address = demisto.args().get('ip')

    raw_response = file_search(hash_value, hash_type)
    response = get_first(raw_response['indicators'])

    # Exit if there was an HTTP error, or if there were no results from the API call
    if 'total' not in raw_response or 'error' in raw_response:
        return_error('Error retrieving results for indicator [{}]'.format(ip_address))
    elif 'total' in raw_response and (raw_response['total'] == 0):
        demisto.results('No information found for indicator [{}]'.format(ip_address))
        return 0

    dbot_score = indicator_confidence_to_dbot_score(response.get('confidence'))

    table = {
        'Value': response.get('value'),
        'ActivityGroups': response.get('activity_groups'),
        'AttackTechniques': response.get('attack_techniques'),
        'PreAttackTechniques': response.get('pre_attack_techniques'),
        'KillChain': response.get('kill_chain'),
        'Comment': response.get('comment'),
        'Confidence': response.get('confidence'),
        'Score': dbot_score,
        'FirstSeen': response.get('first_seen'),
        'Updated': response.get('updated'),
        'Products': get_first(response.get('products')),
        'ID': response.get('id'),
        'UUID': response.get('uuid')
    }
    hr_title = 'Dragos WorldView - {}'.format(ip_address)
    hr = tableToMarkdown(hr_title, table)

    dbot_output = {
        'Type': 'ip',
        'Indicator': ip_address,
        'Vendor': 'Dragos Worldview',
        'Score': dbot_score
    }

    # Build indicator output for file entry context
    ip_output = {
        "Address": ip_address
    }

    # If the dbot score is 3, the file is malicious
    if dbot_score == 3:
        ip_output['Malicious'] = {
            'Vendor': 'Dragos Worldview',
            'Description': 'Confidence: {} Comment: {}'.format(response.get('confidence'), response.get('comment'))
        }

    ec = {
        'DBotScore': dbot_output,
        'Dragos.File': createContext(table, id=response.get('uuid'), removeNull=True),

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


def ip_search(ip_address):
    params = {"type": "ip", "value": ip_address}
    response = http_request('GET', 'indicators', params, None)
    return response

''' COMMANDS MANAGER / SWITCH PANEL '''


LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
    elif demisto.command() == 'file':
        # An example command
        file_search_command()

# Log exceptions
except Exception as e:
    LOG(e.message)
    LOG.print_log()
    raise
