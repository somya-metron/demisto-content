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


def create_standard_output(indicator):
    standard_output = {
        'Value': indicator.get('value'),
        'ActivityGroups': indicator.get('activity_groups'),
        'AttackTechniques': indicator.get('attack_techniques'),
        'PreAttackTechniques': indicator.get('pre_attack_techniques'),
        'KillChain': indicator.get('kill_chain'),
        'Comment': indicator.get('comment'),
        'Confidence': indicator.get('confidence'),
        'Score': indicator_confidence_to_dbot_score(indicator.get('confidence')),
        'FirstSeen': indicator.get('first_seen'),
        'LastSeen': indicator.get('last_seen'),
        'Updated': indicator.get('updated'),
        'Products': get_first(indicator.get('products'))
    }
    return standard_output


def create_dbot_output(indicator, indicator_type, score):
    dbot_output = {
        'Type': indicator_type,
        'Indicator': indicator,
        'Vendor': 'Dragos Worldview',
        'Score': score
    }
    return dbot_output


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    response = http_request('GET', 'products', {"page_size": 1})
    if 'total' not in response or 'error' in response:
        return_error('Error retrieving test data.')
    else:
        demisto.results('ok')


def indicator_search_command():
    # Command switcher
    indicator = demisto.args().get(demisto.command())
    indicator_type = demisto.command().lower()
    indicator_output = {}
    context_sub = 'Dragos.{}'.format(demisto.command())

    if demisto.command().lower() == 'file':
        indicator_type = get_hash_type(indicator)
        indicator_output[indicator_type.upper()] = indicator
        indicator_dt = 'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256)'
    elif demisto.command().lower() == 'ip':
        indicator_output['Address'] = indicator
        indicator_dt = 'IP(val.Address && val.Address == obj.Address)'
    elif demisto.command().lower() == 'domain':
        indicator_output['Name'] = indicator
        indicator_dt = 'Domain(val.Name && val.Name == obj.Name)'

    raw = indicator_search(indicator=indicator, indicator_type=indicator_type)

    if 'total' not in raw:
        return_error('Error retrieving results for indicator [{}]'.format(indicator))
    elif raw['total'] == 0:
        demisto.results('Dragos has no information about indicator [{}]'.format(indicator))
        return 0

    response = get_first(raw['indicators'])
    dbot_score = indicator_confidence_to_dbot_score(response.get('confidence'))
    dbot_output = create_dbot_output(indicator, indicator_type, dbot_score)
    war_room_table = create_standard_output(response)
    war_room_table['UUID'] = response.get('uuid')
    hr_title = 'Dragos WorldView - {}'.format(indicator)
    hr = tableToMarkdown(hr_title, war_room_table)

    # If the dbot score is 3, the indicator is malicious
    if dbot_score == 3:
        indicator_output['Malicious'] = {
            'Vendor': 'Dragos Worldview',
            'Description': 'Confidence: {} Comment: {}'.format(response.get('confidence'), response.get('comment'))
        }

    # Create the entry context
    ec = {
        'DBotScore': dbot_output,
        context_sub: createContext(war_room_table, id=response.get('uuid'), removeNull=True),

        # Using DT selectors to prevent duplicate context entry data
        indicator_dt: indicator_output
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': war_room_table,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    })


def indicator_search(indicator, indicator_type):
    params = {"type": indicator_type, "value": indicator}
    response = http_request('GET', 'indicators', params, None)
    return response


''' COMMANDS MANAGER / SWITCH PANEL '''


LOG('Command being called is %s' % (demisto.command()))

try:
    command = demisto.command()
    if command == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
    else:
        indicator_search_command()

# Log exceptions
except Exception as e:
    LOG(e.message)
    LOG.print_log()
    raise
