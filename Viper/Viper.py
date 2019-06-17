import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import json
import re
import requests
import os
import shlex
import mimetypes
import subprocess
from datetime import date
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

POST_HEADERS = {
    'Authorization': 'Token {}'.format(TOKEN),
    'Accept': 'application/json'
    # Exclude Content-Type as "requests" call must set boundary value used to delineate the parts in the POST body
}

# Remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None, files=None):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=HEADERS,
        files=files
    )
    # Handle error responses gracefully
    if res.status_code in {404}:
        return False
    elif res.status_code not in {200}:
        return_error('Error in API call to Viper [%d] - %s' % (res.status_code, res.reason))
    return res.json()


def http_post(params=None, data=None, files=None):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    res = requests.request(
        url=BASE_URL + 'project/default/malware/upload/',
        method='POST',
        verify=USE_SSL,
        params=params,
        data=data,
        headers=POST_HEADERS,
        files=files
    )
    # Handle error responses gracefully
    if res.status_code not in {201}:
        if res.json()['error']['code'] == 'DuplicateFileHash':
            demisto.results('File already in Viper')
        else:
            warning = {
                'Type': 11,
                'Contents': 'Upload unsuccessful',
                'ContentsFormat': formats['markdown']
            }
            demisto.results(warning)
    else:
        demisto.results("Upload success!")
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
    if not raw:
        warning = {
            'Type': 11,
            'Contents': 'File not found in Viper',
            'ContentsFormat': formats['markdown']
        }
        demisto.results(warning)
    else:
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
                'Description': pretty_tags
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
    response = http_request('GET', url_fragment, None, None, None)
    return response


def viper_upload_command():

    # Get entry id, filename and filepath
    file_entry = demisto.args().get('EntryID')
    filename = demisto.getFilePath(file_entry)['name']
    filepath = demisto.getFilePath(file_entry)['path']

    # Send file to Viper
    response = viper_upload(filepath, filename, file_entry.lower())



def viper_upload(path, name, entry_id):

    # Get absolute filepath for upload
    new_path = os.path.abspath(path)
    files = {'file': (name, open(new_path, 'rb'))}
    incident_name = demisto.get(demisto.investigation(), 'name')


    # Create some basic demisto-related tags to attach to file details on initial upload
    data = {'tag_list': entry_id + ',' + str(date.today()) + ',' + 'demisto' + ',' + incident_name,
            'note_title': ' ',
            'note_body': ' '
            }
    upload = http_post(None, data=data, files=files)
    return upload


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
    elif demisto.command() == 'file':
        #  Collect SHA56 hash from demisto details
        hash_value = demisto.args().get('file')
        hash_type = get_hash_type(hash_value)

        # Check if hash is SHA256 - Viper API only supports SHA256
        if hash_type.lower() != 'sha256':
            error = True
        else:
            error = False
        if not error:
            viper_search_command()
        else:
            warning = {
                'Type': 11,
                'Contents': 'Hash not recognized. Please use SHA256 hashes',
                'ContentsFormat': formats['markdown']
            }
            demisto.results(warning)
    elif demisto.command() == 'upload':
        viper_upload_command()

# Log exceptions
except Exception as e:
    LOG(e.message)
    LOG.print_log()
    raise
