from bs4 import BeautifulSoup
import requests
import time
import codecs
import base64

def banner():
    print('''
  _  ____  _  _ ____ __  ___ _ _  
 | |/ /  \| \| |__  /  \| _ \ | | 
 | ' < () | .` | / / () |   /_  _|
 |_|\_\__/|_|\_|/_/ \__/|_|_\ |_| 
                                    author:  AFANX
                                    pylib:   pyhtb
                                    K0N70R4: https://t.me/k0n70r4/
                                    github:  https://github.com/cyberpunk-afanx/pyhtb/
          ''')
    

def info(msg):
    print("[!] " + str(msg))

def error(msg):
    print("[-] " + str(msg))

def success(msg):
    print("[+] " + str(msg))

def send(payload, method=None,cookie=None):
    info(payload)
    if(method is None):
        if(cookie is None):
            response = requests.get(payload)
            info(response.status_code)
            return response
        else:
            cookies = {}
            cookies[cookie.split(":")[0]] = cookie.split(":")[1]
            response = requests.get(payload, cookies=cookies)
            info(response.status_code)
            return response
    elif(method == "POST"):
        if(cookie is None):
            response = requests.post(payload)
            info(response.status_code)
            return response
        else:
            cookies = {}
            cookies[cookie.split(":")[0]] = cookie.split(":")[1]
            response = requests.post(payload, cookies=cookies)
            info(response.status_code)
            return response
    elif(method == "PUT"):
        if(cookie is None):
            response = requests.put(payload)
            info(response.status_code)
            return response
        else:
            cookies = {}
            cookies[cookie.split(":")[0]] = cookie.split(":")[1]
            response = requests.put(payload, cookies=cookies)
            info(response.status_code)
            return response

def recv_code(url, cookie=None):
    if(cookie is None):
        response = requests.get(url)
        return response.status_code
    else:
        cookies = {}
        cookies[cookie.split(":")[0]] = cookie.split(":")[1]
        response = requests.get(url, cookies=cookies)
        return response.status_code

def recv_cookies(url, domain):
    info(url)
    response = requests.get(url)
    cookie_dict = response.cookies.get_dict(domain=domain)
    found = ['%s=%s' % (name, value) for (name, value) in cookie_dict.items()]
    return ':'.join(found[0].split("="))

def url_encode(str_payload):
    url_encode_result = "+"
    for i in str_payload.split(" "):
        url_encode_result += i + '+'
    return url_encode_result[:len(url_encode_result)-1]

def response_time(time1, time2):
    return (int(time2.split(" ")[1].split(":")[2]) - int(time1.split(" ")[1].split(":")[2]))

def construct_url(url, path=None):
    if(path is None):
        return url
    else:
        return url+path

def hexdump_pcap(filename, pattern):
    print('\nHEXDUMP PCAP FILE')

    PATTERN = ""
    HEX_PATTERN = ""

    for i in pattern:
        HEX_PATTERN += hex(ord(i))[2:]


    with open(filename, 'rb') as file:
        offset = 0

        while True:
            chunk = file.read(16)
            if not chunk:
                break

            print(f'{offset:08x}:', end=' ')

            for byte in chunk:
                print(f'{byte:02x}', end=' ')

            print(' ' * (49 - len(chunk) * 3), end='')
            print('|', end='')

            for byte in chunk:
                if 32 <= byte <= 126:
                    print(chr(byte), end='')
                else:
                    print('.', end='')
            print('|')

            hex_string = ''.join(f'{byte:02x}' for byte in chunk)

            if HEX_PATTERN in hex_string:  
                PATTERN = ('Found "' + pattern + '" at offset:', f'{offset:08x}')
                file.seek(offset)
                PATTERN += ('String found:', file.read(32).decode('ascii', errors='replace'))

            offset += 16

    if(len(PATTERN) != 0):
        info(PATTERN)

def detect_cms(url):
    server = None
    server_version = None
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            cms_detection = {
                'WordPress': lambda: soup.find('meta', {'name': 'generator'}) and 'WordPress' in soup.find('meta', {'name': 'generator'}).get('content'),
                'Drupal': lambda: soup.find('meta', {'name': 'Generator'}) and 'Drupal' in soup.find('meta', {'name': 'Generator'}).get('content'),
                'Joomla': lambda: soup.find('meta', {'name': 'generator'}) and 'Joomla' in soup.find('meta', {'name': 'generator'}).get('content'),
                'Magento': lambda: soup.find('meta', {'name': 'generator'}) and 'Magento' in soup.find('meta', {'name': 'generator'}).get('content'),
                'Shopify': lambda: soup.find('meta', {'name': 'generator'}) and 'Shopify' in soup.find('meta', {'name': 'generator'}).get('content'),
                'Squarespace': lambda: soup.find('meta', {'name': 'generator'}) and 'Squarespace' in soup.find('meta', {'name': 'generator'}).get('content'),
                'Wix': lambda: soup.find('meta', {'name': 'generator'}) and 'Wix' in soup.find('meta', {'name': 'generator'}).get('content')
            }

            for cms, check in cms_detection.items():
                if check():
                    version = soup.find('meta', {'name': 'generator'}).get('content').split(' ')[-1]
                    server = response.headers.get('Server')
                    server_version = response.headers.get('X-Powered-By')
                    return cms, version, server, server_version

            return 'Unknown CMS', None, server, server_version
        else:
            return 'Error', None, server, server_version
    except requests.exceptions.RequestException:
        return 'Error', None, server, server_version

def what_web(url):
    cms, version, server, server_version = detect_cms(url)
    info(f'CMS: {cms}')
    info(f'Version: {version}')
    info(f'Server: {server}')
    info(f'Server Version: {server_version}')
    return cms, version, server, server_version