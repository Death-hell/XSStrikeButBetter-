import random
import requests
import time
from urllib3.exceptions import ProtocolError
import warnings

import core.config
from core.utils import converter, getVar
from core.log import setup_logger

logger = setup_logger(__name__)

warnings.filterwarnings('ignore')  # Disable SSL related warnings


def requester(url, data, headers, GET, delay, timeout):
    if getVar('jsonData'):
        data = converter(data)
import random
import requests
import time
import warnings
from urllib3.exceptions import ProtocolError

import core.config
from core.utils import converter, getVar
from core.log import setup_logger

logger = setup_logger(__name__)

# Suprimir avisos SSL
warnings.filterwarnings('ignore')

# Lista de User-Agents realistas
USER_AGENTS = [
    'Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15'
]

def requester(url, data, headers, GET=True, delay=0, timeout=10):
    if getVar('jsonData'):
        data = converter(data)
    elif getVar('path'):
        url = converter(data, url)
        data = []
        GET = True  # força GET para URLs com path convertido

    time.sleep(delay)

    # Garante User-Agent válido
    if 'User-Agent' not in headers or headers.get('User-Agent') == '$':
        headers['User-Agent'] = random.choice(USER_AGENTS)

    # Logs detalhados para debug
    logger.debug(f'Requester URL: {url}')
    logger.debug(f'Method: {"GET" if GET else "POST"}')
    logger.debug_json('Data:', data)
    logger.debug_json('Headers:', headers)

    try:
        if GET:
            response = requests.get(
                url,
                params=data,
                headers=headers,
                timeout=timeout,
                verify=False,
                proxies=core.config.proxies
            )
        elif getVar('jsonData'):
            response = requests.post(
                url,
                json=data,
                headers=headers,
                timeout=timeout,
                verify=False,
                proxies=core.config.proxies
            )
        else:
            response = requests.post(
                url,
                data=data,
                headers=headers,
                timeout=timeout,
                verify=False,
                proxies=core.config.proxies
            )
        return response

    except ProtocolError:
        logger.warning('WAF may be dropping requests (ProtocolError).')
        logger.warning('Pausing for 10 minutes before retrying...')
        time.sleep(600)
        return requests.Response()

    except requests.RequestException as e:
        logger.warning(f'Connection failed: {e}')
        return requests.Response()
