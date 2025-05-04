import copy
from urllib.parse import urlparse, unquote
from typing import Callable, Dict, List, Optional

from core.colors import good, green, end
from core.requester import requester
from core.utils import get_url, get_params
from core.log import setup_logger

logger = setup_logger(__name__)


def bruteforcer(
    target: str,
    paramData: Optional[Dict[str, str]],
    payloadList: List[str],
    encoding: Optional[Callable[[str], str]],
    headers: Dict[str, str],
    delay: float,
    timeout: float
) -> None:
    """
    Realiza brute-force com payloads nos parâmetros de uma URL (GET ou POST).
    """
    is_get = not bool(paramData)
    host = urlparse(target).netloc
    url = get_url(target, is_get)
    params = get_params(target, paramData, is_get)

    logger.debug(f'Parsed host to bruteforce: {host}')
    logger.debug(f'Parsed URL to bruteforce: {url}')
    logger.debug_json('Bruteforcer params:', params)

    if not params:
        logger.error('No parameters to test.')
        return

    for param_name in params:
        params_copy = copy.deepcopy(params)
        total = len(payloadList)

        for i, raw_payload in enumerate(payloadList, 1):
            payload = unquote(raw_payload)
            if encoding:
                payload = encoding(payload)

            params_copy[param_name] = payload

            logger.run(
                f'Bruteforcing {green}[{param_name}]{end}: {i}/{total}', end='\r'
            )

            try:
                response = requester(url, params_copy, headers, is_get, delay, timeout).text
                if payload in response:
                    logger.info(f'{good} Payload reflected: {payload}')
            except Exception as e:
                logger.error(f'Error testing payload on {param_name}: {e}')

    logger.no_format('')
