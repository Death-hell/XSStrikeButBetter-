import re
import copy
from typing import Dict, Any

import core.config
from core.colors import green, end
from core.config import xsschecker
from core.filterChecker import filterChecker
from core.generator import generator
from core.htmlParser import htmlParser
from core.requester import requester
from core.log import setup_logger

logger = setup_logger(__name__)


def normalize_url(scheme: str, host: str, url: str, main_url: str) -> str:
    """Converte URLs relativas ou parciais em URLs absolutas."""
    if url.startswith(main_url):
        return url
    elif url.startswith('//') and url[2:].startswith(host):
        return f'{scheme}://{url[2:]}'
    elif url.startswith('/'):
        return f'{scheme}://{host}{url}'
    elif re.match(r'\w', url[0]):
        return f'{scheme}://{host}/{url}'
    return url


def crawl(
    scheme: str,
    host: str,
    main_url: str,
    form: Dict[str, Any],
    blindXSS: bool,
    blindPayload: str,
    headers: Dict[str, str],
    delay: float,
    timeout: float,
    encoding: str
) -> None:
    """Executa crawling e testes XSS em formulários encontrados."""
    
    if not form:
        return

    for form_id, form_data in form.items():
        url = normalize_url(scheme, host, form_data.get('action', ''), main_url)
        if not url:
            continue

        if url not in core.config.globalVariables['checkedForms']:
            core.config.globalVariables['checkedForms'][url] = []

        method = form_data.get('method', 'get').lower()
        is_get = method == 'get'
        inputs = form_data.get('inputs', [])
        param_data = {i['name']: i.get('value', '') for i in inputs if 'name' in i}

        for param in param_data.keys():
            if param in core.config.globalVariables['checkedForms'][url]:
                continue

            core.config.globalVariables['checkedForms'][url].append(param)

            # Copia os dados e insere o payload de teste
            params_copy = copy.deepcopy(param_data)
            params_copy[param] = xsschecker

            try:
                response = requester(url, params_copy, headers, is_get, delay, timeout)
                occurrences = htmlParser(response, encoding)
                filtered_occurrences = filterChecker(
                    url, params_copy, headers, is_get, delay, occurrences, timeout, encoding)

                vectors = generator(filtered_occurrences, response.text)
                if vectors:
                    for confidence, vects in vectors.items():
                        if vects:
                            payload = list(vects)[0]
                            logger.vuln(f'Vulnerable webpage: {green}{url}{end}')
                            logger.vuln(f'Param: {green}{param}{end} | Payload: {payload}')
                            break

                # Se XSS cego estiver habilitado, injeta payload
                if blindXSS and blindPayload:
                    params_copy[param] = blindPayload
                    requester(url, params_copy, headers, is_get, delay, timeout)

            except Exception as e:
                logger.error(f'Error testing param {param} on {url}: {e}')
