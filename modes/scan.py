import copy
from urllib.parse import urlparse, unquote

from core.checker import checker
from core.colors import end, green, que
import core.config
from core.config import xsschecker, minEfficiency
from core.dom import dom
from core.filterChecker import filterChecker
from core.generator import generator
from core.htmlParser import htmlParser
from core.requester import requester
from core.utils import get_url, get_params
from core.wafDetector import wafDetector
from core.log import setup_logger

logger = setup_logger(__name__)


def scan(target, paramData, encoding, headers, delay, timeout, skipDOM, skip):
    # Determina se o método é GET (parâmetros na URL) ou POST (paramData fornecido)
    is_get = not bool(paramData)

    # Corrige protocolo caso necessário
    if not target.startswith('http'):
        for proto in ['https://', 'http://']:
            try:
                requester(proto + target, {}, headers, is_get, delay, timeout)
                target = proto + target
                break
            except Exception:
                continue

    logger.debug(f'Scan target: {target}')

    # Solicitação inicial e análise DOM
    response = requester(target, {}, headers, is_get, delay, timeout).text
    if not skipDOM:
        logger.run('Checking for DOM vulnerabilities')
        highlighted = dom(response)
        if highlighted:
            logger.good('Potentially vulnerable objects found')
            logger.red_line(level='good')
            for line in highlighted:
                logger.no_format(line, level='good')
            logger.red_line(level='good')

    host = urlparse(target).netloc
    url = get_url(target, is_get)
    params = get_params(target, paramData, is_get)

    logger.debug(f'Host to scan: {host}')
    logger.debug(f'URL to scan: {url}')
    logger.debug_json('Scan parameters:', params)

    if not params:
        logger.error('No parameters to test.')
        return

    # Detecção de WAF
    test_param = list(params.keys())[0]
    waf_result = wafDetector(url, {test_param: xsschecker}, headers, is_get, delay, timeout)
    if waf_result:
        logger.error(f'WAF detected: {green}{waf_result}{end}')
    else:
        logger.good(f'WAF Status: {green}Offline{end}')

    # Loop principal por parâmetro
    for param_name in params:
        logger.info(f'Testing parameter: {param_name}')
        params_copy = copy.deepcopy(params)
        params_copy[param_name] = encoding(xsschecker) if encoding else xsschecker

        response = requester(url, params_copy, headers, is_get, delay, timeout)
        occurences = htmlParser(response, encoding)
        positions = occurences.keys()

        logger.debug(f'Scan occurences: {occurences}')

        if not occurences:
            logger.error('No reflection found')
            continue

        logger.info(f'Reflections found: {len(occurences)}')
        logger.run('Analysing reflections')

        efficiencies = filterChecker(
            url, params_copy, headers, is_get, delay, occurences, timeout, encoding
        )
        logger.debug(f'Scan efficiencies: {efficiencies}')

        logger.run('Generating payloads')
        vectors = generator(occurences, response.text)
        total = sum(len(v) for v in vectors.values())

        if total == 0:
            logger.error('No vectors were crafted.')
            continue

        logger.info(f'Payloads generated: {total}')
        progress = 0

        # Teste dos payloads gerados
        for confidence, vects in vectors.items():
            for vect in vects:
                progress += 1
                logger.run(f'Progress: {progress}/{total}\r')

                # Substituição segura de caminhos codificados
                logger_vector = vect
                if core.config.globalVariables.get('path'):
                    vect = vect.replace('/', '%2F')

                if not is_get:
                    vect = unquote(vect)

                efficiencies = checker(
                    url, params_copy, headers, is_get, delay, vect,
                    positions, timeout, encoding
                ) or [0] * len(occurences)

                best = max(efficiencies)
                if best == 100 or (vect.startswith('\\') and best >= 95):
                    logger.red_line()
                    logger.good(f'Payload: {logger_vector}')
                    logger.info(f'Efficiency: {best}')
                    logger.info(f'Confidence: {confidence}')
                    if not skip:
                        choice = input(f'{que} Would you like to continue scanning? [y/N] ').lower()
                        if choice != 'y':
                            return
                elif best > minEfficiency:
                    logger.red_line()
                    logger.good(f'Payload: {logger_vector}')
                    logger.info(f'Efficiency: {best}')
                    logger.info(f'Confidence: {confidence}')

        logger.no_format('')
