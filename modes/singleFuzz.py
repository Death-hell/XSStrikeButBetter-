import copy
from urllib.parse import urlparse

from core.colors import green, end
from core.config import xsschecker
from core.fuzzer import fuzzer
from core.requester import requester
from core.utils import get_url, get_params
from core.wafDetector import wafDetector
from core.log import setup_logger

logger = setup_logger(__name__)


def singleFuzz(target, paramData, encoding, headers, delay, timeout):
    isGET = not bool(paramData)

    if not target.startswith(('http://', 'https://')):
        for proto in ['https://', 'http://']:
            try:
                response = requester(proto + target, {}, headers, isGET, delay, timeout)
                target = proto + target
                break
            except Exception as e:
                logger.debug(f'Failed with {proto}: {e}')
        else:
            logger.error('Target is unreachable using both HTTP and HTTPS.')
            return

    logger.debug(f'Single Fuzz target: {target}')

    host = urlparse(target).netloc
    logger.debug(f'Single fuzz host: {host}')

    url = get_url(target, isGET)
    logger.debug(f'Single fuzz URL: {url}')

    params = get_params(target, paramData, isGET)
    logger.debug_json('Single fuzz parameters:', params)

    if not params:
        logger.error('No parameters found for fuzzing.')
        return

    primaryParam = list(params.keys())[0]
    wafName = wafDetector(url, {primaryParam: xsschecker}, headers, isGET, delay, timeout)

    if wafName:
        logger.error(f'WAF detected: {green}{wafName}{end}')
    else:
        logger.good(f'WAF Status: {green}Offline{end}')

    for param in params:
        logger.info(f'Fuzzing parameter: {param}')
        fuzzParams = copy.deepcopy(params)
        fuzzParams[param] = xsschecker
        try:
            fuzzer(url, fuzzParams, headers, isGET, delay, timeout, wafName, encoding)
        except Exception as fuzzEx:
            logger.error(f'Error while fuzzing parameter {param}: {fuzzEx}')
