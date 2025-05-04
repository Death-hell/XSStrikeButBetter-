import json
import re
import sys

from core.requester import requester
from core.log import setup_logger

logger = setup_logger(__name__)


def wafDetector(url, params, headers, GET, delay, timeout):
    try:
        with open(sys.path[0] + '/db/wafSignatures.json', 'r') as file:
            wafSignatures = json.load(file)
    except Exception as e:
        logger.error(f'[WAF] Failed to load signatures: {e}')
        return None

    # Highly noisy payloads to provoke WAF behavior
    noisy_payloads = [
        "<script>alert('XSS')</script>",
        "<IMG SRC=javascript:alert('XSS')>",
        "'><svg/onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<BODY ONLOAD=alert('XSS')>",
        "<object data=javascript:alert('XSS')>",
        "<embed src=javascript:alert('XSS')>"
    ]

    bestMatch = [0, None]

    for noise in noisy_payloads:
        test_params = params.copy()
        test_params['xss'] = noise

        try:
            response = requester(url, test_params, headers, GET, delay, timeout)
        except Exception as e:
            logger.warning(f'[WAF] Request failed with payload: {noise} - {e}')
            continue

        page = response.text
        code = str(response.status_code)
        headers_str = str(response.headers)
        elapsed = response.elapsed.total_seconds()

        logger.debug(f'[WAF] Status Code: {code} | Response Time: {elapsed:.2f}s')
        logger.debug_json('[WAF] Response Headers:', response.headers)

        for wafName, wafSignature in wafSignatures.items():
            score = 0

            if wafSignature.get('page') and re.search(wafSignature['page'], page, re.I):
                score += 2
            if wafSignature.get('code') and re.search(wafSignature['code'], code, re.I):
                score += 1
            if wafSignature.get('headers') and re.search(wafSignature['headers'], headers_str, re.I):
                score += 2
            if elapsed > 5:
                score += 1  # WAF may have introduced intentional delay

            if score > bestMatch[0]:
                bestMatch = [score, wafName]

    if bestMatch[0] > 0:
        logger.info(f'[WAF] WAF Detected: {bestMatch[1]} (score: {bestMatch[0]})')
        return bestMatch[1]
    else:
        logger.info('[WAF] No WAF detected')
        return None
