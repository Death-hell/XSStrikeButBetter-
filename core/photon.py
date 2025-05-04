import re
import concurrent.futures
from urllib.parse import urlparse

from core.dom import dom
from core.log import setup_logger
from core.utils import get_url, get_params
from core.requester import requester
from core.zetanize import zetanize
from plugins.retireJs import retireJs

logger = setup_logger(__name__)


def photon(seedUrl, headers, level, threadCount, delay, timeout, skipDOM):
    forms = []
    processed = set()
    storage = set([seedUrl])
    checkedDOMs = set()
    parsed_url = urlparse(seedUrl)
    main_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    host = parsed_url.netloc

    def rec(target):
        try:
            processed.add(target)
            printable = '/'.join(target.split('/')[3:]) or '/'
            printable = printable[-40:].rjust(40)
            logger.run(f'Parsing {printable}\r')

            url = get_url(target, True)
            params = get_params(target, '', True)

            if '=' in target:
                inputs = [{'name': k, 'value': v} for k, v in params.items()]
                forms.append({0: {'action': url, 'method': 'get', 'inputs': inputs}})

            response = requester(url, params, headers, True, delay, timeout).text
            retireJs(url, response)

            if not skipDOM:
                highlighted = dom(response)
                clean = ''.join(re.sub(r'^\d+\s+', '', line) for line in highlighted)
                if highlighted and clean not in checkedDOMs:
                    checkedDOMs.add(clean)
                    logger.good(f'Potentially vulnerable objects found at {url}')
                    logger.red_line(level='good')
                    for line in highlighted:
                        logger.no_format(line, level='good')
                    logger.red_line(level='good')

            forms.append(zetanize(response))

            for match in re.findall(r'<a\s[^>]*href=["\']?([^"\'>\s]+)', response, re.I):
                link = match.split('#')[0].strip()
                if not link or link.lower().endswith(('.pdf', '.png', '.jpg', '.jpeg', '.xls', '.xml', '.docx', '.doc')):
                    continue
                if link.startswith('http'):
                    if link.startswith(main_url):
                        storage.add(link)
                elif link.startswith('//'):
                    if host in link:
                        storage.add(parsed_url.scheme + ':' + link)
                elif link.startswith('/'):
                    storage.add(main_url + link)
                else:
                    storage.add(main_url + '/' + link)

        except Exception as e:
            logger.error(f'Error while processing {target}: {e}')

    try:
        for _ in range(level):
            targets = list(storage - processed)
            with concurrent.futures.ThreadPoolExecutor(max_workers=threadCount) as executor:
                list(executor.map(rec, targets))
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
        return [forms, processed]

    return [forms, processed]
