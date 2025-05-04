import json
import random
import re
from urllib.parse import urlparse

import core.config
from core.config import xsschecker


def converter(data, url=False):
    if isinstance(data, str):
        if url:
            parts = data.split('/')[3:]
            return {part: part for part in parts}
        return json.loads(data)
    else:
        if url:
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            return base + '/' + '/'.join(data.values())
        return json.dumps(data)


def counter(string):
    return len(re.sub(r'\s|\w', '', string))


def closest(number, numbers):
    return min(numbers.items(), key=lambda x: abs(number - x[1]))[1]


def fill_holes(original, new):
    filler = 0
    filled = []
    for x, y in zip(original, new):
        if int(x) == (y + filler):
            filled.append(y)
        else:
            filled.extend([0, y])
            filler += (int(x) - y)
    return filled


def stripper(string, substring, direction='right'):
    done = False
    result = ''
    iterable = string[::-1] if direction == 'right' else string
    for char in iterable:
        if char == substring and not done:
            done = True
            continue
        result += char
    return result[::-1] if direction == 'right' else result


def extract_headers(headers):
    headers = headers.replace('\\n', '\n')
    return {
        h: v.rstrip(',')
        for h, v in re.findall(r'(.*?):\s(.*)', headers)
    }


def replace_value(mapping, old, new, strategy=None):
    result = strategy(mapping) if strategy else mapping
    return {
        k: (new if v == old else v)
        for k, v in result.items()
    }


def get_url(url, GET):
    return url.split('?')[0] if GET else url


def extract_scripts(response):
    matches = re.findall(r'(?s)<script.*?>(.*?)</script>', response.lower())
    return [match for match in matches if xsschecker in match]


def random_upper(string):
    return ''.join(random.choice((c.upper(), c.lower())) for c in string)


def flatten_params(current_param, params, payload):
    return '?' + '&'.join(
        f"{name}={payload if name == current_param else value}"
        for name, value in params.items()
    )


def gen_gen(fillings, eFillings, lFillings, eventHandlers, tags, functions, ends, badTag=None):
    vectors = []
    r = random_upper
    for tag in tags:
        bait = xsschecker if tag in ['d3v', 'a'] else ''
        for event, compat_tags in eventHandlers.items():
            if tag not in compat_tags:
                continue
            for func in functions:
                for fill in fillings:
                    for ef in eFillings:
                        for lf in lFillings:
                            for end in ends:
                                if tag in ['d3v', 'a'] and '>' in ends:
                                    end = '>'
                                breaker = f"</{r(badTag)}>" if badTag else ''
                                vector = f"{breaker}<{r(tag)}{fill}{r(event)}{ef}={ef}{func}{lf}{end}{bait}"
                                vectors.append(vector)
    return vectors


def get_params(url, data, GET):
    if '?' in url and '=' in url:
        data = url.split('?', 1)[1]
    elif not data:
        return None

    if getVar('jsonData') or getVar('path'):
        return data

    try:
        return json.loads(data.replace('\'', '"'))
    except json.JSONDecodeError:
        pass

    params = {}
    for part in data.split('&'):
        key, *val = part.split('=')
        params[key] = val[0] if val else ''
    return params


def writer(obj, path):
    if isinstance(obj, (list, tuple)):
        content = '\n'.join(obj)
    elif isinstance(obj, dict):
        content = json.dumps(obj, indent=4)
    else:
        content = str(obj)

    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)


def reader(path):
    with open(path, 'r', encoding='utf-8') as f:
        return [line.rstrip('\n') for line in f]


def js_extractor(response):
    matches = re.findall(r'<(?:script|SCRIPT).*?(?:src|SRC)=([^\s>]+)', response)
    return [match.strip('\'"`') for match in matches]


def handle_anchor(parent_url, url):
    parsed = urlparse(parent_url)
    if url.startswith('http'):
        return url
    elif url.startswith('//'):
        return f"{parsed.scheme}:{url}"
    elif url.startswith('/'):
        return f"{parsed.scheme}://{parsed.netloc}{url}"
    elif parent_url.endswith('/'):
        return parent_url + url
    else:
        return parent_url + '/' + url


def deJSON(data):
    return data.replace('\\\\', '\\')


def getVar(name):
    return core.config.globalVariables.get(name)


def updateVar(name, data, mode=None):
    if mode == 'append':
        core.config.globalVariables[name].append(data)
    elif mode == 'add':
        core.config.globalVariables[name].add(data)
    else:
        core.config.globalVariables[name] = data


def is_bad_context(position, non_exec_contexts):
    for start, end, label in non_exec_contexts:
        if start < position < end:
            return label
    return ''


def equalize(array, number):
    while len(array) < number:
        array.append('')


def escaped(position, string):
    backslashes = re.match(r'^\\*', string[:position][::-1])
    if not backslashes:
        return False
    length = len(backslashes.group())
    return length % 2 == 1
