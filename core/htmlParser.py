import re

from core.config import badTags, xsschecker
from core.utils import is_bad_context, equalize, escaped, extract_scripts


def htmlParser(response, encoding=None):
    raw_response = response
    response_text = response.text

    if encoding:
        response_text = response_text.replace(encoding(xsschecker), xsschecker)

    reflections = response_text.count(xsschecker)
    position_and_context = {}
    environment_details = {}

    # Remove comentários HTML
    clean_response = re.sub(r'<!--[\s\S]*?-->', '', response_text)
    script_checkable = clean_response

    # Análise de contexto <script>
    for script in extract_scripts(script_checkable):
        for match in re.finditer(r'(%s.*?)$' % re.escape(xsschecker), script):
            position = match.start(1)
            position_and_context[position] = 'script'
            quote_char = ''
            for i, char in enumerate(match.group()):
                if char in ('/', '\'', '`', '"') and not escaped(i, match.group()):
                    quote_char = char
                elif char in (')', ']', '}') and not escaped(i, match.group()):
                    break
            environment_details[position] = {'details': {'quote': quote_char}}
            script_checkable = script_checkable.replace(xsschecker, '', 1)

    # Contexto de atributos HTML
    if len(position_and_context) < reflections:
        for match in re.finditer(r'<[^>]*?(%s)[^>]*?>' % re.escape(xsschecker), clean_response):
            tag_content = match.group(0)
            position = match.start(1)
            parts = re.split(r'\s+', tag_content)
            tag = parts[0][1:]
            context_type = 'attribute'
            detail = {'tag': tag, 'type': '', 'quote': '', 'name': '', 'value': ''}

            for part in parts:
                if xsschecker in part:
                    if '=' in part:
                        quote_match = re.search(r'=["\'`]', part)
                        quote = quote_match.group(0)[1] if quote_match else ''
                        name, value = part.split('=', 1)
                        detail['quote'] = quote
                        detail['name'] = name
                        detail['value'] = value.strip('>').strip(quote).strip()
                        detail['type'] = 'name' if xsschecker == name else 'value'
                    else:
                        detail['type'] = 'flag'

            position_and_context[position] = context_type
            environment_details[position] = {'details': detail}

    # Contexto HTML cru
    if len(position_and_context) < reflections:
        for match in re.finditer(re.escape(xsschecker), clean_response):
            position = match.start()
            if position not in position_and_context:
                position_and_context[position] = 'html'
                environment_details[position] = {'details': {}}

    # Dentro de comentários
    if len(position_and_context) < reflections:
        for match in re.finditer(r'<!--[\s\S]*?(%s)[\s\S]*?-->' % re.escape(xsschecker), response_text):
            position = match.start(1)
            position_and_context[position] = 'comment'
            environment_details[position] = {'details': {}}

    # Construção da base final
    database = {}
    for i in sorted(position_and_context):
        database[i] = {
            'position': i,
            'context': position_and_context[i],
            'details': environment_details[i]['details']
        }

    # Detectar contextos não executáveis (style, textarea, etc.)
    bad_contexts = list(re.finditer(r'(?is)<(style|template|textarea|title|noembed|noscript)>.*?</\1>', response_text))
    non_exec_ranges = [[match.start(), match.end(), match.group(1)] for match in bad_contexts]

    for entry in database.values():
        position = entry['position']
        bad_tag = is_bad_context(position, non_exec_ranges)
        entry['details']['badTag'] = bad_tag if bad_tag else ''

    return database
