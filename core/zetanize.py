import re
from html import unescape


def zetanize(response: str) -> dict:
    # Remove HTML comments
    response = re.sub(r'(?s)<!--.*?-->', '', response)

    forms = {}
    form_matches = re.findall(r'(?i)(?s)<form[^>]*>.*?</form>', response)

    for i, form in enumerate(form_matches):
        form_data = {}
        form_data['action'] = extract_attribute(form, 'action') or ''
        form_data['method'] = (extract_attribute(form, 'method') or 'get').lower()
        form_data['inputs'] = []

        input_matches = re.findall(r'(?i)<input[^>]*>', form)
        for inp in input_matches:
            name = extract_attribute(inp, 'name')
            if name:
                input_type = extract_attribute(inp, 'type') or ''
                value = extract_attribute(inp, 'value') or ''
                if input_type.lower() == 'submit' and not value:
                    value = 'Submit Query'
                form_data['inputs'].append({
                    'name': name,
                    'type': input_type,
                    'value': value
                })

        forms[i] = form_data

    return forms


def extract_attribute(tag: str, attr: str) -> str:
    """Helper to extract an HTML attribute value from a tag."""
    match = re.search(rf'{attr}\s*=\s*[\'"]([^\'"]+)[\'"]', tag, flags=re.IGNORECASE)
    return unescape(match.group(1)) if match else ''
