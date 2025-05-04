import re
from core.colors import end, red, yellow

# Fallback se as cores não estiverem definidas
if not end: end = ''
if not red: red = '*'
if not yellow: yellow = '*'

# Fontes de dados controláveis
sources = r'''\b(?:document\.(?:URL|documentURI|URLUnencoded|baseURI|cookie|referrer)|location\.(?:href|search|hash)|window\.name|history\.(?:pushState|replaceState)|localStorage|sessionStorage|this\.location)\b'''
# Funções perigosas que podem causar XSS
sinks = r'''\b(?:eval|evaluate|execCommand|assign|navigate|getResponseHeader|open|showModalDialog|setTimeout|setInterval|Function|innerHTML|document\.write)\b'''

def dom(response):
    highlighted = []
    sinkFound = False
    sourceFound = False
    allControlled = set()

    # Extrai todos os <script>...</script>
    scripts = re.findall(r'(?i)(?s)<script[^>]*>(.*?)</script>', response)

    for script in scripts:
        lines = script.split('\n')
        for num, original_line in enumerate(lines, start=1):
            line = original_line
            modified = False

            try:
                # Verifica se há variáveis atribuídas a fontes controláveis
                source_matches = re.finditer(sources, line)
                for match in source_matches:
                    source = match.group()
                    sourceFound = True
                    line = re.sub(re.escape(source), f"{yellow}{source}{end}", line)
                    # Detecta variáveis que recebem fontes controláveis
                    var_match = re.search(r'var\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*' + re.escape(source), line)
                    if var_match:
                        allControlled.add(var_match.group(1))
                    modified = True

                # Marca uso de variáveis controladas em funções
                for var in allControlled:
                    if re.search(r'\b' + re.escape(var) + r'\b', line):
                        sourceFound = True
                        line = re.sub(r'\b' + re.escape(var) + r'\b', f"{yellow}{var}{end}", line)
                        modified = True

                # Destaca sinks perigosos
                sink_matches = re.finditer(sinks, line)
                for match in sink_matches:
                    sink = match.group()
                    sinkFound = True
                    line = re.sub(re.escape(sink), f"{red}{sink}{end}", line)
                    modified = True

                # Marca atribuições perigosas diretas (ex: innerHTML = userData)
                assign_match = re.search(r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(' + sources + r')', line)
                if assign_match:
                    left, right = assign_match.groups()
                    sourceFound = True
                    sinkFound = True
                    line = line.replace(right, f"{yellow}{right}{end}")
                    line = re.sub(r'\b' + re.escape(left) + r'\b', f"{red}{left}{end}", line)
                    modified = True

                if modified:
                    highlighted.append(f'{num:>3} {line.strip()}')

            except MemoryError:
                continue

    return highlighted if (sinkFound or sourceFound) else []
