import re

from core.config import xsschecker
from core.utils import stripper


def jsContexter(script):
    broken = script.split(xsschecker)
    pre = broken[0]

    # Remove conteúdos entre {}, (), "", ''
    pre = re.sub(r'(?s)\{.*?\}|.*?|".*?"|\'.*?\'', '', pre)

    breaker = ''
    i = 0
    while i < len(pre):
        char = pre[i]
        if char == '{':
            breaker += '}'
        elif char == '(':
            breaker += ';)'
        elif char == '[':
            breaker += ']'
        elif char == '/':
            # Detecta início de comentário multiline
            if i + 1 < len(pre) and pre[i + 1] == '*':
                breaker += '/*'
        elif char == '}':
            breaker = stripper(breaker, '}')
        elif char == ')':
            breaker = stripper(breaker, ')')
        elif char == ']':
            breaker = stripper(breaker, ']')
        i += 1

    return breaker[::-1]  # Inverte o conteúdo para indicar o fechamento correto do contexto
