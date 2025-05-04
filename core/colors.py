import sys
import os
import platform

# Detecta o sistema operacional e a versão
machine = sys.platform.lower()
system_version = platform.version()
platform_name = platform.platform()

# Habilita cores ANSI, exceto em sistemas que não suportam bem (ex: macOS antigo, Windows antigo)
def supports_color():
    if machine.startswith(('win', 'darwin', 'os', 'ios')):
        if platform_name.startswith("Windows-10"):
            try:
                build = int(system_version.split(".")[2])
                if build >= 10586:
                    os.system('')  # Habilita ANSI no terminal do Windows
                    return True
            except (IndexError, ValueError):
                pass
        return False
    return True

colors = supports_color()

# Definições de cores
if not colors:
    white = green = red = yellow = end = back = info = que = bad = good = run = ''
else:
    white = '\033[97m'
    green = '\033[92m'
    red = '\033[91m'
    yellow = '\033[93m'
    end = '\033[0m'
    back = '\033[7;91m'
    info = f'{yellow}[!]{end}'
    que = f'\033[94m[?]{end}'
    bad = f'{red}[-]{end}'
    good = f'{green}[+]{end}'
    run = f'{white}[~]{end}'
