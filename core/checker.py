import copy
import re
from urllib.parse import unquote
from fuzzywuzzy import fuzz

from core.config import xsschecker
from core.requester import requester
from core.utils import replace_value, fill_holes


def checker(url, params, headers, GET, delay, payload, positions, timeout, encoding):
    base_marker = 'st4r7s'
    end_marker = '3nd'
    raw_check_string = f'{base_marker}{payload}{end_marker}'
    check_string = encoding(unquote(raw_check_string)) if encoding else raw_check_string

    response = requester(
        url,
        replace_value(params, xsschecker, raw_check_string, copy.deepcopy),
        headers,
        GET,
        delay,
        timeout
    ).text.lower()

    reflected_positions = [match.start() for match in re.finditer(base_marker, response)]
    filled_positions = fill_holes(positions, reflected_positions)

    efficiencies = []
    for idx, position in enumerate(filled_positions):
        local_efficiencies = []

        # Primeira tentativa com posição detectada automaticamente
        try:
            reflected = response[reflected_positions[idx]:reflected_positions[idx] + len(check_string)]
            local_efficiencies.append(fuzz.partial_ratio(reflected, check_string.lower()))
        except IndexError:
            pass

        # Segunda tentativa com posição preenchida por fill_holes
        if position:
            reflected = response[position:position + len(check_string)]
            encoded_check_string = encoding(check_string.lower()) if encoding else check_string.lower()

            efficiency = fuzz.partial_ratio(reflected, encoded_check_string)

            # Caso especial para escape com barra invertida
            if reflected[:-2] == f'\\{payload}':
                efficiency = 90

            local_efficiencies.append(efficiency)
            efficiencies.append(max(local_efficiencies))
        else:
            efficiencies.append(0)

    return list(filter(None, efficiencies))
