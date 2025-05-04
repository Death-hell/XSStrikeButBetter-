import copy
from random import randint
from time import sleep
from urllib.parse import unquote

from core.colors import end, red, green, yellow
from core.config import fuzzes, xsschecker
from core.requester import requester
from core.utils import replace_value, counter
from core.log import setup_logger

logger = setup_logger(__name__)

def fuzzer(url, params, headers, GET=True, delay=0, timeout=10, WAF=False, encoding=None):
    for fuzz in fuzzes:
        fuzz_delay = delay + randint(delay, delay * 2) + counter(fuzz)
        sleep(fuzz_delay)

        try:
            fuzz_input = encoding(unquote(fuzz)) if encoding else fuzz
            data = replace_value(params, xsschecker, fuzz_input, copy.deepcopy)

            response = requester(url, data, headers, GET, delay / 2, timeout)
            status_code = str(response.status_code)

            # Resultado da fuzzing
            if encoding:
                fuzz_display = encoding(fuzz)
            else:
                fuzz_display = fuzz

            if fuzz_display.lower() in response.text.lower():
                result = f"{green}[passed]{end}"
            elif not status_code.startswith('2'):
                result = f"{red}[blocked]{end}"
            else:
                result = f"{yellow}[filtered]{end}"

            logger.info(f"{result} {fuzz_display}")

        except Exception as e:
            logger.error(f"WAF detected or connection error: {e}")

            if delay == 0:
                delay += 6
                logger.info(f"Delay increased to {green}6{end} seconds.")

            cooldown = (delay + 1) * 50
            logger.info(f"Sleeping for {green}{cooldown}{end} seconds to evade WAF...")

            for remaining in range(cooldown, 0, -1):
                logger.info(f"\rResuming in {green}{remaining}{end} seconds...\t", end='', flush=True)
                sleep(1)
            print()

            try:
                test_response = requester(url, params, headers, GET, 0, timeout)
                logger.good(f"Phew! Looks like sleeping helped — continuing fuzzing.")
            except Exception:
                logger.error(f"\nWAF has likely blocked our IP. Exiting fuzzing loop.")
                break
