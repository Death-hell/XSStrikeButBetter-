from concurrent.futures import ThreadPoolExecutor
from core.checker import checker


def extract_environments(occurrences):
    environments = set(['<', '>'])
    for occ in occurrences.values():
        context = occ['context']
        details = occ['details']
        if context == 'comment':
            environments.add('-->')
        elif context == 'script':
            environments.add(details.get('quote', ''))
            environments.add('</scRipT/>')
        elif context == 'attribute':
            if details.get('type') == 'value' and details.get('name') == 'srcdoc':
                environments.add('&lt;')
                environments.add('&gt;')
            if details.get('quote'):
                environments.add(details['quote'])
    return {env for env in environments if env}


def evaluate_environment(env, url, params, headers, GET, delay, positions, timeout, encoding, total_occurrences):
    efficiencies = checker(url, params, headers, GET, delay, env, positions, timeout, encoding)
    efficiencies.extend([0] * (total_occurrences - len(efficiencies)))
    return env, efficiencies


def filterChecker(url, params, headers, GET, delay, occurrences, timeout, encoding, debug=False):
    positions = list(occurrences.keys())
    environments = extract_environments(occurrences)
    total_occurrences = len(occurrences)

    # Initialize score dict for each occurrence
    for occ in occurrences.values():
        occ['score'] = {}

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [
            executor.submit(
                evaluate_environment,
                env, url, params, headers, GET, delay,
                positions, timeout, encoding, total_occurrences
            )
            for env in environments
        ]
        for future in futures:
            env, efficiencies = future.result()
            for i, occ_key in enumerate(occurrences):
                occurrences[occ_key]['score'][env] = efficiencies[i]

    # Optionally print best environment per occurrence
    if debug:
        for i, occ in occurrences.items():
            context = occ['context']
            best = max(occ['score'], key=occ['score'].get)
            score = occ['score'][best]
            print(f"[+] Context: {context} | Best Payload: '{best}' | Score: {score}")

    return occurrences
