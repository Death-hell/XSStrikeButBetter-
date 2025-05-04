import re
import json
import hashlib
from urllib.parse import urlparse

from core.colors import green, end
from core.requester import requester
from core.utils import deJSON, js_extractor, handle_anchor, getVar, updateVar
from core.log import setup_logger

logger = setup_logger(__name__)


def is_defined(value):
    return value is not None


def scan(data, extractor, definitions, matcher=None):
    matcher = matcher or _simple_match
    detected = []
    for component, definition in definitions.items():
        extractors = definition.get("extractors", {}).get(extractor, [])
        for pattern in extractors:
            match = matcher(pattern, data)
            if match:
                detected.append({
                    "version": match,
                    "component": component,
                    "detection": extractor
                })
    return detected


def _simple_match(regex, data):
    regex = deJSON(regex)
    match = re.search(regex, data)
    return match.group(1) if match else None


def _replacement_match(regex, data):
    try:
        regex = deJSON(regex)
        parts = re.search(r'^\/(.*[^\\])\/([^\/]+)\/$', regex)
        if not parts:
            return None
        match = re.search(f"({parts.group(1)})", data)
        if match:
            return re.sub(parts.group(1), parts.group(2), match.group(0))
        return None
    except Exception:
        return None


def _scanhash(file_hash, definitions):
    for component, definition in definitions.items():
        hashes = definition.get("extractors", {}).get("hashes", {})
        if file_hash in hashes:
            return [{
                "version": hashes[file_hash],
                "component": component,
                "detection": 'hash'
            }]
    return []


def check(results, definitions):
    for result in results:
        component = result.get("component")
        if component not in definitions:
            continue
        vulns = definitions[component].get("vulnerabilities", [])
        for vuln in vulns:
            if not _is_at_or_above(result["version"], vuln.get("below")):
                if vuln.get("atOrAbove") and not _is_at_or_above(result["version"], vuln["atOrAbove"]):
                    continue
                vuln_data = {
                    "info": vuln.get("info"),
                    "severity": vuln.get("severity"),
                    "identifiers": vuln.get("identifiers")
                }
                result.setdefault("vulnerabilities", []).append(vuln_data)
    return results


def _is_at_or_above(v1, v2):
    if not v1 or not v2:
        return True
    parts1 = re.split(r'[.-]', v1)
    parts2 = re.split(r'[.-]', v2)
    max_len = max(len(parts1), len(parts2))
    for i in range(max_len):
        a = _to_comparable(parts1[i]) if i < len(parts1) else 0
        b = _to_comparable(parts2[i]) if i < len(parts2) else 0
        if type(a) != type(b):
            return isinstance(a, int)
        if a > b:
            return True
        if a < b:
            return False
    return True


def _to_comparable(value):
    if not is_defined(value):
        return 0
    return int(value) if value.isdigit() else value


def scan_file_content(content, definitions):
    result = scan(content, 'filecontent', definitions)
    if not result:
        result = scan(content, 'filecontentreplace', definitions, _replacement_match)
    if not result:
        file_hash = hashlib.sha1(content.encode('utf8')).hexdigest()
        result = _scanhash(file_hash, definitions)
    return check(result, definitions)


def scan_uri(uri, definitions):
    return scan(uri, 'uri', definitions)


def main_scanner(uri, response_text):
    definitions = getVar('definitions')
    results = scan_uri(uri, definitions)
    results += scan_file_content(response_text, definitions)
    if not results:
        return None

    first = results[0]
    final = {
        'component': first['component'],
        'version': first['version'],
        'vulnerabilities': []
    }

    seen = set()
    for item in results:
        for vuln in item.get('vulnerabilities', []):
            vuln_str = json.dumps(vuln, sort_keys=True)
            if vuln_str not in seen:
                seen.add(vuln_str)
                final['vulnerabilities'].append(vuln)

    return final


def retireJs(url, response):
    scripts = js_extractor(response)
    for script in scripts:
        if script in getVar('checkedScripts'):
            continue
        updateVar('checkedScripts', script, 'add')
        uri = handle_anchor(url, script)

        try:
            res = requester(uri, '', getVar('headers'), True, getVar('delay'), getVar('timeout'))
        except Exception as e:
            logger.error(f"Failed to fetch script {uri}: {str(e)}")
            continue

        result = main_scanner(uri, res.text)
        if result:
            logger.red_line()
            logger.good(f"Vulnerable component: {result['component']} v{result['version']}")
            logger.info(f"Component location: {uri}")
            logger.info(f"Total vulnerabilities: {len(result['vulnerabilities'])}")
            for vuln in result['vulnerabilities']:
                summary = vuln.get('identifiers', {}).get('summary', 'No summary')
                cves = ', '.join(vuln.get('identifiers', {}).get('CVE', []))
                severity = vuln.get('severity', 'Unknown')
                logger.info(f"{green}Summary:{end} {summary}")
                logger.info(f"Severity: {severity}")
                logger.info(f"CVE: {cves}")
            logger.red_line()
