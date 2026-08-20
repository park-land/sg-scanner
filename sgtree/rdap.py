"""RDAP (Registration Data Access Protocol, RFC 7482/7483) lookups for
external IPs — grounds the Claude external-IP guess in who actually
registered the address block (and where), not just the rule's own
description text.

Uses rdap.org, a public bootstrap redirector run by APNIC Labs that forwards
any IP query to whichever regional registry (ARIN/RIPE/APNIC/LACNIC/AFRINIC)
actually holds it — no API key, no registration. Stdlib-only (urllib), so it
doesn't add a dependency. Best-effort throughout: a network failure, timeout,
or a response that doesn't parse the way we expect all degrade to "no data"
rather than raising — a lookup problem should never break the rest of the
report.
"""
import json
import urllib.error
import urllib.request

_TIMEOUT_SECONDS = 5
_BASE_URL = 'https://rdap.org/ip/'


def _org_from_entities(entities):
    """RDAP entities carry a vcardArray; the org name is the 'fn' (formatted
    name) field. Prefer a registrant/administrative entity over whatever
    happens to be listed first (often a technical/abuse contact)."""
    def fn_of(entity):
        vcard = entity.get('vcardArray')
        if not vcard or len(vcard) < 2:
            return None
        for field in vcard[1]:
            if len(field) >= 4 and field[0] == 'fn':
                return field[3]
        return None

    preferred_roles = {'registrant', 'administrative'}
    fallback = None
    for entity in entities or []:
        name = fn_of(entity)
        if not name:
            continue
        if preferred_roles & set(entity.get('roles', [])):
            return name
        fallback = fallback or name
    return fallback


def lookup(ip_or_cidr):
    """Best-effort RDAP lookup. Returns {'org', 'network_name', 'country'}
    (any of which may be None) or None if nothing could be resolved at all."""
    try:
        req = urllib.request.Request(
            _BASE_URL + ip_or_cidr,
            headers={'Accept': 'application/rdap+json'},
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:
            data = json.load(resp)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError):
        return None
    except Exception:
        return None

    result = {
        'org':          _org_from_entities(data.get('entities')),
        'network_name': data.get('name'),
        'country':      data.get('country'),
    }
    return result if any(result.values()) else None
