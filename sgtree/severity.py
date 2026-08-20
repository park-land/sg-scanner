"""Severity scale, the deterministic floor, and non-AI baseline severities.

This is the load-bearing module for the "AI never sinks below the floor"
guarantee: LEVELS defines a strict order, floor_for_port_range() says the
minimum severity a wide-open critical port must carry no matter what,
and clamp() is the one function anything claiming an AI-assessed severity
must be passed through before it's trusted. clamp() is pure arithmetic on
strings — it doesn't call Claude, doesn't know what Claude said, and can't be
talked out of the floor by anything in a prompt, a description, or a rule
name. That's deliberate: the guarantee has to live in code a model can't
argue with, not in an instruction a model could be talked past.
"""

LEVELS = ['info', 'low', 'medium', 'high', 'critical']
_INDEX = {level: i for i, level in enumerate(LEVELS)}

# Ports where "open to the entire internet" is a floor-High finding
# regardless of what an AI (or a misleading rule description) says about it.
# Remote administration and databases/caches with no application-layer auth
# gate in front of them are the two categories that land here.
CRITICAL_PORTS = {
    22:    'SSH',
    3389:  'RDP',
    1433:  'MSSQL',
    1521:  'Oracle',
    3306:  'MySQL/MariaDB',
    5432:  'PostgreSQL',
    6379:  'Redis',
    9042:  'Cassandra',
    9200:  'Elasticsearch',
    11211: 'Memcached',
    27017: 'MongoDB',
    5984:  'CouchDB',
    2379:  'etcd',
}
CRITICAL_FLOOR = 'high'


def index(level):
    """Position in LEVELS, or None if not a recognized level. Tolerates an
    unhashable value (a dict/list where a string was expected — exactly the
    shape a malformed or adversarial AI response might take) rather than
    raising; that's still just "not a recognized level"."""
    try:
        return _INDEX.get(level)
    except TypeError:
        return None


def is_valid(level):
    return index(level) is not None


def max_level(a, b):
    """The more severe of two levels. An unrecognized/None level loses to
    any recognized one — never silently drops a real severity."""
    ia, ib = index(a), index(b)
    if ia is None and ib is None:
        return a or b
    if ia is None:
        return b
    if ib is None:
        return a
    return a if ia >= ib else b


def floor_for_port_range(from_port, to_port):
    """The minimum severity an allow-all rule covering this port range must
    carry, or None if no critical port falls in range. A None from_port/
    to_port is AWS's convention for "all ports/all traffic" (e.g. protocol
    -1), which covers every critical port, so it floors too."""
    if from_port is None or to_port is None:
        return CRITICAL_FLOOR
    for port in CRITICAL_PORTS:
        if from_port <= port <= to_port:
            return CRITICAL_FLOOR
    return None


def critical_ports_in_range(from_port, to_port):
    """The named critical services (if any) an allow-all port range covers —
    for building an explanation, not for the floor decision itself."""
    if from_port is None or to_port is None:
        return list(CRITICAL_PORTS.items())
    return [(p, name) for p, name in CRITICAL_PORTS.items() if from_port <= p <= to_port]


def clamp(level, floor):
    """The one required call site: raises `level` up to `floor` if it's
    below it (or if `level` isn't a recognized value at all — treat an
    unparseable/missing AI severity as ground level, not as "no opinion",
    so a bad or adversarial response still can't slip under the floor).
    Returns `level` unchanged if there's no floor to enforce."""
    if floor is None:
        return level if is_valid(level) else 'medium'
    if not is_valid(level):
        return floor
    return max_level(level, floor)


# --- Non-AI baseline severities -------------------------------------------
# Used both as the severity shown when Claude is disabled/unavailable, and
# as the "current baseline" fed to Claude as context it may raise or lower
# (except where the floor above still applies regardless).

_BASELINE_BY_CHECK = {
    'sg_rule_no_description': 'low',
    'sg_stale_rule':          'medium',
    'sg_unused':              'low',
}


def baseline_for_finding(check_id, from_port=None, to_port=None):
    """A reasonable severity with no AI involved at all. For sg_allows_all
    this is the floor when a critical port is covered, else a flat 'medium'
    (the old undifferentiated behavior an AI severity pass is meant to beat —
    see the eval that measures the delta)."""
    if check_id == 'sg_allows_all':
        return floor_for_port_range(from_port, to_port) or 'medium'
    return _BASELINE_BY_CHECK.get(check_id, 'medium')
