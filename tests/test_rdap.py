"""Unit tests for sgtree/rdap.py. No real network access — urllib.request is
monkeypatched at the urlopen level.
"""
import io
import json

from sgtree import rdap


class _FakeResponse:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _rdap_payload(org=None, network_name=None, country=None, roles=('registrant',)):
    entities = []
    if org:
        entities.append({'roles': list(roles), 'vcardArray': ['vcard', [['fn', {}, 'text', org]]]})
    payload = {}
    if entities:
        payload['entities'] = entities
    if network_name:
        payload['name'] = network_name
    if country:
        payload['country'] = country
    return payload


class TestLookup:
    def test_parses_org_network_name_and_country(self, monkeypatch):
        payload = _rdap_payload(org='Cloudflare, Inc.', network_name='CLOUDFLARENET', country='US')
        monkeypatch.setattr(rdap.urllib.request, 'urlopen', lambda req, timeout=None: _FakeResponse(payload))

        result = rdap.lookup('198.51.100.9')

        assert result == {'org': 'Cloudflare, Inc.', 'network_name': 'CLOUDFLARENET', 'country': 'US'}

    def test_prefers_registrant_role_over_other_entities(self, monkeypatch):
        payload = {
            'entities': [
                {'roles': ['technical'], 'vcardArray': ['vcard', [['fn', {}, 'text', 'Some Abuse Contact']]]},
                {'roles': ['registrant'], 'vcardArray': ['vcard', [['fn', {}, 'text', 'Amazon.com, Inc.']]]},
            ],
        }
        monkeypatch.setattr(rdap.urllib.request, 'urlopen', lambda req, timeout=None: _FakeResponse(payload))

        result = rdap.lookup('203.0.113.5')

        assert result['org'] == 'Amazon.com, Inc.'

    def test_falls_back_to_any_entity_when_no_preferred_role(self, monkeypatch):
        payload = {
            'entities': [
                {'roles': ['technical'], 'vcardArray': ['vcard', [['fn', {}, 'text', 'Some Contact']]]},
            ],
        }
        monkeypatch.setattr(rdap.urllib.request, 'urlopen', lambda req, timeout=None: _FakeResponse(payload))

        result = rdap.lookup('203.0.113.5')

        assert result['org'] == 'Some Contact'

    def test_network_error_returns_none(self, monkeypatch):
        def boom(req, timeout=None):
            raise rdap.urllib.error.URLError('no network')

        monkeypatch.setattr(rdap.urllib.request, 'urlopen', boom)

        assert rdap.lookup('198.51.100.9') is None

    def test_malformed_json_returns_none(self, monkeypatch):
        class BadResponse:
            def read(self):
                return b'not json'

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(rdap.urllib.request, 'urlopen', lambda req, timeout=None: BadResponse())

        assert rdap.lookup('198.51.100.9') is None

    def test_empty_response_returns_none(self, monkeypatch):
        monkeypatch.setattr(rdap.urllib.request, 'urlopen', lambda req, timeout=None: _FakeResponse({}))

        assert rdap.lookup('198.51.100.9') is None
