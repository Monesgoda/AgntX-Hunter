"""Unit tests for pentest.framework.scope (stdlib unittest, no network, no I/O beyond tmp files).

Run from the repository root:  python -m unittest discover -s tests -v
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pentest.framework import scope as S  # noqa: E402


def entry(**kw):
    base = {'status': 'authorized', 'in_scope': ['example.com', '*.example.com']}
    base.update(kw)
    return base


class HostNormalizationTests(unittest.TestCase):
    def test_lowercase_and_single_root_dot(self):
        self.assertEqual(S._host('Example.COM.'), 'example.com')

    def test_multiple_trailing_dots_are_not_collapsed(self):
        # Regression: rstrip('.') used to turn 'example.com..' into 'example.com'.
        self.assertFalse(S.check_target(entry(), 'http://example.com../'))
        self.assertNotEqual(S._host('example.com..'), 'example.com')
        self.assertFalse(S._match(S._host('example.com..'), 'example.com'))

    def test_host_port_is_stripped(self):
        self.assertEqual(S._host('example.com:8443'), 'example.com')

    def test_ipv6_forms(self):
        self.assertEqual(S._host('[::1]:80'), '::1')
        self.assertEqual(S._host('http://[2001:db8::1]/x'), '2001:db8::1')

    def test_idna(self):
        self.assertEqual(S._host('bücher.example'), 'xn--bcher-kva.example')

    def test_rejects_paths_credentials_and_empty(self):
        for bad in ('', '  ', 'example.com/path', 'user@example.com', 'a\\b',
                    'http://user:pw@example.com/', 'ftp://example.com'):
            with self.assertRaises(S.ScopeError, msg=bad):
                S._host(bad)


class ScopeSpecTests(unittest.TestCase):
    def test_valid_specs(self):
        for ok in ('example.com', '*.example.com', '10.0.0.0/30', '192.0.2.7', 'https://example.com',
                   'https://example.com/'):
            self.assertTrue(S._valid_scope_spec(ok), ok)

    def test_invalid_specs(self):
        for bad in ('', ' ', None, 5, 'example.com/admin', 'https://example.com/admin',
                    'https://example.com/?q=1', 'a@b.com', 'a%41.com', 'x#y', 'a\\b'):
            self.assertFalse(S._valid_scope_spec(bad), repr(bad))


class MatchTests(unittest.TestCase):
    def test_exact_and_wildcard(self):
        self.assertTrue(S._match('example.com', 'example.com'))
        self.assertTrue(S._match('a.example.com', '*.example.com'))
        self.assertTrue(S._match('a.b.example.com', '*.example.com'))
        self.assertFalse(S._match('example.com', '*.example.com'))
        self.assertFalse(S._match('badexample.com', '*.example.com'))
        self.assertFalse(S._match('example.com.evil.net', 'example.com'))

    def test_cidr(self):
        self.assertTrue(S._match('10.0.0.2', '10.0.0.0/30'))
        self.assertFalse(S._match('10.0.0.9', '10.0.0.0/30'))
        self.assertFalse(S._match('example.com', '10.0.0.0/30'))


class LoadScopeTests(unittest.TestCase):
    def _load(self, doc, eid='e1'):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'scope.json'
            p.write_text(json.dumps(doc), encoding='utf8')
            return S.load_scope(p, eid)

    def test_authorized_loads(self):
        e = self._load({'engagements': {'e1': entry()}})
        self.assertEqual(e['in_scope'], ['example.com', '*.example.com'])

    def test_list_format(self):
        e = self._load({'engagements': [dict(entry(), id='e1')]})
        self.assertEqual(e['status'], 'authorized')

    def test_pending_and_unknown_status_fail_closed(self):
        for status in ('pending_authorization', None, 'AUTHORIZED', True):
            with self.assertRaises(S.ScopeError, msg=str(status)):
                self._load({'engagements': {'e1': entry(status=status)}})

    def test_unregistered_engagement(self):
        with self.assertRaises(S.ScopeError):
            self._load({'engagements': {'e1': entry()}}, 'other')

    def test_bad_engagement_ids(self):
        for bad in ('../x', '', '-a', 'a b', 'a' * 65):
            with self.assertRaises(S.ScopeError, msg=bad):
                self._load({'engagements': {'e1': entry()}}, bad)

    def test_duplicate_id_in_list(self):
        doc = {'engagements': [dict(entry(), id='e1'), dict(entry(), id='e1')]}
        with self.assertRaises(S.ScopeError):
            self._load(doc)

    def test_missing_or_invalid_file(self):
        with self.assertRaises(S.ScopeError):
            S.load_scope('/nonexistent/scope.json', 'e1')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 's.json'
            p.write_text('{not json', encoding='utf8')
            with self.assertRaises(S.ScopeError):
                S.load_scope(p, 'e1')

    def test_empty_or_path_in_scope(self):
        for bad in ([], ['example.com/admin'], 'example.com'):
            with self.assertRaises(S.ScopeError, msg=str(bad)):
                self._load({'engagements': {'e1': entry(in_scope=bad)}})

    def test_approval_required_needs_reference(self):
        with self.assertRaises(S.ScopeError):
            self._load({'engagements': {'e1': entry(approval_required=True)}})
        self._load({'engagements': {'e1': entry(approval_required=True, approval_reference='TICKET-1')}})

    def test_boolean_flags_must_be_json_booleans(self):
        for key in ('allow_private_networks', 'allow_mutating_probes', 'allow_external_recon_tools',
                    'allow_infrastructure_scanning', 'allow_nmap_service_scan'):
            for bad in ('true', 1, 'yes', None):
                with self.assertRaises(S.ScopeError, msg=f'{key}={bad!r}'):
                    self._load({'engagements': {'e1': entry(**{key: bad})}})
            self._load({'engagements': {'e1': entry(**{key: False})}})


class RequestRateTests(unittest.TestCase):
    def test_stricter_wins(self):
        self.assertEqual(S.request_rate({'requests_per_second': 5}), 1)
        self.assertEqual(S.request_rate({'requests_per_second': 0.5}), 0.5)
        self.assertEqual(S.request_rate({}), 1)

    def test_invalid_rates(self):
        for bad in (0, -1, True, float('nan'), float('inf'), '1', None):
            with self.assertRaises(S.ScopeError, msg=repr(bad)):
                S.request_rate({'requests_per_second': bad})
        with self.assertRaises(S.ScopeError):
            S.request_rate([])


class EndpointKeyTests(unittest.TestCase):
    def test_normalizes_scheme_host_default_port_only(self):
        self.assertEqual(S.endpoint_url_key('HTTPS://Example.COM/A%2fb?x=1'),
                         ('https', 'example.com', 443, '/A%2fb', 'x=1'))
        self.assertEqual(S.endpoint_url_key('http://example.com')[2:4], (80, '/'))

    def test_rejections(self):
        for bad in ('', None, 'ftp://example.com/', 'http://u:p@example.com/', 'http://example.com/#f',
                    'http://example.com/a\\b', 'http://example.com//x', 'http://example.com/a b',
                    'http://example.com/%zz', 'http://example.com:0/', 'http://example.com:99999/',
                    'http://[::1%25eth0]/', 'http://[1.2.3.4]/', 'http://example.com:/',
                    'http://exa_mple.com/', 'http://example.com/é'):
            with self.assertRaises(S.ScopeError, msg=repr(bad)):
                S.endpoint_url_key(bad)


class RestrictedEndpointTests(unittest.TestCase):
    def test_absent_returns_none(self):
        self.assertIsNone(S.validate_restricted_endpoints({}))

    def test_present_but_empty_or_malformed_raises(self):
        for bad in (None, [], {}, 'x', [{'url': 'http://example.com/'}],
                    [{'url': 'http://example.com/', 'methods': []}],
                    [{'url': 'http://example.com/', 'methods': ['get']}],
                    [{'url': 'http://example.com/', 'methods': ['GET', 'GET']}],
                    [{'url': 'http://example.com/', 'methods': ['GET'], 'extra': 1}]):
            with self.assertRaises(S.ScopeError, msg=repr(bad)):
                S.validate_restricted_endpoints({'restricted_endpoints': bad})

    def test_exact_endpoint_and_method(self):
        e = entry(restricted_endpoints=[{'url': 'https://example.com/api?id=1', 'methods': ['GET']}])
        self.assertTrue(S.check_target(e, 'https://example.com/api?id=1', method='GET'))
        self.assertFalse(S.check_target(e, 'https://example.com/api?id=1', method='POST'))
        self.assertFalse(S.check_target(e, 'https://example.com/api?id=2', method='GET'))
        self.assertFalse(S.check_target(e, 'https://example.com/api/', method='GET'))
        self.assertFalse(S.check_target(e, 'https://example.com/other', method='GET'))

    def test_bare_host_only_for_inventory(self):
        e = entry(restricted_endpoints=[{'url': 'https://example.com/api', 'methods': ['GET']}])
        self.assertTrue(S.check_target(e, 'example.com'))
        self.assertFalse(S.check_target(e, 'example.com', method='GET'))

    def test_services_refuse_restricted_scopes(self):
        e = entry(in_scope=['192.0.2.1'],
                  restricted_endpoints=[{'url': 'http://192.0.2.1/', 'methods': ['GET']}])
        with self.assertRaises(S.ScopeError):
            S.require_service(e, '192.0.2.1', 80)
        with self.assertRaises(S.ScopeError):
            S.nmap_targets(e)


class CheckTargetTests(unittest.TestCase):
    def test_basic_in_scope(self):
        e = entry()
        self.assertTrue(S.check_target(e, 'https://example.com/'))
        self.assertTrue(S.check_target(e, 'https://www.example.com/x?y=1'))
        self.assertFalse(S.check_target(e, 'https://example.org/'))
        self.assertFalse(S.check_target(e, 'https://example.com.evil.net/'))

    def test_unsupported_scheme_and_userinfo(self):
        self.assertFalse(S.check_target(entry(), 'ftp://example.com/'))
        self.assertFalse(S.check_target(entry(), 'https://example.com@evil.net/'))
        self.assertFalse(S.check_target(entry(), 'https://user:pw@example.com/'))

    def test_default_ports_only(self):
        e = entry()
        self.assertTrue(S.check_target(e, 'http://example.com:80/'))
        self.assertFalse(S.check_target(e, 'http://example.com:8080/'))
        self.assertTrue(S.check_target(entry(allowed_ports=[8080]), 'http://example.com:8080/'))
        self.assertFalse(S.check_target(entry(allowed_ports=[8080]), 'http://example.com/'))

    def test_out_of_scope_ports_win(self):
        e = entry(allowed_ports=[80, 443, 8443], out_of_scope_ports=[8443])
        self.assertFalse(S.check_target(e, 'https://example.com:8443/'))
        self.assertTrue(S.check_target(e, 'https://example.com/'))

    def test_allowed_schemes(self):
        e = entry(allowed_schemes=['https'])
        self.assertTrue(S.check_target(e, 'https://example.com/'))
        self.assertFalse(S.check_target(e, 'http://example.com/'))

    def test_malformed_port_config_fails_closed(self):
        for bad in ([True], [False], ['x'], [0], [70000], [80.5], 'abc', 443, None, [None]):
            self.assertFalse(S.check_target(entry(allowed_ports=bad), 'https://example.com/'), repr(bad))
        self.assertFalse(S.check_target(entry(out_of_scope_ports=[True]), 'https://example.com/'))
        self.assertFalse(S.check_target(entry(out_of_scope_ports='x'), 'https://example.com/'))

    def test_boolean_port_does_not_authorize_port_one(self):
        # Regression: int(True) == 1, so allowed_ports=[True] used to allow port 1.
        self.assertFalse(S.check_target(entry(allowed_ports=[True]), 'http://example.com:1/'))

    def test_invalid_method(self):
        for bad in ('get', 'TRACE', 5, ''):
            self.assertFalse(S.check_target(entry(), 'https://example.com/', method=bad), repr(bad))

    def test_missing_in_scope_key(self):
        self.assertFalse(S.check_target({}, 'https://example.com/'))

    def test_ip_and_cidr_scope(self):
        e = entry(in_scope=['10.0.0.0/30'])
        self.assertTrue(S.check_target(e, 'http://10.0.0.1/'))
        self.assertFalse(S.check_target(e, 'http://10.0.0.8/'))
        self.assertFalse(S.check_target(e, 'http://example.com/'))

    def test_ipv6_literal(self):
        e = entry(in_scope=['2001:db8::/126'])
        self.assertTrue(S.check_target(e, 'http://[2001:db8::1]/'))
        self.assertFalse(S.check_target(e, 'http://[2001:db8::99]/'))

    def test_require_target_raises(self):
        self.assertTrue(S.require_target(entry(), 'https://example.com/'))
        with self.assertRaises(S.ScopeError):
            S.require_target(entry(), 'https://example.org/')


class OutOfScopeTests(unittest.TestCase):
    def test_exclusion_beats_inclusion(self):
        e = entry(out_of_scope=['admin.example.com'])
        self.assertFalse(S.check_target(e, 'https://admin.example.com/'))
        self.assertTrue(S.check_target(e, 'https://www.example.com/'))

    def test_wildcard_exclusion(self):
        e = entry(out_of_scope=['*.internal.example.com'])
        self.assertFalse(S.check_target(e, 'https://db.internal.example.com/'))
        self.assertTrue(S.check_target(e, 'https://www.example.com/'))

    def test_forbidden_alias(self):
        self.assertFalse(S.check_target(entry(forbidden=['admin.example.com']), 'https://admin.example.com/'))

    def test_both_exclusion_keys_are_merged(self):
        # Regression: a non-empty/empty out_of_scope used to hide `forbidden` entirely.
        e = entry(out_of_scope=[], forbidden=['admin.example.com'])
        self.assertFalse(S.check_target(e, 'https://admin.example.com/'))
        e = entry(out_of_scope=['a.example.com'], forbidden=['b.example.com'])
        self.assertFalse(S.check_target(e, 'https://a.example.com/'))
        self.assertFalse(S.check_target(e, 'https://b.example.com/'))
        self.assertTrue(S.check_target(e, 'https://c.example.com/'))

    def test_malformed_exclusions_deny_everything(self):
        for bad in ('admin.example.com', 5, {'a': 1}):
            self.assertFalse(S.check_target(entry(out_of_scope=bad), 'https://www.example.com/'), repr(bad))
            self.assertFalse(S.check_target(entry(forbidden=bad), 'https://www.example.com/'), repr(bad))
        for bad_item in (['example.com/admin'], [None], [''], ['a@b']):
            self.assertFalse(S.check_target(entry(out_of_scope=bad_item), 'https://www.example.com/'), repr(bad_item))


class HttpEndpointTests(unittest.TestCase):
    def test_defaults_to_get(self):
        self.assertTrue(S.require_http_endpoint(entry(), {'url': 'https://example.com/'}))

    def test_rejections(self):
        for bad in (None, {}, {'url': 5}, {'url': 'example.com'}, {'url': 'ftp://example.com/'},
                    {'url': 'https://example.com/', 'method': 'get'},
                    {'url': 'https://example.com/', 'method': 5}):
            with self.assertRaises(S.ScopeError, msg=repr(bad)):
                S.require_http_endpoint(entry(), bad)

    def test_method_enforced_with_restrictions(self):
        e = entry(restricted_endpoints=[{'url': 'https://example.com/x', 'methods': ['GET']}])
        S.require_http_endpoint(e, {'url': 'https://example.com/x'})
        with self.assertRaises(S.ScopeError):
            S.require_http_endpoint(e, {'url': 'https://example.com/x', 'method': 'DELETE'})


class RootsAndNmapTests(unittest.TestCase):
    def test_roots(self):
        e = entry(in_scope=['*.example.com', 'api.example.org', '10.0.0.0/30', '192.0.2.5', 'localhost'])
        self.assertEqual(S.roots(e), ['api.example.org', 'example.com'])

    def test_nmap_targets_exact_ips_only_by_default(self):
        e = entry(in_scope=['192.0.2.5', '10.0.0.0/30', 'example.com'])
        self.assertEqual(S.nmap_targets(e), ['192.0.2.5'])

    def test_nmap_cidr_expansion_opt_in_and_bounded(self):
        e = entry(in_scope=['10.0.0.0/30'], nmap_expand_cidr=True)
        self.assertEqual(S.nmap_targets(e), ['10.0.0.1', '10.0.0.2'])
        with self.assertRaises(S.ScopeError):
            S.nmap_targets(entry(in_scope=['10.0.0.0/24'], nmap_expand_cidr=True))

    def test_nmap_excluded_ip_is_dropped_and_cap_enforced(self):
        e = entry(in_scope=['10.0.0.0/30'], nmap_expand_cidr=True, out_of_scope=['10.0.0.2'])
        self.assertEqual(S.nmap_targets(e), ['10.0.0.1'])
        e = entry(in_scope=['192.0.2.1', '192.0.2.2', '192.0.2.3'], nmap_max_hosts=2)
        with self.assertRaises(S.ScopeError):
            S.nmap_targets(e)


class RequireServiceTests(unittest.TestCase):
    def test_allowed_and_blocked_ports(self):
        e = entry(in_scope=['192.0.2.1'], allowed_ports=[22, 443], out_of_scope_ports=[443])
        self.assertTrue(S.require_service(e, '192.0.2.1', 22))
        for port in (443, 80, 0, 70000):
            with self.assertRaises(S.ScopeError, msg=str(port)):
                S.require_service(e, '192.0.2.1', port)

    def test_bad_inputs(self):
        e = entry(in_scope=['192.0.2.1'], allowed_ports=[22])
        for port in ('abc', None, True):
            with self.assertRaises(S.ScopeError, msg=repr(port)):
                S.require_service(e, '192.0.2.1', port)
        with self.assertRaises(S.ScopeError):
            S.require_service(e, '192.0.2.1', 22, protocol='icmp')
        with self.assertRaises(S.ScopeError):
            S.require_service(e, '192.0.2.99', 22)

    def test_boolean_allowed_port_does_not_authorize_port_one(self):
        e = entry(in_scope=['192.0.2.1'], allowed_ports=[True])
        with self.assertRaises(S.ScopeError):
            S.require_service(e, '192.0.2.1', 1)


if __name__ == '__main__':
    unittest.main()
