"""Exercise the memory comparator through real files and the real CLI."""
import contextlib
import errno
import importlib.util
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).absolute().with_name('compare.py')
SPEC = importlib.util.spec_from_file_location('memory_compare', SCRIPT)
compare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compare)

ABSOLUTE = 8 * 1024 * 1024
PHASES = ('idle', 'loaded', 'drained', 'reapplied')
METRICS = ('rss_bytes', 'anon_bytes', 'peak_rss_bytes')
REQUIRED_EVIDENCE = (
    'tcp_bytes', 'udp_bytes', 'apply_count', 'loaded_connections',
    'drained_connections', 'drained_udp_connections', 'udp_during_load',
    'udp_drain_verified',
)


def metrics(rss, anon=None, peak=None):
    """Build one phase metric object with independent copies for each caller."""
    if anon is None:
        anon = rss
    if peak is None:
        peak = rss
    return {'rss_bytes': rss, 'anon_bytes': anon, 'peak_rss_bytes': peak}


def uniform(rss, anon=None, peak=None):
    """Repeat one metric object across every measured phase."""
    metric = metrics(rss, anon, peak)
    return dict((phase, dict(metric)) for phase in PHASES)


def evidence(**overrides):
    """Return the minimal evidence contract, including proven load and drain UDP."""
    body = {
        'tcp_bytes': {'wg1': 1200, 'wg2': 900},
        'udp_bytes': {'wg1': 400, 'wg2': 350},
        'apply_count': 3,
        'loaded_connections': 32,
        'drained_connections': 0,
        'drained_udp_connections': 2,
        'udp_during_load': True,
        'udp_drain_verified': True,
    }
    body.update(overrides)
    return body


def document(variant, scenario, run, phases, evidence_body=None, samples=None, extra=None):
    """Build one run document. Extra evidence belongs inside evidence_body."""
    body = {
        'schema_version': 1,
        'variant': variant,
        'scenario': scenario,
        'run': run,
        'phases': phases,
        'evidence': evidence() if evidence_body is None else evidence_body,
    }
    if samples is not None:
        body['samples'] = samples
    if extra:
        body.update(extra)
    return body


class MemoryCompareTest(unittest.TestCase):
    """Check the gate the way the runner invokes it, using temporary run files."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.baseline = self.root / 'baseline'
        self.candidate = self.root / 'candidate'
        self.output = self.root / 'report.json'
        self.baseline.mkdir()
        self.candidate.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def write_run(self, directory, variant, scenario, run, phases, **kwargs):
        """Write one result file with the filename the comparator requires."""
        path = directory / ('%s-%s.json' % (scenario, run))
        payload = document(variant, scenario, run, phases, **kwargs)
        path.write_text(json.dumps(payload) + '\n', encoding='utf-8')
        return path

    def write_pair(self, baseline_phases, candidate_phases=None, awg_phases=None,
                   candidate_for_run=None, awg_kwargs=None):
        """Write three WireGuard pairs and the required candidate AmneziaWG run."""
        cand = None
        for run in (1, 2, 3):
            base = baseline_phases(run) if callable(baseline_phases) else baseline_phases
            if candidate_for_run is not None:
                cand = candidate_for_run(run)
            elif candidate_phases is not None:
                cand = candidate_phases(run) if callable(candidate_phases) else candidate_phases
            else:
                cand = base
            self.write_run(self.baseline, 'baseline', 'wireguard', run, base)
            self.write_run(self.candidate, 'candidate', 'wireguard', run, cand)
        if awg_phases is None:
            awg_phases = cand
        awg = awg_phases(1) if callable(awg_phases) else awg_phases
        self.write_run(self.candidate, 'candidate', 'amneziawg', 1, awg, **(awg_kwargs or {}))

    def clear(self):
        """Remove files created by an earlier subtest in this temporary root."""
        for directory in (self.baseline, self.candidate):
            if not directory.exists():
                directory.mkdir()
                continue
            for child in list(directory.iterdir()):
                if child.is_dir() and not child.is_symlink():
                    child.rmdir()
                else:
                    child.unlink()

    def evaluate(self):
        return compare.evaluate(self.baseline, self.candidate)

    def row(self, report, phase, metric):
        found = [
            item for item in report['comparisons']
            if item['phase'] == phase and item['metric'] == metric
        ]
        self.assertEqual(len(found), 1)
        return found[0]

    def error_text(self, report):
        return '\n'.join(
            '%s %s %s' % (item['file'], item['path'], item['message'])
            for item in report['errors']
        )

    def assert_malformed(self, snippet):
        report = self.evaluate()
        self.assertEqual(report['status'], 'malformed')
        self.assertFalse(report['passed'])
        self.assertEqual(report['comparisons'], [])
        self.assertIn(snippet, self.error_text(report))
        return report

    def reject(self, mutator, snippet, scenario='wireguard', directory='candidate'):
        """Plant a valid set, mutate one document, and require a closed failure."""
        self.clear()
        self.write_pair(uniform(20_000_000, anon=10_000_000))
        path = getattr(self, directory) / ('%s-1.json' % scenario)
        doc = json.loads(path.read_text(encoding='utf-8'))
        mutator(doc)
        path.write_text(json.dumps(doc), encoding='utf-8')
        return self.assert_malformed(snippet)

    def run_main(self, output=None):
        """Invoke the real CLI function in-process so coverage sees it."""
        output = self.output if output is None else output
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = compare.main([
                '--baseline', str(self.baseline),
                '--candidate', str(self.candidate),
                '--output', str(output),
            ])
        return code, stdout.getvalue(), stderr.getvalue()

    def run_cli(self, args=None):
        """Run the comparator script as a separate process."""
        if args is None:
            args = [
                '--baseline', str(self.baseline),
                '--candidate', str(self.candidate),
                '--output', str(self.output),
            ]
        return subprocess.run(
            [sys.executable, str(SCRIPT)] + list(args),
            capture_output=True, text=True, check=False,
        )

    def test_threshold_boundary_equality_passes_and_one_byte_fails(self):
        """Equality at the 8 MiB floor and at 10% passes; the next byte fails."""
        self.write_pair(uniform(1_000_000), uniform(9_388_608))
        report = self.evaluate()
        self.assertTrue(report['passed'], report['failures'])
        self.assertEqual(len(report['comparisons']), 12)
        self.assertEqual(report['failures'], [])
        self.assertEqual(report['threshold']['absolute_bytes'], 8_388_608)
        sample = self.row(report, 'idle', 'rss_bytes')
        self.assertEqual(sample['baseline_median'], 1_000_000)
        self.assertEqual(sample['candidate_median'], 9_388_608)
        self.assertEqual(sample['delta_bytes'], 8_388_608)
        self.assertEqual(sample['relative_allowance_bytes'], 100_000)
        self.assertEqual(sample['absolute_allowance_bytes'], ABSOLUTE)
        self.assertEqual(sample['allowance_bytes'], ABSOLUTE)
        self.assertEqual(sample['limit_bytes'], 9_388_608)
        self.assertTrue(sample['passed'])

        self.clear()

        def one_over(_run):
            body = uniform(9_388_608)
            body['loaded'] = metrics(9_388_608, 9_388_608, 9_388_609)
            return body

        self.write_pair(uniform(1_000_000), candidate_for_run=one_over)
        report = self.evaluate()
        self.assertEqual(report['status'], 'regression')
        self.assertEqual(
            [(item['phase'], item['metric']) for item in report['failures']],
            [('loaded', 'peak_rss_bytes')],
        )
        self.assertEqual(report['failures'][0]['limit_bytes'], 9_388_608)
        self.assertEqual(report['failures'][0]['candidate_median'], 9_388_609)

        self.clear()

        def at_relative(_run):
            body = uniform(200_000_000)
            body['reapplied'] = metrics(200_000_000, 200_000_000, 220_000_000)
            return body

        self.write_pair(uniform(200_000_000), candidate_for_run=at_relative)
        report = self.evaluate()
        relative = self.row(report, 'reapplied', 'peak_rss_bytes')
        self.assertEqual(relative['relative_allowance_bytes'], 20_000_000)
        self.assertEqual(relative['allowance_bytes'], 20_000_000)
        self.assertEqual(relative['limit_bytes'], 220_000_000)
        self.assertTrue(report['passed'], report['failures'])

        self.clear()

        def over_relative(_run):
            body = uniform(200_000_000)
            body['reapplied'] = metrics(200_000_000, 200_000_000, 220_000_001)
            return body

        self.write_pair(uniform(200_000_000), candidate_for_run=over_relative)
        report = self.evaluate()
        self.assertFalse(report['passed'])
        self.assertEqual(report['failures'][0]['phase'], 'reapplied')
        self.assertEqual(report['failures'][0]['metric'], 'peak_rss_bytes')
        self.assertEqual(report['failures'][0]['candidate_median'], 220_000_001)
        self.assertEqual(report['failures'][0]['limit_bytes'], 220_000_000)

        self.clear()

        def at_fraction(_run):
            body = uniform(200_000_003)
            body['drained'] = metrics(200_000_003, 200_000_003, 220_000_003)
            return body

        self.write_pair(uniform(200_000_003), candidate_for_run=at_fraction)
        report = self.evaluate()
        fraction = self.row(report, 'drained', 'peak_rss_bytes')
        self.assertEqual(fraction['relative_allowance_bytes'], 20_000_000)
        self.assertEqual(fraction['limit_bytes'], 220_000_003)
        self.assertTrue(report['passed'], report['failures'])

        self.clear()

        def over_fraction(_run):
            body = uniform(200_000_003)
            body['drained'] = metrics(200_000_003, 200_000_003, 220_000_004)
            return body

        self.write_pair(uniform(200_000_003), candidate_for_run=over_fraction)
        report = self.evaluate()
        self.assertEqual(report['status'], 'regression')
        self.assertEqual(report['failures'][0]['candidate_median'], 220_000_004)
        self.assertEqual(report['failures'][0]['limit_bytes'], 220_000_003)

    def test_plausible_false_green_mean_and_idle_do_not_hide_growth(self):
        """A lower idle phase and a low outlier must not hide median growth."""
        baseline_anon = 20_000_000
        limit = baseline_anon + ABSOLUTE
        high = limit + 1
        low = 1_000_000
        self.assertLess((low + high + high) / 3.0, limit)

        def candidate_run(run):
            body = uniform(40_000_000, anon=baseline_anon)
            body['idle'] = metrics(30_000_000, 15_000_000, 30_000_000)
            anon = low if run == 1 else high
            body['reapplied'] = metrics(40_000_000, anon, 40_000_000)
            return body

        self.write_pair(uniform(40_000_000, anon=baseline_anon), candidate_for_run=candidate_run)
        report = self.evaluate()
        self.assertEqual(report['status'], 'regression')
        self.assertFalse(report['passed'])
        self.assertEqual(
            [(item['phase'], item['metric']) for item in report['failures']],
            [('reapplied', 'anon_bytes')],
        )
        failed = report['failures'][0]
        self.assertEqual(failed['candidate_median'], high)
        self.assertEqual(failed['baseline_median'], baseline_anon)
        self.assertEqual(failed['limit_bytes'], limit)
        self.assertEqual(failed['delta_bytes'], high - baseline_anon)
        idle = self.row(report, 'idle', 'rss_bytes')
        self.assertLess(idle['candidate_median'], idle['baseline_median'])
        self.assertTrue(idle['passed'])

    def test_genuine_peak_growth_is_a_regression(self):
        """Flat RSS and anonymous RSS do not excuse sampled peak growth."""
        baseline = 40_000_000
        grown = baseline + ABSOLUTE + 1

        def candidate_run(_run):
            body = uniform(baseline, anon=20_000_000)
            body['loaded'] = metrics(baseline, 20_000_000, grown)
            return body

        self.write_pair(uniform(baseline, anon=20_000_000), candidate_for_run=candidate_run)
        report = self.evaluate()
        self.assertEqual(report['status'], 'regression')
        self.assertEqual(
            [(item['phase'], item['metric']) for item in report['failures']],
            [('loaded', 'peak_rss_bytes')],
        )
        failed = report['failures'][0]
        self.assertEqual(failed['candidate_median'], grown)
        self.assertEqual(failed['limit_bytes'], baseline + ABSOLUTE)
        self.assertEqual(failed['delta_bytes'], grown - baseline)
        for phase in PHASES:
            for metric in METRICS:
                if (phase, metric) == ('loaded', 'peak_rss_bytes'):
                    continue
                self.assertTrue(self.row(report, phase, metric)['passed'], (phase, metric))

    def test_median_outlier_does_not_fail_or_hide_growth(self):
        """One spike does not fail; one low sample does not hide two high runs."""
        baseline = 50_000_000
        spike = 400_000_000
        self.assertGreater(spike, baseline + ABSOLUTE)

        def spiked(run):
            if run == 3:
                return uniform(baseline, anon=25_000_000, peak=spike)
            return uniform(baseline, anon=25_000_000)

        self.write_pair(uniform(baseline, anon=25_000_000), candidate_for_run=spiked)
        report = self.evaluate()
        self.assertTrue(report['passed'], report['failures'])
        self.assertEqual(self.row(report, 'loaded', 'peak_rss_bytes')['candidate_median'], baseline)

        self.clear()
        low = 10_000_000
        high = baseline + ABSOLUTE + 1
        self.assertLess((low + high + high) / 3.0, baseline + ABSOLUTE)

        def masked(run):
            if run == 1:
                return uniform(low, anon=low // 2, peak=low)
            return uniform(high, anon=25_000_000, peak=high)

        self.write_pair(uniform(baseline, anon=25_000_000), candidate_for_run=masked)
        report = self.evaluate()
        self.assertEqual(report['status'], 'regression')
        rss = self.row(report, 'loaded', 'rss_bytes')
        self.assertEqual(rss['candidate_median'], high)
        self.assertFalse(rss['passed'])
        self.assertNotEqual(rss['candidate_median'], low)

    def test_invalid_evidence_is_not_success(self):
        """Incomplete, coerced, or out-of-contract evidence cannot pass the gate."""
        cases = (
            ('tcp zero', lambda doc: doc['evidence']['tcp_bytes'].__setitem__('wg1', 0), 'positive integer'),
            ('tcp tunnel', lambda doc: doc['evidence'].__setitem__('tcp_bytes', {'wg1': 10}), 'wg1 and wg2'),
            ('udp zero', lambda doc: doc['evidence']['udp_bytes'].__setitem__('wg2', 0), 'positive integer'),
            ('extra tunnel', lambda doc: doc['evidence']['udp_bytes'].__setitem__('wg3', 10), 'wg1 and wg2'),
            ('apply count', lambda doc: doc['evidence'].__setitem__('apply_count', 2), '>= 3'),
            ('apply bool', lambda doc: doc['evidence'].__setitem__('apply_count', True), '>= 3'),
            ('loaded count', lambda doc: doc['evidence'].__setitem__('loaded_connections', 31), '>= 32'),
            ('loaded bool', lambda doc: doc['evidence'].__setitem__('loaded_connections', True), 'TCP sessions'),
            ('tcp drain', lambda doc: doc['evidence'].__setitem__('drained_connections', 1), 'TCP sessions after drain'),
            ('tcp drain bool', lambda doc: doc['evidence'].__setitem__('drained_connections', False), 'TCP sessions after drain'),
            ('udp residual zero', lambda doc: doc['evidence'].__setitem__('drained_udp_connections', 0), 'integer 2'),
            ('udp residual one', lambda doc: doc['evidence'].__setitem__('drained_udp_connections', 1), 'integer 2'),
            ('udp residual nine', lambda doc: doc['evidence'].__setitem__('drained_udp_connections', 9), 'integer 2'),
            ('udp residual negative', lambda doc: doc['evidence'].__setitem__('drained_udp_connections', -1), 'integer 2'),
            ('udp residual bool', lambda doc: doc['evidence'].__setitem__('drained_udp_connections', False), 'integer 2'),
            ('udp residual float', lambda doc: doc['evidence'].__setitem__('drained_udp_connections', 1.0), 'integer 2'),
            ('udp flag false', lambda doc: doc['evidence'].__setitem__('udp_during_load', False), 'must be true'),
            ('udp flag one', lambda doc: doc['evidence'].__setitem__('udp_during_load', 1), 'must be true'),
            ('udp flag text', lambda doc: doc['evidence'].__setitem__('udp_during_load', 'true'), 'must be true'),
            ('udp drain false', lambda doc: doc['evidence'].__setitem__('udp_drain_verified', False), 'udp_drain_verified'),
            ('udp drain one', lambda doc: doc['evidence'].__setitem__('udp_drain_verified', 1), 'udp_drain_verified'),
            ('udp drain text', lambda doc: doc['evidence'].__setitem__('udp_drain_verified', 'true'), 'udp_drain_verified'),
            ('evidence list', lambda doc: doc.__setitem__('evidence', []), 'JSON object'),
        )
        for name, mutator, snippet in cases:
            with self.subTest(name=name):
                self.reject(mutator, snippet)
        for key in REQUIRED_EVIDENCE:
            with self.subTest(missing=key):
                self.reject(lambda doc, field=key: doc['evidence'].pop(field), key)
        with self.subTest(name='awg udp flag'):
            self.reject(
                lambda doc: doc['evidence'].pop('udp_during_load'),
                'udp_during_load',
                scenario='amneziawg',
            )
        with self.subTest(name='awg udp drain flag'):
            self.reject(
                lambda doc: doc['evidence'].pop('udp_drain_verified'),
                'udp_drain_verified',
                scenario='amneziawg',
            )

        self.clear()
        self.write_pair(
            uniform(20_000_000, anon=10_000_000),
            awg_kwargs={'evidence_body': evidence(per_cycle_udp_residual=[1, 0])},
        )
        report = self.evaluate()
        self.assertTrue(report['passed'], report['errors'])
        self.assertEqual(report['amneziawg']['evidence']['drained_udp_connections'], 2)
        self.assertIs(report['amneziawg']['evidence']['udp_during_load'], True)
        self.assertIs(report['amneziawg']['evidence']['udp_drain_verified'], True)

    def test_schema_identity_and_phase_invariants(self):
        """Reject documents that would make an illegal measurement look comparable."""
        self.reject(lambda doc: doc.__setitem__('schema_version', True), 'schema_version')
        self.reject(lambda doc: doc.__setitem__('schema_version', 1.0), 'schema_version')
        self.reject(lambda doc: doc.__setitem__('schema_version', '1'), 'schema_version')
        self.reject(lambda doc: doc.__setitem__('run', 2), 'run')
        self.reject(lambda doc: doc.__setitem__('scenario', 'amneziawg'), 'scenario')
        self.reject(lambda doc: doc.__setitem__('variant', 'baseline'), 'variant', directory='candidate')
        self.reject(lambda doc: doc.__setitem__('variant', 'candidate'), 'variant', directory='baseline')
        self.reject(lambda doc: doc['phases'].pop('drained'), 'missing drained')
        self.reject(lambda doc: doc['phases'].__setitem__('warmup', doc['phases']['idle']), 'unexpected warmup')
        self.reject(lambda doc: doc.__setitem__('phases', []), 'JSON object')
        self.reject(lambda doc: doc['phases']['idle'].pop('peak_rss_bytes'), 'peak_rss_bytes')
        self.reject(lambda doc: doc['phases']['idle'].__setitem__('rss_bytes', True), 'positive integer')
        self.reject(lambda doc: doc['phases']['idle'].__setitem__('rss_bytes', 0), 'positive integer')
        self.reject(lambda doc: doc['phases']['loaded'].__setitem__('rss_bytes', 10000000.5), 'positive integer')
        self.reject(
            lambda doc: doc['phases']['loaded'].__setitem__(
                'anon_bytes', doc['phases']['loaded']['rss_bytes'] + 1,
            ),
            'below anon_bytes',
        )
        self.reject(
            lambda doc: doc['phases']['drained'].__setitem__(
                'peak_rss_bytes', doc['phases']['drained']['rss_bytes'] - 1,
            ),
            'below rss_bytes',
        )
        self.reject(lambda doc: doc.__setitem__('samples', 'raw'), 'samples')
        self.reject(lambda doc: doc.__setitem__('binary', '/tmp/keenproxy'), 'unexpected keys')
        self.reject(lambda doc: doc.pop('evidence'), 'missing evidence')
        self.reject(lambda doc: doc.pop('phases'), 'missing phases')

        self.clear()
        self.write_pair(uniform(20_000_000, anon=10_000_000))
        (self.candidate / 'wireguard-1.json').write_text(
            '{"schema_version": 1, "schema_version": 1}\n', encoding='utf-8',
        )
        self.assert_malformed('duplicate key')

        self.clear()
        self.write_pair(uniform(20_000_000, anon=10_000_000))
        (self.candidate / 'wireguard-1.json').write_text('{"rss_bytes": Infinity}\n', encoding='utf-8')
        self.assert_malformed('non-finite')

        self.clear()
        self.write_pair(uniform(20_000_000, anon=10_000_000))
        (self.candidate / 'wireguard-1.json').write_bytes(b'\xff\xfe')
        self.assert_malformed('UTF-8')

        self.clear()
        self.write_pair(uniform(20_000_000, anon=10_000_000))
        (self.candidate / 'wireguard-1.json').write_text('[1, 2, 3]\n', encoding='utf-8')
        self.assert_malformed('JSON object')

        self.clear()
        self.write_pair(
            uniform(20_000_000, anon=10_000_000),
            awg_kwargs={'samples': [{'phase': 'loaded', 'rss_bytes': 20_000_000}]},
        )
        report = self.evaluate()
        self.assertTrue(report['passed'], report['errors'])

    def test_missing_run_unexpected_json_and_baseline_awg(self):
        """Missing runs and unexpected JSON fail closed; logs beside them do not."""
        self.write_pair(uniform(20_000_000, anon=10_000_000))
        (self.candidate / 'runner.log').write_text('kept beside results\n', encoding='utf-8')
        report = self.evaluate()
        self.assertTrue(report['passed'], report['errors'])

        (self.candidate / 'wireguard-2.json').unlink()
        (self.baseline / 'wireguard-3.json').unlink()
        report = self.assert_malformed('missing required run file')
        text = self.error_text(report)
        self.assertIn('wireguard-2.json', text)
        self.assertIn('wireguard-3.json', text)

        self.clear()
        self.write_pair(uniform(20_000_000, anon=10_000_000))
        (self.candidate / 'notes.json').write_text('{}\n', encoding='utf-8')
        self.assert_malformed('unexpected JSON input')

        self.clear()
        self.write_pair(uniform(20_000_000, anon=10_000_000))
        self.write_run(self.baseline, 'baseline', 'amneziawg', 1, uniform(20_000_000, anon=10_000_000))
        self.assert_malformed('baseline cannot include amneziawg')

        self.clear()
        self.write_pair(uniform(20_000_000, anon=10_000_000))
        self.write_run(self.candidate, 'candidate', 'amneziawg', 2, uniform(20_000_000, anon=10_000_000))
        self.assert_malformed('unexpected JSON input')

        self.clear()
        self.write_pair(uniform(20_000_000, anon=10_000_000))
        target = self.candidate / 'wireguard-1.json'
        target.unlink()
        target.mkdir()
        self.assert_malformed('not a regular file')

        self.clear()
        self.write_pair(uniform(20_000_000, anon=10_000_000))
        for child in list(self.baseline.iterdir()):
            child.unlink()
        self.baseline.rmdir()
        self.assert_malformed('baseline directory is missing')

        file_path = self.root / 'not-a-dir'
        file_path.write_text('x', encoding='utf-8')
        report = compare.evaluate(file_path, self.candidate)
        self.assertEqual(report['status'], 'malformed')
        self.assertFalse(report['passed'])
        self.assertIn('not a directory', self.error_text(report))

    def test_candidate_only_awg_is_excluded_from_medians(self):
        """AmneziaWG is reported and validated, never blended into WireGuard medians."""
        over = 40_000_000 + ABSOLUTE + 1

        def candidate_run(run):
            if run < 3:
                return uniform(40_000_000)
            return uniform(over)

        self.write_pair(
            uniform(40_000_000),
            candidate_for_run=candidate_run,
            awg_phases=uniform(over),
            awg_kwargs={'evidence_body': evidence(per_cycle_udp_residual=[1, 0])},
        )
        report = self.evaluate()
        self.assertEqual(report['status'], 'pass')
        self.assertTrue(report['passed'])
        self.assertEqual(self.row(report, 'loaded', 'rss_bytes')['candidate_median'], 40_000_000)
        self.assertEqual(report['amneziawg']['phases']['loaded']['rss_bytes'], over)
        self.assertEqual(report['amneziawg']['evidence']['drained_udp_connections'], 2)
        self.assertIs(report['amneziawg']['evidence']['udp_drain_verified'], True)
        self.assertEqual(report['amneziawg']['file'], 'amneziawg-1.json')
        self.assertEqual(report['failures'], [])

        self.clear()
        self.write_pair(
            uniform(40_000_000),
            candidate_phases=uniform(over),
            awg_phases=uniform(40_000_000),
        )
        report = self.evaluate()
        self.assertEqual(report['status'], 'regression')
        self.assertFalse(report['passed'])
        self.assertEqual(self.row(report, 'loaded', 'rss_bytes')['candidate_median'], over)
        self.assertEqual(report['amneziawg']['phases']['idle']['rss_bytes'], 40_000_000)

        self.clear()
        self.write_pair(uniform(40_000_000))
        (self.candidate / 'amneziawg-1.json').unlink()
        report = self.assert_malformed('amneziawg-1.json')
        self.assertIsNone(report['amneziawg'])

    def test_directory_io_failure_replaces_previous_passing_report(self):
        self.write_pair(uniform(20_000_000))
        original_iterdir = Path.iterdir
        for directory in (self.baseline, self.candidate):
            for error in (PermissionError(errno.EACCES, 'Permission denied'),
                          OSError(errno.EIO, 'Input/output error')):
                with self.subTest(directory=directory.name, error=type(error).__name__):
                    self.assertEqual(self.run_main()[0], 0)

                    def entries(path):
                        if path == directory:
                            raise error
                        return original_iterdir(path)

                    with mock.patch.object(Path, 'iterdir', entries):
                        code, stdout, stderr = self.run_main()
                    self.assertEqual(code, 2)
                    self.assertNotIn('memory comparison passed', stdout)
                    self.assertIn('cannot read directory', stderr)
                    report = json.loads(self.output.read_text(encoding='utf-8'))
                    self.assertEqual(report['status'], 'malformed')
                    self.assertFalse(report['passed'])
                    self.assertEqual(report['comparisons'], [])
                    self.assertTrue(any(item['file'] == str(directory) for item in report['errors']))

    def test_cli_exit_codes_write_report_without_false_success(self):
        """The real CLI returns 0, 1, or 2 and stores a complete report either way."""
        self.write_pair(uniform(20_000_000, anon=10_000_000))
        nested = self.root / 'nested' / 'report.json'
        code, stdout, stderr = self.run_main(nested)
        self.assertEqual(code, 0)
        self.assertIn('memory comparison passed', stdout)
        self.assertEqual(stderr, '')
        self.assertTrue(nested.is_file())
        self.assertTrue(nested.read_text(encoding='utf-8').endswith('\n'))
        self.assertTrue(json.loads(nested.read_text(encoding='utf-8'))['passed'])
        self.assertEqual(
            [path.name for path in nested.parent.iterdir() if path.name.startswith('.')],
            [],
        )

        passed = self.run_cli()
        self.assertEqual(passed.returncode, 0)
        self.assertIn('memory comparison passed', passed.stdout)
        self.assertEqual(json.loads(self.output.read_text(encoding='utf-8'))['status'], 'pass')

        self.clear()
        self.output.write_text('garbage', encoding='utf-8')
        self.write_pair(uniform(20_000_000, anon=10_000_000), uniform(80_000_000, anon=40_000_000))
        code, stdout, stderr = self.run_main()
        self.assertEqual(code, 1)
        self.assertNotIn('memory comparison passed', stdout)
        self.assertIn('exceeds limit', stderr)
        stored = self.output.read_text(encoding='utf-8')
        self.assertFalse(stored.startswith('garbage'))
        parsed = json.loads(stored)
        self.assertEqual(parsed['status'], 'regression')
        self.assertFalse(parsed['passed'])
        self.assertTrue(parsed['failures'])
        failed = self.run_cli()
        self.assertEqual(failed.returncode, 1)
        self.assertNotIn('memory comparison passed', failed.stdout)

        self.clear()
        self.write_pair(uniform(20_000_000, anon=10_000_000))
        (self.candidate / 'wireguard-2.json').unlink()
        code, stdout, stderr = self.run_main()
        self.assertEqual(code, 2)
        self.assertNotIn('memory comparison passed', stdout)
        self.assertIn('missing required run file', stderr)
        parsed = json.loads(self.output.read_text(encoding='utf-8'))
        self.assertEqual(parsed['status'], 'malformed')
        self.assertFalse(parsed['passed'])
        self.assertEqual(parsed['comparisons'], [])
        missing = self.run_cli()
        self.assertEqual(missing.returncode, 2)

        usage = self.run_cli([])
        self.assertEqual(usage.returncode, 2)
        self.assertTrue(usage.stderr)
        with contextlib.redirect_stderr(io.StringIO()) as error:
            with self.assertRaises(SystemExit) as caught:
                compare.main([])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn('--baseline', error.getvalue())

        self.clear()
        self.write_pair(uniform(20_000_000, anon=10_000_000))
        old_argv = sys.argv
        sys.argv = [
            str(SCRIPT), '--baseline', str(self.baseline),
            '--candidate', str(self.candidate), '--output', str(self.output),
        ]
        try:
            script_out, script_err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(script_out), contextlib.redirect_stderr(script_err):
                with self.assertRaises(SystemExit) as caught:
                    runpy.run_path(str(SCRIPT), run_name='__main__')
        finally:
            sys.argv = old_argv
        self.assertEqual(caught.exception.code, 0)
        self.assertIn('memory comparison passed', script_out.getvalue())

        self.clear()
        self.write_pair(uniform(20_000_000, anon=10_000_000))
        blocked = self.root / 'blocked-output'
        blocked.mkdir()
        code, stdout, stderr = self.run_main(blocked)
        self.assertEqual(code, 2)
        self.assertNotIn('memory comparison passed', stdout)
        self.assertIn('cannot write report', stderr)
        self.assertEqual(
            [path.name for path in self.root.iterdir() if path.name.startswith('.')],
            [],
        )

        self.clear()
        self.write_pair(uniform(20_000_000, anon=10_000_000), uniform(80_000_000, anon=40_000_000))
        code, stdout, stderr = self.run_main(blocked)
        self.assertEqual(code, 1)
        self.assertNotIn('memory comparison passed', stdout)
        self.assertIn('cannot write report', stderr)
        self.assertIn('exceeds limit', stderr)


if __name__ == '__main__':
    unittest.main()
