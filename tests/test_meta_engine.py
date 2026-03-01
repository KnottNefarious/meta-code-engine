"""
Meta-Code Engine — Comprehensive Test Suite
============================================
Covers every module, every public method, every vulnerability type,
edge cases, sanitizer suppression, inter-procedural tracking,
sandbox escapes, and full integration paths.

Run:  python -m pytest tests/test_meta_engine.py -v
"""

import ast
import sys
import os
import unittest

# Make sure the project root is on the path regardless of how tests are run.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from meta_code.meta_engine  import MetaCodeEngine, SymbolicAnalyzer, SymbolicValue, Finding, AnalysisReport
from meta_code.dissonance    import DissonanceDetector, SemanticAnalyzer
from meta_code.compression   import PatternExtractor, ProgramCompressor, KolmogorovComplexity
from meta_code.resolution    import ResolutionPredictor
from meta_code.transposition import TranspositionFinder, StructuralAnalyzer
from meta_code.execution     import HarmonicExecutor, ExecutionMonitor
from meta_code.core          import (
    Program, SemanticSignature, DissonanceReport,
    ExecutionTrace, BehaviorType,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _analyze(code: str):
    """Run SymbolicAnalyzer and return list of Finding objects."""
    tree = ast.parse(code)
    analyzer = SymbolicAnalyzer()
    analyzer.analyze(tree)
    return analyzer.findings


def _vuln_types(code: str):
    """Return set of vulnerability type strings detected in code."""
    return {f.vuln_type for f in _analyze(code)}


def _orchestrate(code: str):
    """Run the full MetaCodeEngine and return list of issue strings."""
    engine = MetaCodeEngine()
    return engine.orchestrate(code).issues


def _dissonance(source: str):
    d = DissonanceDetector(source)
    d.parse()
    d.analyze()
    return d


# ---------------------------------------------------------------------------
# 1. SYMBOLIC ANALYZER — taint sources
# ---------------------------------------------------------------------------

class TestTaintSources(unittest.TestCase):

    def test_request_args_get_is_tainted(self):
        code = "user = request.args.get('id')\ncursor.execute(user)"
        self.assertIn("SQL Injection", _vuln_types(code))

    def test_request_form_is_tainted(self):
        code = "user = request.form.get('q')\ncursor.execute(user)"
        self.assertIn("SQL Injection", _vuln_types(code))

    def test_request_json_is_tainted(self):
        code = "user = request.json.get('cmd')\nos.system(user)"
        self.assertIn("Command Injection", _vuln_types(code))

    def test_request_headers_is_tainted(self):
        code = "h = request.headers.get('X-Id')\ncursor.execute(h)"
        self.assertIn("SQL Injection", _vuln_types(code))

    def test_request_cookies_is_tainted(self):
        code = "c = request.cookies.get('token')\ncursor.execute(c)"
        self.assertIn("SQL Injection", _vuln_types(code))

    def test_request_data_is_tainted(self):
        code = "d = request.data.get('blob')\ncursor.execute(d)"
        self.assertIn("SQL Injection", _vuln_types(code))

    def test_request_values_is_tainted(self):
        code = "v = request.values.get('key')\ncursor.execute(v)"
        self.assertIn("SQL Injection", _vuln_types(code))


# ---------------------------------------------------------------------------
# 2. SQL INJECTION
# ---------------------------------------------------------------------------

class TestSQLInjection(unittest.TestCase):

    def test_direct_execute(self):
        code = "q = request.args.get('q')\ncursor.execute(q)"
        self.assertIn("SQL Injection", _vuln_types(code))

    def test_executemany(self):
        code = "q = request.args.get('q')\ncursor.executemany(q, [])"
        self.assertIn("SQL Injection", _vuln_types(code))

    def test_via_concatenation(self):
        code = (
            "uid = request.args.get('id')\n"
            "sql = 'SELECT * FROM users WHERE id=' + uid\n"
            "cursor.execute(sql)"
        )
        self.assertIn("SQL Injection", _vuln_types(code))

    def test_severity_is_high(self):
        code = "uid = request.args.get('id')\ncursor.execute(uid)"
        findings = _analyze(code)
        sql = [f for f in findings if f.vuln_type == "SQL Injection"]
        self.assertTrue(sql)
        self.assertEqual(sql[0].severity, "HIGH")

    def test_exploitability(self):
        code = "uid = request.args.get('id')\ncursor.execute(uid)"
        findings = _analyze(code)
        sql = [f for f in findings if f.vuln_type == "SQL Injection"]
        self.assertEqual(sql[0].exploitability, "VERY LIKELY")

    def test_no_false_positive_constant(self):
        code = "cursor.execute('SELECT 1')"
        self.assertNotIn("SQL Injection", _vuln_types(code))

    def test_no_false_positive_parameterized(self):
        code = (
            "uid = request.args.get('id')\n"
            "cursor.execute('SELECT * FROM users WHERE id=?', (uid,))"
        )
        # The first arg is a constant — no taint in first arg
        self.assertNotIn("SQL Injection", _vuln_types(code))

    def test_lineno_present(self):
        code = "uid = request.args.get('id')\ncursor.execute(uid)"
        findings = _analyze(code)
        sql = [f for f in findings if f.vuln_type == "SQL Injection"]
        self.assertIsNotNone(sql[0].lineno)

    def test_attack_path_in_format(self):
        code = "uid = request.args.get('id')\ncursor.execute(uid)"
        findings = _analyze(code)
        sql = [f for f in findings if f.vuln_type == "SQL Injection"]
        formatted = sql[0].format()
        self.assertIn("Attack Path", formatted)


# ---------------------------------------------------------------------------
# 3. CROSS-SITE SCRIPTING (XSS)
# ---------------------------------------------------------------------------

class TestXSS(unittest.TestCase):

    def test_return_html_plus_tainted(self):
        code = (
            "name = request.args.get('name')\n"
            "return '<html>' + name"
        )
        self.assertIn("Cross-Site Scripting (XSS)", _vuln_types(code))

    def test_return_tainted_directly(self):
        code = (
            "name = request.args.get('name')\n"
            "return name"
        )
        self.assertIn("Cross-Site Scripting (XSS)", _vuln_types(code))

    def test_sanitizer_suppresses_xss(self):
        code = (
            "name = request.args.get('name')\n"
            "safe = escape(name)\n"
            "return safe"
        )
        self.assertNotIn("Cross-Site Scripting (XSS)", _vuln_types(code))

    def test_severity_is_high(self):
        code = "name = request.args.get('name')\nreturn '<h1>' + name"
        findings = _analyze(code)
        xss = [f for f in findings if f.vuln_type == "Cross-Site Scripting (XSS)"]
        self.assertTrue(xss)
        self.assertEqual(xss[0].severity, "HIGH")

    def test_no_false_positive_constant_return(self):
        code = "return '<html><body>Hello</body></html>'"
        self.assertNotIn("Cross-Site Scripting (XSS)", _vuln_types(code))

    def test_xss_dedup(self):
        """Same sink at same line should not produce duplicate findings."""
        code = "name = request.args.get('name')\nreturn name"
        findings = [f for f in _analyze(code) if f.vuln_type == "Cross-Site Scripting (XSS)"]
        self.assertEqual(len(findings), 1)


# ---------------------------------------------------------------------------
# 4. COMMAND INJECTION
# ---------------------------------------------------------------------------

class TestCommandInjection(unittest.TestCase):

    def test_os_system(self):
        code = "cmd = request.args.get('cmd')\nos.system(cmd)"
        self.assertIn("Command Injection", _vuln_types(code))

    def test_os_popen(self):
        code = "cmd = request.args.get('cmd')\nos.popen(cmd)"
        self.assertIn("Command Injection", _vuln_types(code))

    def test_subprocess_call_shell_true(self):
        code = "cmd = request.args.get('cmd')\nsubprocess.call(cmd, shell=True)"
        self.assertIn("Command Injection", _vuln_types(code))

    def test_subprocess_run_shell_true(self):
        code = "cmd = request.args.get('cmd')\nsubprocess.run(cmd, shell=True)"
        self.assertIn("Command Injection", _vuln_types(code))

    def test_subprocess_popen_shell_true(self):
        code = "cmd = request.args.get('cmd')\nsubprocess.Popen(cmd, shell=True)"
        self.assertIn("Command Injection", _vuln_types(code))

    def test_subprocess_without_shell_true_not_flagged(self):
        """subprocess.call(['ls', '-la']) without shell=True is safe."""
        code = "subprocess.call(['ls', '-la'])"
        self.assertNotIn("Command Injection", _vuln_types(code))

    def test_severity_is_critical(self):
        code = "cmd = request.args.get('cmd')\nos.system(cmd)"
        findings = _analyze(code)
        ci = [f for f in findings if f.vuln_type == "Command Injection"]
        self.assertTrue(ci)
        self.assertEqual(ci[0].severity, "CRITICAL")

    def test_exploitability_very_likely(self):
        code = "cmd = request.args.get('cmd')\nos.system(cmd)"
        findings = _analyze(code)
        ci = [f for f in findings if f.vuln_type == "Command Injection"]
        self.assertEqual(ci[0].exploitability, "VERY LIKELY")

    def test_check_call_shell_true(self):
        code = "cmd = request.args.get('cmd')\nsubprocess.check_call(cmd, shell=True)"
        self.assertIn("Command Injection", _vuln_types(code))

    def test_check_output_shell_true(self):
        code = "cmd = request.args.get('cmd')\nsubprocess.check_output(cmd, shell=True)"
        self.assertIn("Command Injection", _vuln_types(code))


# ---------------------------------------------------------------------------
# 5. PATH TRAVERSAL
# ---------------------------------------------------------------------------

class TestPathTraversal(unittest.TestCase):

    def test_open_with_tainted_path(self):
        code = "path = request.args.get('file')\nopen(path)"
        self.assertIn("Path Traversal", _vuln_types(code))

    def test_severity_is_medium(self):
        code = "path = request.args.get('file')\nopen(path)"
        findings = _analyze(code)
        pt = [f for f in findings if f.vuln_type == "Path Traversal"]
        self.assertTrue(pt)
        self.assertEqual(pt[0].severity, "MEDIUM")

    def test_no_false_positive_constant_path(self):
        code = "open('config.txt')"
        self.assertNotIn("Path Traversal", _vuln_types(code))

    def test_via_variable_chain(self):
        code = (
            "raw = request.args.get('f')\n"
            "path = raw\n"
            "open(path)"
        )
        self.assertIn("Path Traversal", _vuln_types(code))


# ---------------------------------------------------------------------------
# 6. UNSAFE DESERIALIZATION
# ---------------------------------------------------------------------------

class TestUnsafeDeserialization(unittest.TestCase):

    def test_pickle_loads(self):
        code = "data = request.args.get('blob')\npickle.loads(data)"
        self.assertIn("Unsafe Deserialization", _vuln_types(code))

    def test_pickle_load(self):
        code = "data = request.args.get('blob')\npickle.load(data)"
        self.assertIn("Unsafe Deserialization", _vuln_types(code))

    def test_yaml_load(self):
        code = "data = request.args.get('cfg')\nyaml.load(data)"
        self.assertIn("Unsafe Deserialization", _vuln_types(code))

    def test_marshal_loads(self):
        code = "data = request.args.get('blob')\nmarshal.loads(data)"
        self.assertIn("Unsafe Deserialization", _vuln_types(code))

    def test_severity_is_critical(self):
        code = "data = request.args.get('blob')\npickle.loads(data)"
        findings = _analyze(code)
        ud = [f for f in findings if f.vuln_type == "Unsafe Deserialization"]
        self.assertTrue(ud)
        self.assertEqual(ud[0].severity, "CRITICAL")

    def test_exploitability_very_likely(self):
        code = "data = request.args.get('blob')\npickle.loads(data)"
        findings = _analyze(code)
        ud = [f for f in findings if f.vuln_type == "Unsafe Deserialization"]
        self.assertEqual(ud[0].exploitability, "VERY LIKELY")

    def test_no_false_positive_constant(self):
        code = "pickle.loads(b'\\x80\\x03}q\\x00.')"
        self.assertNotIn("Unsafe Deserialization", _vuln_types(code))


# ---------------------------------------------------------------------------
# 7. SERVER-SIDE REQUEST FORGERY (SSRF)
# ---------------------------------------------------------------------------

class TestSSRF(unittest.TestCase):

    def test_requests_get(self):
        code = "url = request.args.get('url')\nrequests.get(url)"
        self.assertIn("Server-Side Request Forgery (SSRF)", _vuln_types(code))

    def test_requests_post(self):
        code = "url = request.args.get('url')\nrequests.post(url)"
        self.assertIn("Server-Side Request Forgery (SSRF)", _vuln_types(code))

    def test_requests_put(self):
        code = "url = request.args.get('url')\nrequests.put(url)"
        self.assertIn("Server-Side Request Forgery (SSRF)", _vuln_types(code))

    def test_requests_delete(self):
        code = "url = request.args.get('url')\nrequests.delete(url)"
        self.assertIn("Server-Side Request Forgery (SSRF)", _vuln_types(code))

    def test_requests_request(self):
        code = "url = request.args.get('url')\nrequests.request('GET', url)"
        self.assertIn("Server-Side Request Forgery (SSRF)", _vuln_types(code))

    def test_severity_is_high(self):
        code = "url = request.args.get('url')\nrequests.get(url)"
        findings = _analyze(code)
        ssrf = [f for f in findings if f.vuln_type == "Server-Side Request Forgery (SSRF)"]
        self.assertTrue(ssrf)
        self.assertEqual(ssrf[0].severity, "HIGH")

    def test_no_false_positive_constant_url(self):
        code = "requests.get('https://api.example.com/data')"
        self.assertNotIn("Server-Side Request Forgery (SSRF)", _vuln_types(code))


# ---------------------------------------------------------------------------
# 8. OPEN REDIRECT
# ---------------------------------------------------------------------------

class TestOpenRedirect(unittest.TestCase):

    def test_flask_redirect_tainted(self):
        code = "url = request.args.get('next')\nreturn redirect(url)"
        self.assertIn("Open Redirect", _vuln_types(code))

    def test_severity_is_medium(self):
        code = "url = request.args.get('next')\nreturn redirect(url)"
        findings = _analyze(code)
        redir = [f for f in findings if f.vuln_type == "Open Redirect"]
        self.assertTrue(redir)
        self.assertEqual(redir[0].severity, "MEDIUM")

    def test_no_false_positive_constant_redirect(self):
        code = "return redirect('/dashboard')"
        self.assertNotIn("Open Redirect", _vuln_types(code))


# ---------------------------------------------------------------------------
# 9. INSECURE DIRECT OBJECT REFERENCE (IDOR)
# ---------------------------------------------------------------------------

class TestIDOR(unittest.TestCase):

    def test_subscript_with_tainted_key(self):
        code = (
            "uid = request.args.get('user_id')\n"
            "doc = documents[uid]\n"
            "return doc"
        )
        self.assertIn("Insecure Direct Object Reference (IDOR)", _vuln_types(code))

    def test_severity_is_high(self):
        code = (
            "uid = request.args.get('user_id')\n"
            "doc = documents[uid]\n"
            "return doc"
        )
        findings = _analyze(code)
        idor = [f for f in findings if f.vuln_type == "Insecure Direct Object Reference (IDOR)"]
        self.assertTrue(idor)
        self.assertEqual(idor[0].severity, "HIGH")


# ---------------------------------------------------------------------------
# 10. INTER-PROCEDURAL TAINT TRACKING
# ---------------------------------------------------------------------------

class TestInterProcedural(unittest.TestCase):

    def test_taint_through_function_call(self):
        code = (
            "def run_query(q):\n"
            "    cursor.execute(q)\n"
            "\n"
            "user_input = request.args.get('q')\n"
            "run_query(user_input)\n"
        )
        self.assertIn("SQL Injection", _vuln_types(code))

    def test_clean_function_call_no_finding(self):
        code = (
            "def greet(name):\n"
            "    print('Hello ' + name)\n"
            "\n"
            "greet('Alice')\n"
        )
        self.assertEqual(_analyze(code), [])


# ---------------------------------------------------------------------------
# 11. DEDUPLICATION
# ---------------------------------------------------------------------------

class TestDeduplication(unittest.TestCase):

    def test_same_finding_not_duplicated(self):
        code = "uid = request.args.get('id')\ncursor.execute(uid)"
        findings = [f for f in _analyze(code) if f.vuln_type == "SQL Injection"]
        self.assertEqual(len(findings), 1)


# ---------------------------------------------------------------------------
# 12. CLEAN CODE / FALSE POSITIVES
# ---------------------------------------------------------------------------

class TestCleanCode(unittest.TestCase):

    def test_no_findings_for_safe_code(self):
        code = (
            "x = 10\n"
            "y = 20\n"
            "print(x + y)\n"
        )
        self.assertEqual(_analyze(code), [])

    def test_no_findings_for_constant_sql(self):
        code = "cursor.execute('SELECT COUNT(*) FROM users')"
        self.assertEqual(_analyze(code), [])

    def test_no_findings_for_constant_open(self):
        code = "with open('data.txt') as f: pass"
        self.assertEqual(_analyze(code), [])


# ---------------------------------------------------------------------------
# 13. METACODEENGINE ORCHESTRATOR
# ---------------------------------------------------------------------------

class TestMetaCodeEngine(unittest.TestCase):

    def setUp(self):
        self.engine = MetaCodeEngine()

    def test_orchestrate_sql_injection(self):
        code = "uid = request.args.get('id')\ncursor.execute(uid)"
        report = self.engine.orchestrate(code)
        self.assertTrue(any("SQL Injection" in issue for issue in report.issues))

    def test_orchestrate_command_injection(self):
        code = "cmd = request.args.get('cmd')\nos.system(cmd)"
        report = self.engine.orchestrate(code)
        self.assertTrue(any("Command Injection" in issue for issue in report.issues))

    def test_orchestrate_xss(self):
        code = "n = request.args.get('n')\nreturn '<div>' + n"
        report = self.engine.orchestrate(code)
        self.assertTrue(any("Cross-Site Scripting" in issue for issue in report.issues))

    def test_orchestrate_deserialization(self):
        code = "d = request.args.get('d')\npickle.loads(d)"
        report = self.engine.orchestrate(code)
        self.assertTrue(any("Deserialization" in issue for issue in report.issues))

    def test_orchestrate_ssrf(self):
        code = "url = request.args.get('url')\nrequests.get(url)"
        report = self.engine.orchestrate(code)
        self.assertTrue(any("SSRF" in issue for issue in report.issues))

    def test_orchestrate_path_traversal(self):
        code = "p = request.args.get('f')\nopen(p)"
        report = self.engine.orchestrate(code)
        self.assertTrue(any("Path Traversal" in issue for issue in report.issues))

    def test_orchestrate_open_redirect(self):
        code = "url = request.args.get('next')\nreturn redirect(url)"
        report = self.engine.orchestrate(code)
        self.assertTrue(any("Open Redirect" in issue for issue in report.issues))

    def test_orchestrate_clean_code(self):
        code = "x = 1\nprint(x)"
        report = self.engine.orchestrate(code)
        self.assertEqual(report.issues, [])

    def test_orchestrate_syntax_error(self):
        code = "def broken(:"
        report = self.engine.orchestrate(code)
        self.assertEqual(len(report.issues), 1)
        self.assertIn("Invalid Python", report.issues[0])

    def test_orchestrate_empty_string(self):
        report = self.engine.orchestrate("")
        self.assertEqual(report.issues, [])

    def test_orchestrate_returns_analysis_report(self):
        report = self.engine.orchestrate("x = 1")
        self.assertIsInstance(report, AnalysisReport)

    def test_orchestrate_multiple_vulns(self):
        code = (
            "p = request.args.get('p')\n"
            "open(p)\n"
            "cursor.execute(p)\n"
        )
        report = self.engine.orchestrate(code)
        self.assertGreaterEqual(len(report.issues), 2)

    def test_finding_format_contains_all_fields(self):
        code = "uid = request.args.get('id')\ncursor.execute(uid)"
        report = self.engine.orchestrate(code)
        issue = report.issues[0]
        for field in ["Severity", "Attack Path", "Sink", "Why", "Fix"]:
            self.assertIn(field, issue)


# ---------------------------------------------------------------------------
# 14. FINDING CLASS
# ---------------------------------------------------------------------------

class TestFinding(unittest.TestCase):

    def test_format_includes_location_when_lineno(self):
        f = Finding("SQL Injection", "HIGH", ["request", "get", "uid"],
                    "cursor.execute(query)", "reason", "fix", lineno=5)
        self.assertIn("line 5", f.format())

    def test_format_no_location_when_no_lineno(self):
        f = Finding("SQL Injection", "HIGH", ["request"],
                    "cursor.execute(query)", "reason", "fix")
        self.assertNotIn("Location", f.format())

    def test_exploitability_command_injection(self):
        f = Finding("Command Injection", "CRITICAL", [], "os.system", "r", "f")
        self.assertEqual(f.exploitability, "VERY LIKELY")

    def test_exploitability_xss(self):
        f = Finding("Cross-Site Scripting (XSS)", "HIGH", [], "HTTP response", "r", "f")
        self.assertEqual(f.exploitability, "LIKELY")

    def test_exploitability_path_traversal(self):
        f = Finding("Path Traversal", "MEDIUM", [], "open(path)", "r", "f")
        self.assertEqual(f.exploitability, "LIKELY")

    def test_exploitability_unknown(self):
        f = Finding("Weird New Vuln", "LOW", [], "sink", "r", "f")
        self.assertEqual(f.exploitability, "UNKNOWN")


# ---------------------------------------------------------------------------
# 15. SYMBOLIC VALUE
# ---------------------------------------------------------------------------

class TestSymbolicValue(unittest.TestCase):

    def test_default_tainted_false(self):
        sv = SymbolicValue("x")
        self.assertFalse(sv.tainted)

    def test_tainted_true(self):
        sv = SymbolicValue("x", tainted=True)
        self.assertTrue(sv.tainted)

    def test_add_extends_path(self):
        sv = SymbolicValue("x", tainted=True, path=["request"])
        sv.add("form")
        self.assertIn("form", sv.path)

    def test_merge_tainted_if_either_tainted(self):
        a = SymbolicValue("a", tainted=True, path=["request"])
        b = SymbolicValue("b", tainted=False, path=["literal"])
        merged = a.merge(b)
        self.assertTrue(merged.tainted)

    def test_merge_path_deduplication(self):
        a = SymbolicValue("a", tainted=True, path=["request", "get"])
        b = SymbolicValue("b", tainted=True, path=["request", "form"])
        merged = a.merge(b)
        # "request" should appear only once
        self.assertEqual(merged.path.count("request"), 1)


# ---------------------------------------------------------------------------
# 16. DISSONANCE DETECTOR
# ---------------------------------------------------------------------------

class TestDissonanceDetector(unittest.TestCase):

    def test_unused_variable_flagged(self):
        d = _dissonance("x = 10\ny = 20\nprint(y)")
        issues = d.get_issues()
        self.assertEqual(len(issues), 1)
        self.assertIn("x", issues[0])

    def test_used_variable_not_flagged(self):
        d = _dissonance("x = 10\nprint(x)")
        self.assertEqual(d.get_issues(), [])

    def test_unreachable_code_flagged(self):
        d = _dissonance("if False:\n    print('dead')")
        self.assertTrue(any("Unreachable" in i for i in d.get_issues()))

    def test_clean_code_no_issues(self):
        d = _dissonance("x = 1\nprint(x)")
        self.assertEqual(d.get_issues(), [])

    def test_multiple_unused_vars(self):
        d = _dissonance("a = 1\nb = 2\nc = 3\nprint(c)")
        issues = d.get_issues()
        names = " ".join(issues)
        self.assertIn("a", names)
        self.assertIn("b", names)

    def test_has_issues_true(self):
        d = _dissonance("x = 10")
        self.assertTrue(d.has_issues())

    def test_has_issues_false(self):
        d = _dissonance("x = 10\nprint(x)")
        self.assertFalse(d.has_issues())

    def test_report_is_string(self):
        d = _dissonance("x = 10")
        self.assertIsInstance(d.report(), str)

    def test_check_consistency_false_when_issues(self):
        d = _dissonance("x = 10")
        self.assertFalse(d.check_consistency())

    def test_check_consistency_true_when_clean(self):
        d = _dissonance("x = 10\nprint(x)")
        self.assertTrue(d.check_consistency())

    def test_dead_code_after_return(self):
        d = _dissonance("def f():\n    return 1\n    x = 2")
        self.assertTrue(d.has_issues())

    def test_empty_except_block(self):
        d = _dissonance("try:\n    pass\nexcept:\n    pass")
        # should flag empty bare except
        self.assertTrue(d.has_issues())

    def test_comparison_with_self(self):
        d = _dissonance("x = 1\nif x == x:\n    pass")
        self.assertTrue(d.has_issues())

    def test_mutable_default_arg(self):
        d = _dissonance("def f(lst=[]):\n    lst.append(1)")
        self.assertTrue(d.has_issues())

    def test_no_false_positive_loop_variable(self):
        """Loop variable used in loop body should not be flagged."""
        d = _dissonance("for i in range(10):\n    print(i)")
        unused = [i for i in d.get_issues() if "i" in i and "Unused" in i]
        self.assertEqual(unused, [])


# ---------------------------------------------------------------------------
# 17. SEMANTIC ANALYZER (internal)
# ---------------------------------------------------------------------------

class TestSemanticAnalyzer(unittest.TestCase):

    def test_empty_code_no_issues(self):
        tree = ast.parse("")
        sa = SemanticAnalyzer()
        sa.visit(tree)
        sa.finalize()
        self.assertEqual(sa.issues, [])

    def test_generic_visit_covers_nested(self):
        code = "def outer():\n    x = 1\n    def inner():\n        print(x)\n    inner()"
        tree = ast.parse(code)
        sa = SemanticAnalyzer()
        sa.visit(tree)
        sa.finalize()
        # x is used inside inner, should not be flagged
        unused_x = [i for i in sa.issues if "x" in i and "Unused" in i]
        self.assertEqual(unused_x, [])


# ---------------------------------------------------------------------------
# 18. PATTERN EXTRACTOR
# ---------------------------------------------------------------------------

class TestPatternExtractor(unittest.TestCase):

    MULTI_FEATURE = (
        "import os\n"
        "import sys\n"
        "\n"
        "class MyClass:\n"
        "    def method(self, x):\n"
        "        if x > 0:\n"
        "            for i in range(x):\n"
        "                print(i)\n"
        "        try:\n"
        "            return x\n"
        "        except Exception:\n"
        "            pass\n"
        "\n"
        "obj = MyClass()\n"
        "result = obj.method(5)\n"
    )

    def _extract(self, code):
        pe = PatternExtractor(code)
        return pe.extract_patterns()

    def test_imports_counted(self):
        p = self._extract(self.MULTI_FEATURE)
        self.assertEqual(p["imports"], 2)

    def test_class_defs_counted(self):
        p = self._extract(self.MULTI_FEATURE)
        self.assertEqual(p["class_defs"], 1)

    def test_function_defs_counted(self):
        p = self._extract(self.MULTI_FEATURE)
        self.assertGreaterEqual(p["function_defs"], 1)

    def test_conditionals_counted(self):
        p = self._extract(self.MULTI_FEATURE)
        self.assertGreaterEqual(p["conditionals"], 1)

    def test_loops_counted(self):
        p = self._extract(self.MULTI_FEATURE)
        self.assertGreaterEqual(p["loops"], 1)

    def test_try_except_counted(self):
        p = self._extract(self.MULTI_FEATURE)
        self.assertGreaterEqual(p["try_except"], 1)

    def test_return_statements_counted(self):
        p = self._extract(self.MULTI_FEATURE)
        self.assertGreaterEqual(p["return_statements"], 1)

    def test_function_calls_counted(self):
        p = self._extract(self.MULTI_FEATURE)
        self.assertGreater(p["function_calls"], 0)

    def test_variable_assignments_counted(self):
        p = self._extract(self.MULTI_FEATURE)
        self.assertGreater(p["variable_assignments"], 0)

    def test_empty_code_all_zeros(self):
        p = self._extract("")
        for v in p.values():
            self.assertEqual(v, 0)

    def test_while_loop_counted(self):
        p = self._extract("while True:\n    break")
        self.assertEqual(p["loops"], 1)

    def test_returns_dict_with_expected_keys(self):
        p = self._extract("x = 1")
        expected_keys = {
            "loops", "conditionals", "function_defs", "function_calls",
            "variable_assignments", "imports", "class_defs",
            "return_statements", "try_except",
        }
        self.assertEqual(set(p.keys()), expected_keys)


# ---------------------------------------------------------------------------
# 19. PROGRAM COMPRESSOR
# ---------------------------------------------------------------------------

class TestProgramCompressor(unittest.TestCase):

    def test_compress_returns_tuple(self):
        pc = ProgramCompressor("x = 1")
        result = pc.compress()
        self.assertIsInstance(result, tuple)

    def test_same_structure_same_compression(self):
        pc1 = ProgramCompressor("x = 1")
        pc2 = ProgramCompressor("y = 99999")
        # Both are Assign of a Name to a Constant — same structure
        self.assertEqual(pc1.compress(), pc2.compress())

    def test_different_structure_different_compression(self):
        pc1 = ProgramCompressor("x = 1")
        pc2 = ProgramCompressor("def f(): return 1")
        self.assertNotEqual(pc1.compress(), pc2.compress())

    def test_compress_strips_variable_names(self):
        pc1 = ProgramCompressor("alpha = 1")
        pc2 = ProgramCompressor("zeta = 1")
        self.assertEqual(pc1.compress(), pc2.compress())

    def test_compress_strips_literals(self):
        pc1 = ProgramCompressor("x = 'hello'")
        pc2 = ProgramCompressor("x = 'world'")
        self.assertEqual(pc1.compress(), pc2.compress())

    def test_compress_empty_module(self):
        pc = ProgramCompressor("")
        result = pc.compress()
        self.assertIsNotNone(result)


# ---------------------------------------------------------------------------
# 20. KOLMOGOROV COMPLEXITY
# ---------------------------------------------------------------------------

class TestKolmogorovComplexity(unittest.TestCase):

    def test_returns_required_keys(self):
        kc = KolmogorovComplexity("x = 1")
        result = kc.compute_complexity()
        self.assertIn("raw_size", result)
        self.assertIn("compressed_size", result)
        self.assertIn("ratio", result)

    def test_ratio_between_zero_and_one(self):
        code = "for i in range(100):\n    print(i * i * i)\n"
        kc = KolmogorovComplexity(code)
        result = kc.compute_complexity()
        self.assertGreaterEqual(result["ratio"], 0.0)
        self.assertLessEqual(result["ratio"], 1.0)

    def test_raw_size_positive(self):
        kc = KolmogorovComplexity("x = 1\nprint(x)")
        result = kc.compute_complexity()
        self.assertGreater(result["raw_size"], 0)

    def test_more_complex_code_higher_raw_size(self):
        simple = KolmogorovComplexity("x = 1")
        complex_ = KolmogorovComplexity(
            "for i in range(100):\n"
            "    for j in range(100):\n"
            "        if i % 2 == 0:\n"
            "            print(i * j)\n"
        )
        self.assertGreater(
            complex_.compute_complexity()["raw_size"],
            simple.compute_complexity()["raw_size"],
        )

    def test_empty_code_handled(self):
        kc = KolmogorovComplexity("")
        result = kc.compute_complexity()
        # ratio may be 0 for empty / tiny input — just must not crash
        self.assertIsNotNone(result)


# ---------------------------------------------------------------------------
# 21. RESOLUTION PREDICTOR
# ---------------------------------------------------------------------------

class TestResolutionPredictor(unittest.TestCase):

    def test_analyze_returns_counter(self):
        from collections import Counter
        rp = ResolutionPredictor(["Unused variable: x in assignment."])
        result = rp.analyze()
        self.assertIsInstance(result, Counter)

    def test_analyze_counts_unused_variable(self):
        rp = ResolutionPredictor(["Unused variable: x in assignment."])
        counts = rp.analyze()
        self.assertGreater(counts["unused variable"], 0)

    def test_analyze_counts_unreachable_code(self):
        rp = ResolutionPredictor(["Unreachable code detected in if statement."])
        counts = rp.analyze()
        self.assertGreater(counts["unreachable code"], 0)

    def test_predict_resolution_empty_issues(self):
        rp = ResolutionPredictor([])
        rp.analyze()
        self.assertEqual(rp.predict_resolution(), [])

    def test_predict_resolution_unused_variable_suggestion(self):
        rp = ResolutionPredictor(["Unused variable: x in assignment."])
        rp.analyze()
        preds = rp.predict_resolution()
        self.assertEqual(len(preds), 1)
        self.assertIn("Remove or use", preds[0]["suggestion"])

    def test_predict_resolution_unreachable_suggestion(self):
        rp = ResolutionPredictor(["Unreachable code detected in if statement."])
        rp.analyze()
        preds = rp.predict_resolution()
        self.assertIn("Remove the unreachable", preds[0]["suggestion"])

    def test_predict_resolution_unknown_issue_generic_suggestion(self):
        rp = ResolutionPredictor(["Something totally unknown went wrong."])
        rp.analyze()
        preds = rp.predict_resolution()
        self.assertIn("Review and address", preds[0]["suggestion"])

    def test_convergence_true_on_recurring_issue(self):
        issue = "Unused variable: x in assignment."
        rp = ResolutionPredictor([issue])
        rp.add_historical_run([issue])
        rp.analyze()
        preds = rp.predict_resolution()
        self.assertTrue(preds[0]["convergence"])

    def test_convergence_false_on_first_run(self):
        issue = "Unused variable: y in assignment."
        rp = ResolutionPredictor([issue])
        rp.analyze()
        preds = rp.predict_resolution()
        self.assertFalse(preds[0]["convergence"])

    def test_multiple_issues_multiple_predictions(self):
        issues = [
            "Unused variable: a in assignment.",
            "Unreachable code detected in if statement.",
        ]
        rp = ResolutionPredictor(issues)
        rp.analyze()
        preds = rp.predict_resolution()
        self.assertEqual(len(preds), 2)

    def test_prediction_contains_issue_key(self):
        issue = "Unused variable: z in assignment."
        rp = ResolutionPredictor([issue])
        rp.analyze()
        pred = rp.predict_resolution()[0]
        self.assertEqual(pred["issue"], issue)


# ---------------------------------------------------------------------------
# 22. TRANSPOSITION FINDER
# ---------------------------------------------------------------------------

class TestTranspositionFinder(unittest.TestCase):

    PROG1 = "x = 1\nprint(x)"
    PROG2 = "y = 2\nprint(y)"
    PROG3 = "def f():\n    return [i for i in range(10)]"

    def test_identical_programs_similarity_one(self):
        tf = TranspositionFinder()
        result = tf.find_transpositions(self.PROG1, self.PROG1)
        self.assertAlmostEqual(result["similarity_score"], 1.0)

    def test_similar_programs_high_similarity(self):
        tf = TranspositionFinder()
        result = tf.find_transpositions(self.PROG1, self.PROG2)
        self.assertGreater(result["similarity_score"], 0.7)

    def test_different_programs_lower_similarity(self):
        tf = TranspositionFinder()
        result = tf.find_transpositions(self.PROG1, self.PROG3)
        # PROG3 has unique constructs
        self.assertLess(result["similarity_score"], 1.0)

    def test_shared_node_types_is_list(self):
        tf = TranspositionFinder()
        result = tf.find_transpositions(self.PROG1, self.PROG2)
        self.assertIsInstance(result["shared_node_types"], list)

    def test_only_in_program1_not_in_program2(self):
        tf = TranspositionFinder()
        result = tf.find_transpositions(self.PROG1, self.PROG3)
        # PROG3 has FunctionDef, ListComp etc. not in PROG1
        self.assertIsInstance(result["only_in_program2"], list)

    def test_isomorphic_nodes_same_count(self):
        tf = TranspositionFinder()
        result = tf.find_transpositions(self.PROG1, self.PROG2)
        for node, (c1, c2) in result["isomorphic_nodes"].items():
            self.assertEqual(c1, c2)

    def test_divergent_nodes_different_counts(self):
        tf = TranspositionFinder()
        result = tf.find_transpositions(self.PROG1, self.PROG3)
        for node, (c1, c2) in result["divergent_nodes"].items():
            self.assertNotEqual(c1, c2)

    def test_result_contains_all_keys(self):
        tf = TranspositionFinder()
        result = tf.find_transpositions(self.PROG1, self.PROG2)
        for key in ["shared_node_types", "only_in_program1", "only_in_program2",
                    "isomorphic_nodes", "divergent_nodes", "similarity_score"]:
            self.assertIn(key, result)


# ---------------------------------------------------------------------------
# 23. STRUCTURAL ANALYZER
# ---------------------------------------------------------------------------

class TestStructuralAnalyzer(unittest.TestCase):

    def test_depth_simple_assignment(self):
        sa = StructuralAnalyzer()
        result = sa.analyze_structure("x = 1")
        self.assertGreaterEqual(result["depth"], 1)

    def test_total_nodes_positive(self):
        sa = StructuralAnalyzer()
        result = sa.analyze_structure("x = 1")
        self.assertGreater(result["total_nodes"], 0)

    def test_branching_factor_zero_no_branches(self):
        sa = StructuralAnalyzer()
        result = sa.analyze_structure("x = 1\nprint(x)")
        self.assertEqual(result["branching_factor"], 0.0)

    def test_branching_factor_positive_with_branches(self):
        sa = StructuralAnalyzer()
        result = sa.analyze_structure("if True:\n    pass\nfor i in range(10):\n    pass")
        self.assertGreater(result["branching_factor"], 0.0)

    def test_node_type_distribution_is_dict(self):
        sa = StructuralAnalyzer()
        result = sa.analyze_structure("x = 1")
        self.assertIsInstance(result["node_type_distribution"], dict)

    def test_structural_signature_is_tuple(self):
        sa = StructuralAnalyzer()
        result = sa.analyze_structure("x = 1")
        self.assertIsInstance(result["structural_signature"], tuple)

    def test_complex_code_greater_depth(self):
        sa = StructuralAnalyzer()
        simple = sa.analyze_structure("x = 1")
        nested = sa.analyze_structure(
            "def f():\n    for i in range(10):\n        if i > 5:\n            print(i)"
        )
        self.assertGreater(nested["depth"], simple["depth"])


# ---------------------------------------------------------------------------
# 24. HARMONIC EXECUTOR
# ---------------------------------------------------------------------------

class TestHarmonicExecutor(unittest.TestCase):

    def setUp(self):
        self.exe = HarmonicExecutor()

    def test_execute_simple_print(self):
        result = self.exe.execute("print('hello world')")
        self.assertTrue(result["success"])
        self.assertEqual(result["output"].strip(), "hello world")

    def test_execute_arithmetic(self):
        result = self.exe.execute("x = 2 + 3\nprint(x)")
        self.assertTrue(result["success"])
        self.assertIn("5", result["output"])

    def test_execute_variables_returned(self):
        result = self.exe.execute("answer = 42")
        self.assertTrue(result["success"])
        self.assertIn("answer", result["variables"])

    def test_execute_output_captured(self):
        result = self.exe.execute("print('line1')\nprint('line2')")
        self.assertIn("line1", result["output"])
        self.assertIn("line2", result["output"])

    def test_reject_import(self):
        result = self.exe.execute("import os")
        self.assertFalse(result["success"])
        self.assertTrue(len(result["errors"]) > 0)

    def test_reject_import_from(self):
        result = self.exe.execute("from os import system")
        self.assertFalse(result["success"])

    def test_reject_exec_call(self):
        result = self.exe.execute("exec('import os')")
        self.assertFalse(result["success"])

    def test_reject_eval_call(self):
        result = self.exe.execute("eval('1+1')")
        self.assertFalse(result["success"])

    def test_reject_open_call(self):
        result = self.exe.execute("open('/etc/passwd')")
        self.assertFalse(result["success"])

    def test_reject_global(self):
        result = self.exe.execute("def f():\n    global x\nx = 1\nf()")
        self.assertFalse(result["success"])

    def test_runtime_error_captured(self):
        result = self.exe.execute("x = 1 / 0")
        self.assertFalse(result["success"])
        self.assertTrue(len(result["errors"]) > 0)

    def test_success_false_on_name_error(self):
        result = self.exe.execute("print(undefined_variable)")
        self.assertFalse(result["success"])

    def test_builtin_functions_available(self):
        result = self.exe.execute("print(len([1, 2, 3]))")
        self.assertTrue(result["success"])
        self.assertIn("3", result["output"])

    def test_list_comprehension_works(self):
        result = self.exe.execute("x = [i*i for i in range(5)]\nprint(x)")
        self.assertTrue(result["success"])

    def test_empty_code_succeeds(self):
        result = self.exe.execute("")
        self.assertTrue(result["success"])

    def test_result_has_required_keys(self):
        result = self.exe.execute("x = 1")
        for key in ["success", "output", "errors", "variables"]:
            self.assertIn(key, result)


# ---------------------------------------------------------------------------
# 25. EXECUTION MONITOR
# ---------------------------------------------------------------------------

class TestExecutionMonitor(unittest.TestCase):

    def setUp(self):
        self.mon = ExecutionMonitor()

    def test_monitor_traces_steps(self):
        trace = self.mon.monitor("x = 1\ny = 2\nprint(x + y)")
        self.assertEqual(len(trace["steps"]), 3)

    def test_monitor_step_has_statement(self):
        trace = self.mon.monitor("x = 42")
        self.assertIn("statement", trace["steps"][0])

    def test_monitor_step_has_node_type(self):
        trace = self.mon.monitor("x = 42")
        self.assertIn("node_type", trace["steps"][0])

    def test_monitor_captures_output(self):
        trace = self.mon.monitor("print('traced!')")
        self.assertIn("traced!", trace["output"])

    def test_monitor_final_variables(self):
        trace = self.mon.monitor("x = 7\ny = x * 6")
        self.assertIn("x", trace["final_variables"])
        self.assertIn("y", trace["final_variables"])

    def test_monitor_step_tracks_variables_after(self):
        trace = self.mon.monitor("x = 100")
        self.assertIn("variables_after", trace["steps"][0])
        self.assertIn("x", trace["steps"][0]["variables_after"])

    def test_monitor_handles_step_error(self):
        trace = self.mon.monitor("x = 1\ny = 1/0\nz = 3")
        errors = [s for s in trace["steps"] if s.get("error")]
        self.assertEqual(len(errors), 1)

    def test_monitor_rejects_forbidden_constructs(self):
        trace = self.mon.monitor("import os")
        self.assertTrue(len(trace["errors"]) > 0)

    def test_result_has_required_keys(self):
        trace = self.mon.monitor("x = 1")
        for key in ["steps", "output", "errors", "final_variables"]:
            self.assertIn(key, trace)


# ---------------------------------------------------------------------------
# 26. CORE DATA MODELS
# ---------------------------------------------------------------------------

class TestCoreModels(unittest.TestCase):

    def test_program_creation(self):
        p = Program("test_app", "1.0", source_code="x = 1")
        self.assertEqual(p.name, "test_app")
        self.assertEqual(p.version, "1.0")

    def test_program_add_signature(self):
        p = Program("app", "1.0")
        sig = SemanticSignature("sig_1", "test signature")
        p.add_signature(sig)
        self.assertEqual(len(p.signatures), 1)

    def test_semantic_signature_compressed_form_default_empty(self):
        sig = SemanticSignature("sig_1", "desc")
        self.assertEqual(sig.compressed_form, [])

    def test_semantic_signature_node_types_default_empty(self):
        sig = SemanticSignature("sig_1", "desc")
        self.assertEqual(sig.node_types, {})

    def test_dissonance_report_add_issue(self):
        p = Program("app", "1.0")
        dr = DissonanceReport("rep_1", p, [])
        dr.add_issue("unused variable: x")
        self.assertEqual(len(dr.issues), 1)

    def test_dissonance_report_complexity_metrics_default_empty(self):
        p = Program("app", "1.0")
        dr = DissonanceReport("rep_1", p, [])
        self.assertEqual(dr.complexity_metrics, {})

    def test_execution_trace_add_step(self):
        p = Program("app", "1.0")
        et = ExecutionTrace("trace_1", p)
        et.add_step({"stmt": "x = 1", "vars": {"x": 1}})
        self.assertEqual(len(et.steps), 1)

    def test_execution_trace_output_default_empty(self):
        p = Program("app", "1.0")
        et = ExecutionTrace("trace_1", p)
        self.assertEqual(et.output, "")

    def test_behavior_type_creation(self):
        bt = BehaviorType("bt_1", "Idempotent")
        self.assertEqual(bt.behavior_id, "bt_1")
        self.assertEqual(bt.description, "Idempotent")


# ---------------------------------------------------------------------------
# 27. INTEGRATION TESTS
# ---------------------------------------------------------------------------

class TestIntegration(unittest.TestCase):
    """End-to-end flows combining multiple modules."""

    def test_dissonance_then_resolution(self):
        """Detect issues with DissonanceDetector then predict resolutions."""
        code = "x = 10\ny = 20\nprint(y)\nif False:\n    print('dead')"
        d = _dissonance(code)
        issues = d.get_issues()
        self.assertTrue(issues)

        rp = ResolutionPredictor(issues)
        rp.analyze()
        preds = rp.predict_resolution()
        self.assertEqual(len(preds), len(issues))
        for pred in preds:
            self.assertIn("suggestion", pred)

    def test_compression_and_transposition_pipeline(self):
        """Compress two programs and then compare them structurally."""
        prog1 = "x = 1\nprint(x)"
        prog2 = "y = 99\nprint(y)"

        kc1 = KolmogorovComplexity(prog1).compute_complexity()
        kc2 = KolmogorovComplexity(prog2).compute_complexity()
        self.assertEqual(kc1["raw_size"], kc2["raw_size"])  # same structure

        tf = TranspositionFinder()
        result = tf.find_transpositions(prog1, prog2)
        self.assertAlmostEqual(result["similarity_score"], 1.0)

    def test_full_security_pipeline(self):
        """Full SAST pipeline with multiple vulnerability types."""
        code = (
            "cmd  = request.args.get('cmd')\n"
            "uid  = request.args.get('uid')\n"
            "url  = request.args.get('url')\n"
            "blob = request.args.get('blob')\n"
            "path = request.args.get('path')\n"
            "next_url = request.args.get('next')\n"
            "os.system(cmd)\n"
            "cursor.execute(uid)\n"
            "requests.get(url)\n"
            "pickle.loads(blob)\n"
            "open(path)\n"
            "return redirect(next_url)\n"
        )
        engine = MetaCodeEngine()
        report = engine.orchestrate(code)
        vuln_text = "\n".join(report.issues)

        self.assertIn("Command Injection", vuln_text)
        self.assertIn("SQL Injection", vuln_text)
        self.assertIn("SSRF", vuln_text)
        self.assertIn("Deserialization", vuln_text)
        self.assertIn("Path Traversal", vuln_text)
        self.assertIn("Open Redirect", vuln_text)

    def test_execution_then_monitor_consistency(self):
        """Same code should give consistent output via executor and monitor."""
        code = "total = sum(range(10))\nprint(total)"
        exe_result = HarmonicExecutor().execute(code)
        mon_result = ExecutionMonitor().monitor(code)
        self.assertEqual(exe_result["output"].strip(), mon_result["output"].strip())

    def test_pattern_extraction_on_vulnerable_code(self):
        """Pattern extractor should work on any valid Python, including vuln code."""
        code = (
            "def handle_request():\n"
            "    uid = request.args.get('id')\n"
            "    cursor.execute(uid)\n"
            "    return uid\n"
        )
        pe = PatternExtractor(code)
        patterns = pe.extract_patterns()
        self.assertEqual(patterns["function_defs"], 1)
        self.assertEqual(patterns["return_statements"], 1)

    def test_structural_analysis_on_clean_vs_complex(self):
        """More complex program should have higher branching factor."""
        simple = StructuralAnalyzer().analyze_structure("x = 1")
        complex_ = StructuralAnalyzer().analyze_structure(
            "if True:\n    for i in range(10):\n        try:\n            pass\n        except: pass"
        )
        self.assertGreater(complex_["branching_factor"], simple["branching_factor"])


# ---------------------------------------------------------------------------
# 28. EDGE CASES & ROBUSTNESS
# ---------------------------------------------------------------------------

class TestEdgeCases(unittest.TestCase):

    def test_engine_handles_empty_input(self):
        engine = MetaCodeEngine()
        report = engine.orchestrate("")
        self.assertIsInstance(report, AnalysisReport)

    def test_engine_handles_whitespace_only(self):
        engine = MetaCodeEngine()
        report = engine.orchestrate("   \n\n   ")
        self.assertIsInstance(report, AnalysisReport)

    def test_engine_handles_unicode_code(self):
        engine = MetaCodeEngine()
        report = engine.orchestrate("x = '日本語テスト'")
        self.assertIsInstance(report, AnalysisReport)

    def test_engine_handles_deeply_nested(self):
        code = "def a():\n    def b():\n        def c():\n            return request.args.get('x')\n        return c()\n    return b()\na()"
        engine = MetaCodeEngine()
        report = engine.orchestrate(code)
        self.assertIsInstance(report, AnalysisReport)

    def test_dissonance_handles_empty_string(self):
        d = _dissonance("")
        self.assertEqual(d.get_issues(), [])

    def test_resolution_predictor_none_data_handled(self):
        rp = ResolutionPredictor(None)
        rp.analyze()
        self.assertEqual(rp.predict_resolution(), [])

    def test_executor_large_output(self):
        code = "for i in range(100):\n    print(i)"
        result = HarmonicExecutor().execute(code)
        self.assertTrue(result["success"])
        self.assertGreater(len(result["output"]), 0)

    def test_kolmogorov_single_line(self):
        kc = KolmogorovComplexity("pass")
        result = kc.compute_complexity()
        self.assertGreater(result["raw_size"], 0)

    def test_transposition_empty_programs(self):
        tf = TranspositionFinder()
        result = tf.find_transpositions("pass", "pass")
        self.assertAlmostEqual(result["similarity_score"], 1.0)

    def test_pattern_extractor_only_functions(self):
        code = "def f(): pass\ndef g(): pass\ndef h(): pass"
        pe = PatternExtractor(code)
        patterns = pe.extract_patterns()
        self.assertEqual(patterns["function_defs"], 3)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
