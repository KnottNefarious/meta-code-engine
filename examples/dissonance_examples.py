"""
examples/dissonance_examples.py
================================
Working examples demonstrating every module in Meta-Code Engine.
Run:  python examples/dissonance_examples.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from meta_code.meta_engine   import MetaCodeEngine
from meta_code.dissonance    import DissonanceDetector
from meta_code.compression   import PatternExtractor, KolmogorovComplexity
from meta_code.resolution    import ResolutionPredictor
from meta_code.transposition import TranspositionFinder, StructuralAnalyzer
from meta_code.execution     import HarmonicExecutor, ExecutionMonitor


DIVIDER = "─" * 60


def section(title):
    print(f"\n{DIVIDER}")
    print(f"  {title}")
    print(DIVIDER)


# ---------------------------------------------------------------------------
# 1. SAST — Security Analysis
# ---------------------------------------------------------------------------

section("1. SAST — Security Vulnerability Detection")

VULNERABLE_CODE = """
from flask import request, redirect
import os, pickle, requests

def handle():
    cmd      = request.args.get('cmd')
    uid      = request.args.get('uid')
    url      = request.args.get('url')
    blob     = request.args.get('blob')
    path     = request.args.get('path')
    next_url = request.args.get('next')

    os.system(cmd)                # Command Injection
    cursor.execute(uid)           # SQL Injection
    requests.get(url)                  # SSRF
    pickle.loads(blob)            # Unsafe Deserialization
    open(path)                    # Path Traversal
    return redirect(next_url)     # Open Redirect
"""

engine = MetaCodeEngine()
report = engine.orchestrate(VULNERABLE_CODE)
print(f"Found {len(report.issues)} vulnerabilities:\n")
for issue in report.issues:
    print(issue)
    print()

# Clean code — should produce nothing
SAFE_CODE = "x = [i * i for i in range(10)]\nprint(sum(x))"
clean_report = engine.orchestrate(SAFE_CODE)
print(f"Safe code: {len(clean_report.issues)} vulnerabilities detected  ✔")


# ---------------------------------------------------------------------------
# 2. Dissonance Detection
# ---------------------------------------------------------------------------

section("2. Dissonance Detector — Code Quality Issues")

DISSONANT_CODE = """
def process(data, items=[]):          # mutable default arg
    unused_x = 99                     # unused variable
    if False:                         # unreachable code
        print("never")
    items.append(data)
    return items
    extra = "dead code"               # dead after return

x = 5
if x == x:                            # tautological comparison
    pass

try:
    result = int("bad")
except:                                # empty bare except
    pass
"""

detector = DissonanceDetector(DISSONANT_CODE)
detector.parse()
detector.analyze()
issues = detector.get_issues()
print(f"Issues found ({len(issues)}):\n")
for i, issue in enumerate(issues, 1):
    print(f"  {i}. {issue}")


# ---------------------------------------------------------------------------
# 3. Resolution Prediction
# ---------------------------------------------------------------------------

section("3. Resolution Predictor — Fix Suggestions")

predictor = ResolutionPredictor(issues)
predictor.analyze()

# Simulate a recurring issue by adding it to history
predictor.add_historical_run(issues[:2])

predictions = predictor.predict_resolution()
print(f"Predictions ({len(predictions)}):\n")
for p in predictions:
    conv = "  ← recurring issue ⚠" if p["convergence"] else ""
    print(f"  Issue:      {p['issue']}")
    print(f"  Fix:        {p['suggestion']}{conv}")
    print()


# ---------------------------------------------------------------------------
# 4. Pattern Extraction & Kolmogorov Complexity
# ---------------------------------------------------------------------------

section("4. Pattern Extraction & Complexity Analysis")

RICH_CODE = """
import os
import sys

class DataPipeline:
    def __init__(self, source):
        self.source = source
        self.results = []

    def run(self):
        try:
            for item in self.source:
                if item.get('active'):
                    for sub in item.get('children', []):
                        self.results.append(sub)
                else:
                    self.results.append(item)
        except KeyError as e:
            print(f"Key error: {e}")
        return self.results
"""

patterns   = PatternExtractor(RICH_CODE).extract_patterns()
complexity = KolmogorovComplexity(RICH_CODE).compute_complexity()

print("AST Patterns:")
for name, count in patterns.items():
    if count:
        bar = "█" * count
        print(f"  {name:25s} {bar} ({count})")

print(f"\nKolmogorov Complexity:")
print(f"  Raw AST size:      {complexity['raw_size']} bytes")
print(f"  Compressed size:   {complexity['compressed_size']} bytes")
print(f"  Complexity ratio:  {complexity['ratio']:.3f}  (closer to 1.0 = more complex)")


# ---------------------------------------------------------------------------
# 5. Structural Comparison (Transposition)
# ---------------------------------------------------------------------------

section("5. Structural Comparison — Two Programs")

PROG_A = """
def validate_email(email):
    if '@' in email and '.' in email:
        return True
    return False
"""

PROG_B = """
def validate_phone(phone):
    if len(phone) == 10 and phone.isdigit():
        return True
    return False
"""

tf      = TranspositionFinder()
sa      = StructuralAnalyzer()
result  = tf.find_transpositions(PROG_A, PROG_B)
struct_a = sa.analyze_structure(PROG_A)
struct_b = sa.analyze_structure(PROG_B)

print(f"Similarity Score: {result['similarity_score']:.1%}")
print(f"Shared node types ({len(result['shared_node_types'])}): {', '.join(result['shared_node_types'][:6])}…")
if result['only_in_program1']: print(f"Only in A: {', '.join(result['only_in_program1'])}")
if result['only_in_program2']: print(f"Only in B: {', '.join(result['only_in_program2'])}")
print(f"\nProgram A — depth: {struct_a['depth']}, nodes: {struct_a['total_nodes']}, branching: {struct_a['branching_factor']:.3f}")
print(f"Program B — depth: {struct_b['depth']}, nodes: {struct_b['total_nodes']}, branching: {struct_b['branching_factor']:.3f}")


# ---------------------------------------------------------------------------
# 6. Safe Execution
# ---------------------------------------------------------------------------

section("6. Harmonic Executor — Safe Sandboxed Execution")

SAFE_EXEC = """
nums   = [7, 2, 9, 4, 1, 8, 3]
evens  = [n for n in nums if n % 2 == 0]
odds   = [n for n in nums if n % 2 != 0]
print(f"Evens: {sorted(evens)}")
print(f"Odds:  {sorted(odds)}")
print(f"Total: {sum(nums)}")
"""

executor = HarmonicExecutor()
result   = executor.execute(SAFE_EXEC)
print("Result:", "✔ success" if result['success'] else "✘ failed")
print("Output:\n" + result['output'].strip())
print("Variables:", result['variables'])

# Blocked execution
print("\n--- Attempting blocked import ---")
blocked = executor.execute("import os; os.system('ls')")
print("Blocked:", not blocked['success'], "—", blocked['errors'])


# ---------------------------------------------------------------------------
# 7. Execution Monitor
# ---------------------------------------------------------------------------

section("7. Execution Monitor — Step-by-Step Trace")

TRACE_CODE = """
total = 0
for i in range(1, 6):
    total += i
result = total * 2
print(result)
"""

monitor = ExecutionMonitor()
trace   = monitor.monitor(TRACE_CODE)

print(f"Steps traced: {len(trace['steps'])}")
print(f"Output: {trace['output'].strip()}")
print("\nVariable evolution:")
for step in trace['steps']:
    if step.get('variables_after'):
        print(f"  {step['statement']:30s} → {step['variables_after']}")

print(f"\nFinal variables: {trace['final_variables']}")

print(f"\n{DIVIDER}")
print("  All examples complete ✔")
print(DIVIDER)
