"""
dissonance.py — Semantic quality analysis for Python source code.

Detects:
  • Unused variables
  • Unreachable code  (if False: ...)
  • Dead code after return
  • Empty bare except blocks
  • Tautological comparisons  (x == x)
  • Mutable default arguments  (def f(lst=[]): ...)
"""

import ast


class SemanticAnalyzer(ast.NodeVisitor):
    """
    Walks the AST to collect semantic code-quality issues.
    Call visit(tree) then finalize() to get the full issue list.
    """

    def __init__(self):
        self.issues      = []
        self._assigned   = {}    # name → assignment node
        self._used       = set() # names that appear in Load context

    # ------------------------------------------------------------------
    # Variable tracking
    # ------------------------------------------------------------------

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._assigned[target.id] = node
        self.generic_visit(node)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            self._used.add(node.id)

    # ------------------------------------------------------------------
    # For loop — the loop variable is considered "used"
    # ------------------------------------------------------------------

    def visit_For(self, node):
        if isinstance(node.target, ast.Name):
            self._used.add(node.target.id)
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Unreachable code — if False: ...
    # ------------------------------------------------------------------

    def visit_If(self, node):
        if isinstance(node.test, ast.Constant) and node.test.value is False:
            self.issues.append("Unreachable code detected in if statement.")
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Dead code after return
    # ------------------------------------------------------------------

    def visit_FunctionDef(self, node):
        self._check_dead_code_after_return(node.body)
        self.generic_visit(node)

    def _check_dead_code_after_return(self, stmts):
        for i, stmt in enumerate(stmts):
            if isinstance(stmt, ast.Return) and i < len(stmts) - 1:
                self.issues.append(
                    "Dead code after return statement — statements after this line will never execute."
                )
                break  # one report per function body

    # ------------------------------------------------------------------
    # Empty bare except
    # ------------------------------------------------------------------

    def visit_ExceptHandler(self, node):
        if node.type is None:                       # bare except:
            # body is a single Pass or empty
            is_empty = (
                len(node.body) == 1
                and isinstance(node.body[0], ast.Pass)
            )
            if is_empty:
                self.issues.append(
                    "Empty bare except block detected — errors are silently swallowed."
                )
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Tautological comparison  x == x
    # ------------------------------------------------------------------

    def visit_Compare(self, node):
        if (len(node.ops) == 1
                and isinstance(node.ops[0], ast.Eq)
                and isinstance(node.left, ast.Name)
                and len(node.comparators) == 1
                and isinstance(node.comparators[0], ast.Name)
                and node.left.id == node.comparators[0].id):
            self.issues.append(
                f"Tautological comparison: '{node.left.id} == {node.left.id}' is always True."
            )
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Mutable default argument  def f(lst=[]): ...
    # ------------------------------------------------------------------

    def visit_FunctionDef_defaults(self, node):   # called via generic_visit below
        pass

    def _check_mutable_defaults(self, node):
        _MUTABLE = (ast.List, ast.Dict, ast.Set)
        for default in node.args.defaults + node.args.kw_defaults:
            if default is not None and isinstance(default, _MUTABLE):
                self.issues.append(
                    f"Mutable default argument in function '{node.name}' — "
                    "use None and assign inside the function body instead."
                )

    def generic_visit(self, node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._check_mutable_defaults(node)
        super().generic_visit(node)

    # ------------------------------------------------------------------
    # Finalize — report unused variables
    # ------------------------------------------------------------------

    def finalize(self):
        for name, _ in self._assigned.items():
            if name not in self._used:
                self.issues.append(f"Unused variable: '{name}' is assigned but never read.")


# ---------------------------------------------------------------------------
# DissonanceDetector — public interface
# ---------------------------------------------------------------------------

class DissonanceDetector:
    """
    Public interface for semantic dissonance detection.

    Usage:
        d = DissonanceDetector(source_code)
        d.parse()
        d.analyze()
        print(d.report())
    """

    def __init__(self, source_code: str):
        self.source_code = source_code
        self._analyzer   = SemanticAnalyzer()
        self._parsed     = False

    def parse(self):
        try:
            self._tree  = ast.parse(self.source_code)
            self._parsed = True
        except SyntaxError as e:
            self._tree   = None
            self._parsed = False
            self._analyzer.issues.append(f"Syntax error — cannot parse: {e.msg}")

    def analyze(self):
        if not self._parsed or self._tree is None:
            return
        self._analyzer.visit(self._tree)
        self._analyzer.finalize()

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_issues(self):
        return list(self._analyzer.issues)

    def has_issues(self):
        return bool(self._analyzer.issues)

    def check_consistency(self):
        return not self._analyzer.issues

    def report(self):
        return "\n".join(self._analyzer.issues)
