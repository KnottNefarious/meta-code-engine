import ast

class SemanticAnalyzer:
    def __init__(self):
        self.issues = []
        self._scope_refs = []

    def _collect_refs(self, node):
        """Collect all names referenced (Load context) in node's subtree."""
        return {
            n.id for n in ast.walk(node)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
        }

    def visit(self, node):
        method_name = 'visit_' + node.__class__.__name__
        visitor = getattr(self, method_name, self.generic_visit)
        visitor(node)

    def generic_visit(self, node):
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def _enter_scope(self, node):
        self._scope_refs.append(self._collect_refs(node))
        self.generic_visit(node)
        self._scope_refs.pop()

    def visit_Module(self, node):
        self._enter_scope(node)

    def visit_FunctionDef(self, node):
        self._enter_scope(node)

    def visit_AsyncFunctionDef(self, node):
        self._enter_scope(node)

    def visit_ClassDef(self, node):
        self._enter_scope(node)

    def visit_Assign(self, node):
        # Logic to detect unused variables - only flag if never referenced in current scope
        current_refs = self._scope_refs[-1] if self._scope_refs else set()
        for target in node.targets:
            if isinstance(target, ast.Name):
                if target.id not in current_refs:
                    self.issues.append(f"Unused variable: {target.id} in assignment.")

    def visit_If(self, node):
        # Logic to detect unreachable code
        if isinstance(node.test, ast.Constant) and not node.test.value:
            self.issues.append("Unreachable code detected in if statement.")
        self.generic_visit(node)

    def check_consistency(self):
        return len(self.issues) == 0

class RealDissonanceDetector:
    def __init__(self, source_code):
        self.source_code = source_code
        self.analyzer = SemanticAnalyzer()
        self.issues = []

    def parse(self):
        self.tree = ast.parse(self.source_code)

    def analyze(self):
        self.analyzer.visit(self.tree)
        self.issues = self.analyzer.issues

    def check_consistency(self):
        return self.analyzer.check_consistency()

    def report(self):
        return "\n".join(self.issues)

    def get_issues(self):
        return self.issues

    def has_issues(self):
        return len(self.issues) > 0

class DissonanceDetector:
    def __init__(self, source_code):
        self.detector = RealDissonanceDetector(source_code)

    def parse(self):
        self.detector.parse()

    def analyze(self):
        self.detector.analyze()

    def check_consistency(self):
        return self.detector.check_consistency()

    def report(self):
        return self.detector.report()

    def get_issues(self):
        return self.detector.get_issues()

    def has_issues(self):
        return self.detector.has_issues()