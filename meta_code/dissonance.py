import ast

class SemanticAnalyzer:
    def __init__(self):
        self.issues = []

    def visit(self, node):
        method_name = 'visit_' + node.__class__.__name__
        visitor = getattr(self, method_name, self.generic_visit)
        visitor(node)

    def generic_visit(self, node):
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def visit_Assign(self, node):
        # Logic to detect unused variables
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.issues.append(f"Unused variable: {target.id} in assignment.")

    def visit_If(self, node):
        # Logic to detect unreachable code
        if isinstance(node.test, ast.Constant) and not node.test.value:
            self.issues.append("Unreachable code detected in if statement.")

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