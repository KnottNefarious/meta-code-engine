import ast
import zlib


class PatternExtractor:
    """Extract recurring structural patterns from source code using AST analysis."""

    def __init__(self, data):
        self.data = data
        self._tree = None

    def _parse(self):
        if self._tree is None:
            self._tree = ast.parse(self.data)

    def extract_patterns(self):
        """Return a dict mapping pattern names to their occurrence counts."""
        self._parse()
        patterns = {
            'loops': 0,
            'conditionals': 0,
            'function_defs': 0,
            'function_calls': 0,
            'variable_assignments': 0,
            'imports': 0,
            'class_defs': 0,
            'return_statements': 0,
            'try_except': 0,
        }
        for node in ast.walk(self._tree):
            if isinstance(node, (ast.For, ast.While)):
                patterns['loops'] += 1
            elif isinstance(node, ast.If):
                patterns['conditionals'] += 1
            elif isinstance(node, ast.FunctionDef):
                patterns['function_defs'] += 1
            elif isinstance(node, ast.Call):
                patterns['function_calls'] += 1
            elif isinstance(node, ast.Assign):
                patterns['variable_assignments'] += 1
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                patterns['imports'] += 1
            elif isinstance(node, ast.ClassDef):
                patterns['class_defs'] += 1
            elif isinstance(node, ast.Return):
                patterns['return_statements'] += 1
            elif isinstance(node, ast.Try):
                patterns['try_except'] += 1
        return patterns


class ProgramCompressor:
    """Compress a program's AST to its minimal structural representation."""

    def __init__(self, program):
        self.program = program
        self._tree = None

    def _parse(self):
        if self._tree is None:
            self._tree = ast.parse(self.program)

    def _structural_form(self, node):
        """Recursively produce a structure-only representation, stripping names/literals."""
        node_type = node.__class__.__name__
        children = [self._structural_form(child) for child in ast.iter_child_nodes(node)]
        if children:
            return (node_type, tuple(children))
        return (node_type,)

    def compress(self):
        """Return the structural (name/literal-free) representation of the program."""
        self._parse()
        return self._structural_form(self._tree)


class KolmogorovComplexity:
    """Estimate Kolmogorov complexity via compressed-size ratio of the AST."""

    def __init__(self, data):
        self.data = data

    def compute_complexity(self):
        """Return a complexity dict with raw_size, compressed_size, and ratio."""
        compressor = ProgramCompressor(self.data)
        structural = str(compressor.compress())
        raw_size = len(structural.encode('utf-8'))
        compressed_size = len(zlib.compress(structural.encode('utf-8'), level=9))
        ratio = compressed_size / raw_size if raw_size > 0 else 0.0
        return {
            'raw_size': raw_size,
            'compressed_size': compressed_size,
            'ratio': ratio,
        }

