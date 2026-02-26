import ast
from collections import Counter


class TranspositionFinder:
    """Compare two programs' AST structures to find shared patterns and divergences."""

    def __init__(self):
        pass

    def _node_type_sequence(self, source):
        tree = ast.parse(source)
        return [node.__class__.__name__ for node in ast.walk(tree)]

    def find_transpositions(self, program1, program2):
        """Return a dict describing structural similarities and differences."""
        seq1 = self._node_type_sequence(program1)
        seq2 = self._node_type_sequence(program2)
        set1 = set(seq1)
        set2 = set(seq2)
        shared = set1 & set2
        only_in_1 = set1 - set2
        only_in_2 = set2 - set1
        counts1 = Counter(seq1)
        counts2 = Counter(seq2)
        isomorphic_nodes = {
            n: (counts1[n], counts2[n])
            for n in shared
            if counts1[n] == counts2[n]
        }
        divergent_nodes = {
            n: (counts1.get(n, 0), counts2.get(n, 0))
            for n in (shared - set(isomorphic_nodes)) | only_in_1 | only_in_2
        }
        similarity = len(shared) / len(set1 | set2) if (set1 | set2) else 1.0
        return {
            'shared_node_types': sorted(shared),
            'only_in_program1': sorted(only_in_1),
            'only_in_program2': sorted(only_in_2),
            'isomorphic_nodes': isomorphic_nodes,
            'divergent_nodes': divergent_nodes,
            'similarity_score': similarity,
        }


class StructuralAnalyzer:
    """Analyze a single program's structural metrics."""

    def __init__(self):
        pass

    def _depth(self, node):
        children = list(ast.iter_child_nodes(node))
        if not children:
            return 1
        return 1 + max(self._depth(child) for child in children)

    def analyze_structure(self, program):
        """Return structural metrics for the given source code string."""
        tree = ast.parse(program)
        node_types = Counter(node.__class__.__name__ for node in ast.walk(tree))
        total_nodes = sum(node_types.values())
        branching_nodes = (
            node_types.get('If', 0)
            + node_types.get('For', 0)
            + node_types.get('While', 0)
            + node_types.get('Try', 0)
        )
        depth = self._depth(tree)
        branching_factor = branching_nodes / total_nodes if total_nodes > 0 else 0.0
        signature = tuple(sorted(node_types.items()))
        return {
            'depth': depth,
            'total_nodes': total_nodes,
            'branching_factor': branching_factor,
            'node_type_distribution': dict(node_types),
            'structural_signature': signature,
        }

