from collections import Counter


# Maps issue-type keywords to suggested fix messages.
_RESOLUTION_PATTERNS = {
    'unused variable': 'Remove or use the unused variable.',
    'unreachable code': 'Remove the unreachable code block or fix the condition.',
    'syntax error': 'Review and correct the syntax near the reported location.',
    'name error': 'Ensure the variable or function is defined before use.',
    'type error': 'Check that operands or arguments have compatible types.',
    'import error': 'Verify the module name and that it is installed.',
    'attribute error': 'Confirm the object has the referenced attribute.',
    'index error': 'Guard array accesses with bounds checks.',
    'key error': 'Use .get() or check key existence before accessing the dict.',
    'zero division': 'Add a check to avoid division by zero.',
}


class ResolutionPredictor:
    """
    Predict likely resolutions for detected issues and track convergence.

    Modelled on asymptotic convergence: if the same issues recur, the
    predictor converges on stable resolution recommendations.
    """

    def __init__(self, data):
        # data: a list of issue strings (e.g. from DissonanceDetector.get_issues())
        self.data = data if data is not None else []
        self._history = []

    def add_historical_run(self, issues):
        """Record a previous issue list for convergence tracking."""
        self._history.append(list(issues))

    def analyze(self):
        """Count how often each issue type appears in the current issue list."""
        self._history.append(list(self.data))
        return Counter(
            key
            for issue in self.data
            for key in _RESOLUTION_PATTERNS
            if key in issue.lower()
        )

    def predict_resolution(self):
        """
        Return a list of resolution suggestions for the current issues.

        Each entry is a dict with 'issue', 'suggestion', and 'convergence'
        (True if this issue type appeared in previous analysis runs too).
        """
        previous_issues = set(
            issue
            for run in self._history[:-1]
            for issue in run
        ) if len(self._history) > 1 else set()

        predictions = []
        for issue in self.data:
            suggestion = 'Review and address the flagged issue.'
            for key, fix in _RESOLUTION_PATTERNS.items():
                if key in issue.lower():
                    suggestion = fix
                    break
            predictions.append({
                'issue': issue,
                'suggestion': suggestion,
                'convergence': issue in previous_issues,
            })
        return predictions

