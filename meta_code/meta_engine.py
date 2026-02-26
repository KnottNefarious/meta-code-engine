import ast

from meta_code.core import DissonanceReport, Program, SemanticSignature
from meta_code.dissonance import DissonanceDetector
from meta_code.compression import KolmogorovComplexity, PatternExtractor, ProgramCompressor
from meta_code.transposition import StructuralAnalyzer
from meta_code.resolution import ResolutionPredictor


class MetaCodeEngine:
    """
    Orchestrator for the full Meta-Code Engine analysis pipeline.

    Implements the Generating Function model:
      S = Σ aₙ  where  aₙ = f(n)
    Each stage aₙ feeds its output into the next stage.
    """

    def __init__(self):
        self._history = []  # stores issue lists across runs for convergence tracking

    def orchestrate(self, source_code, program_name='program', program_version='1.0'):
        """
        Run the full analysis pipeline on *source_code*.

        Returns a :class:`~meta_code.core.DissonanceReport` populated with:
          - dissonance issues
          - complexity metrics
          - structural analysis
          - resolution predictions
        """
        # --- Stage 0: Parse ---
        tree = ast.parse(source_code)
        program = Program(
            name=program_name,
            version=program_version,
            source_code=source_code,
            ast_tree=tree,
        )

        # --- Stage 1: Dissonance check ---
        detector = DissonanceDetector(source_code)
        detector.parse()
        detector.analyze()
        issues = detector.get_issues()

        # --- Stage 2: Pattern extraction ---
        extractor = PatternExtractor(source_code)
        patterns = extractor.extract_patterns()

        # --- Stage 3: Kolmogorov complexity ---
        kc = KolmogorovComplexity(source_code)
        complexity = kc.compute_complexity()
        complexity['patterns'] = patterns

        # --- Stage 4: Structural analysis ---
        analyzer = StructuralAnalyzer()
        structure = analyzer.analyze_structure(source_code)

        # --- Stage 5: Build SemanticSignature ---
        compressed_form = list(ProgramCompressor(source_code).compress())
        signature = SemanticSignature(
            signature_id=f"{program_name}-sig",
            description="Compressed structural signature",
            compressed_form=compressed_form,
            node_types=structure.get('node_type_distribution', {}),
        )
        program.add_signature(signature)

        # --- Stage 6: Resolution prediction ---
        self._history.append(issues)
        predictor = ResolutionPredictor(issues)
        # Feed historical issues into predictor so convergence is tracked
        for past_run in self._history[:-1]:
            predictor.add_historical_run(past_run)
        predictor.analyze()
        predictions = predictor.predict_resolution()

        # --- Assemble report ---
        report = DissonanceReport(
            report_id=f"{program_name}-report",
            program=program,
            issues=issues,
        )
        report.complexity_metrics = complexity
        report.structural_analysis = structure
        report.resolution_predictions = predictions
        return report

