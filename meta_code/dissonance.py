class DissonanceDetector:
    def __init__(self, text1, text2):
        self.text1 = text1
        self.text2 = text2

    def check_consistency(self):
        # Implement a method to check semantic consistency between text1 and text2
        # This is a placeholder for actual implementation
        return self.text1.lower() == self.text2.lower()  # Example comparison

    def report(self):
        # Implement a method to report the findings
        if self.check_consistency():
            return "The texts are semantically consistent."
        else:
            return "The texts are semantically inconsistent."