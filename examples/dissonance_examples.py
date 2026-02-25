# Dissonance Detector Examples

This file contains practical examples demonstrating the use of the DissonanceDetector class.

## Example 1: Basic Usage
```
from some_module import DissonanceDetector

detector = DissonanceDetector(threshold=0.5)
result = detector.detect(data)
print("Detection result:", result)
```

## Example 2: Advanced Configuration
```
from some_module import DissonanceDetector

detector = DissonanceDetector(threshold=0.7, method='advanced')
data = [1, 2, 3, 5, 8, 13, 21]
result = detector.detect(data)
print("Advanced detection result:", result)
```

## Example 3: Real-world Data
```
from some_module import DissonanceDetector
import pandas as pd

data = pd.read_csv('real_world_data.csv')
detector = DissonanceDetector(threshold=0.6)
result = detector.detect(data)
print("Real-world detection result:", result)
```

## Conclusion
These examples illustrate various ways to utilize the DissonanceDetector in practical scenarios.