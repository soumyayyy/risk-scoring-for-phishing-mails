# 🧠 Confidence Scorer Module

The `confidence_scorer.py` module is the central decision-making engine for the main phishing detection system. It ingests threat data from multiple independent security scanners and calculates a final, normalized **Phishing Confidence Score**.

## 🎯 Module Objective
To provide a highly accurate, mathematically sound, and fault-tolerant final verdict on whether an email is a phishing attempt, rather than relying on a single point of failure.

## ✨ Core Logic & Features

* **Weighted Average Algorithm:** Applies predefined weights to different threat vectors based on severity. 
  * *Example:* A confirmed malicious URL (30% weight) impacts the final score much heavier than a slightly suspicious language pattern (10% weight).
* **Score Normalization:** Ensures the final confidence score always remains within strict mathematical bounds (`0.0` to `1.0`), regardless of extreme inputs.
* **Graceful Degradation:** Built for real-world resilience. If a sub-component (e.g., the ML Classifier) fails or times out, the module dynamically drops that component's weight and recalculates the score using only the successful checks. The system will *not* crash.
* **Detailed Verdict Reporting:** Does not just return "True" or "False". It returns a complete `ScoreResult` object containing the overall confidence, a categorized risk level (Low, Medium, High), and human-readable reasoning for the verdict.

## 🧮 The Weights Breakdown
By default, the algorithm prioritizes definitive technical indicators over heuristic text analysis:
* **Machine Learning Classifier:** `35%`
* **URL Analysis:** `30%`
* **Sensitive Request (NLP):** `15%`
* **Polite Request (NLP):** `10%`
* **Short Email Risk:** `10%`

*(Note: Custom weights can be passed dynamically into the function during runtime if required by specific deployments).*

## 💻 Usage Example

```python
from confidence_scorer import score_analysis_confidence

# 1. Gather results from your various scanners
scan_results = {
    'ml_classifier': {'classification': 'phishing', 'confidence': 0.85},
    'url_analysis': {'summary': {'total_urls': 2, 'suspicious_urls': 1, 'high_risk_urls': 0}},
    'sensitive_request': {'risk_level': 'high'},
    # If a scanner fails, it is handled gracefully:
    'polite_request': {'error': 'API Timeout'} 
}

# 2. Run the scoring engine
verdict = score_analysis_confidence(scan_results)

# 3. Utilize the results
print(f"Phishing Detected: {verdict.is_phishing}")
print(f"Confidence: {verdict.overall_confidence * 100:.1f}%")
print(f"Risk Level: {verdict.risk_level.upper()}")
print(f"Reasoning: {verdict.reasoning}")
