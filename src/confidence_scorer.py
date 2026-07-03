#!/usr/bin/env python3
"""
MailSentinel - Confidence Scorer Module
Calculates a normalized, weighted average risk score from multiple security components.
"""

class ScoreResult:
    """
    Data structure containing the final analysis report.
    Matches the fields expected by the test suite.
    """
    def __init__(self, overall_confidence, risk_level, component_scores, reasoning, is_phishing):
        self.overall_confidence = overall_confidence  # Float between 0.0 and 1.0
        self.risk_level = risk_level                  # String: 'low', 'medium', or 'high'
        self.component_scores = component_scores      # Dictionary of individual scores
        self.reasoning = reasoning                    # String text explaining the result
        self.is_phishing = is_phishing                # Boolean flag (True/False)


class ConfidenceScorer:
    """
    Manages the default algorithmic weights for the phishing detector.
    Requirement 3.2: Weights must sum up to approximately 1.0.
    """
    def __init__(self):
        self.weights = {
            'ml_classifier': 0.35,
            'url_analysis': 0.30,
            'sensitive_request': 0.15,
            'polite_request': 0.10,
            'short_email_risk': 0.10
        }


def score_analysis_confidence(results, custom_weights=None):
    """
    Calculates the final phishing probability score using a Normalized Weighted Average.
    
    Requirements Validated:
      - 3.1: Weighted algorithm combination
      - 3.3: Score normalization (0.0 to 1.0 range)
      - 3.4: Detailed breakdown of contributing factors
      - 3.5: Graceful degradation when sub-components fail
    """
    scorer = ConfidenceScorer()
    weights = custom_weights if custom_weights else scorer.weights
    
    component_scores = {}
    total_weight_used = 0.0
    weighted_sum = 0.0
    
    # Mathematical mapping for heuristic text risk levels
    risk_map = {'high': 1.0, 'medium': 0.5, 'low': 0.0, 'none': 0.0}
    
    for component, data in results.items():
        # Requirement 3.5: Graceful Degradation
        # If a component has an 'error' key, it failed. Skip it and redistribute weight.
        if not data or 'error' in data:
            continue 
            
        weight = weights.get(component, 0)
        score = 0.0
        
        # 1. Evaluate Machine Learning Classifier Output
        if component == 'ml_classifier':
            if data.get('classification') == 'phishing':
                score = data.get('confidence', 1.0)
            else:
                # If legitimate, treat confidence as distance from phishing (low threat)
                score = 0.0
        
        # 2. Evaluate URL Analysis Output
        elif component == 'url_analysis':
            summary = data.get('summary', {})
            total_urls = summary.get('total_urls', 0)
            if total_urls > 0:
                bad_urls = summary.get('suspicious_urls', 0) + summary.get('high_risk_urls', 0)
                # Ratio of malicious links to total links, bounded at 1.0
                score = min(1.0, bad_urls / total_urls)
                
        # 3. Evaluate Natural Language Processing (NLP) / Heuristic Outputs
        elif component in ['sensitive_request', 'polite_request', 'short_email_risk']:
            score = risk_map.get(data.get('risk_level', 'low'), 0.0)
            
        # Track individual calculated score
        component_scores[component] = score
        
        # Core Formula: sum(score * weight)
        weighted_sum += score * weight
        total_weight_used += weight
        
    # Requirement 3.3: Score Normalization
    # Divide by total weight used so the score dynamically scales if components fail
    overall_confidence = 0.0
    if total_weight_used > 0:
        overall_confidence = weighted_sum / total_weight_used
        
    # Classify Risk Level based on thresholds
    if overall_confidence < 0.3:
        risk_level = 'low'
    elif overall_confidence < 0.7:
        risk_level = 'medium'
    else:
        risk_level = 'high'
        
    # Requirement 3.4: Final Outputs & Verdict Determination
    is_phishing = overall_confidence >= 0.7
    reasoning = (
        f"Analysis finalized using {len(component_scores)} operational checks. "
        f"Aggregated thread confidence reached {overall_confidence * 100:.1f}%."
    )
    
    return ScoreResult(
        overall_confidence=overall_confidence,
        risk_level=risk_level,
        component_scores=component_scores,
        reasoning=reasoning,
        is_phishing=is_phishing
    )
