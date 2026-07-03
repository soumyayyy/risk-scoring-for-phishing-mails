#!/usr/bin/env python3
"""
Test script for Confidence Scorer functionality.
Validates requirements 3.1, 3.2, 3.3, 3.4, 3.5 from the enhanced phishing detector spec.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from confidence_scorer import ConfidenceScorer, score_analysis_confidence


def test_weighted_confidence_calculation():
    """Test Requirement 3.1: Weighted algorithm combination"""
    print("Testing Requirement 3.1: Weighted confidence calculation")
    
    high_risk_results = {
        'ml_classifier': {'classification': 'phishing', 'confidence': 0.9},
        'url_analysis': {
            'summary': {
                'total_urls': 2,
                'safe_urls': 0,
                'suspicious_urls': 1,
                'high_risk_urls': 1
            }
        },
        'sensitive_request': {
            'is_sensitive_request': True,
            'category': 'financial',
            'risk_level': 'high'
        },
        'polite_request': {
            'is_polite_request': True,
            'risk_level': 'high'
        },
        'short_email_risk': {
            'is_short': True,
            'risk_level': 'medium'
        }
    }
    
    result = score_analysis_confidence(high_risk_results)
    print(f"  High-risk email confidence: {result.overall_confidence:.3f}")
    print(f"  Risk level: {result.risk_level}")
    
    low_risk_results = {
        'ml_classifier': {'classification': 'legitimate', 'confidence': 0.1},
        'url_analysis': {
            'summary': {
                'total_urls': 2,
                'safe_urls': 2,
                'suspicious_urls': 0,
                'high_risk_urls': 0
            }
        },
        'sensitive_request': {
            'is_sensitive_request': False,
            'category': 'none',
            'risk_level': 'low'
        },
        'polite_request': {
            'is_polite_request': False,
            'risk_level': 'low'
        },
        'short_email_risk': {
            'is_short': False,
            'risk_level': 'low'
        }
    }
    
    low_result = score_analysis_confidence(low_risk_results)
    print(f"  Low-risk email confidence: {low_result.overall_confidence:.3f}")
    print(f"  Risk level: {low_result.risk_level}")
    
    if result.overall_confidence > low_result.overall_confidence:
        print("  ✓ PASS: Weighted algorithm correctly differentiates risk levels")
        return True
    else:
        print("  ✗ FAIL: Weighted algorithm not working correctly")
        return False


def test_component_weight_assignment():
    """Test Requirement 3.2: Appropriate weight assignment"""
    print("\nTesting Requirement 3.2: Component weight assignment")
    
    scorer = ConfidenceScorer()
    weights = scorer.weights
    
    print(f"  Component weights:")
    for component, weight in weights.items():
        print(f"    {component}: {weight:.3f}")
    
    required_components = ['ml_classifier', 'url_analysis', 'sensitive_request', 'polite_request', 'short_email_risk']
    has_all_components = all(comp in weights for comp in required_components)
    
    total_weight = sum(weights.values())
    weights_normalized = abs(total_weight - 1.0) < 0.001
    
    print(f"  Total weight: {total_weight:.3f}")
    print(f"  All required components present: {has_all_components}")
    print(f"  Weights normalized: {weights_normalized}")
    
    if has_all_components and weights_normalized:
        print("  ✓ PASS: Component weights properly assigned")
        return True
    else:
        print("  ✗ FAIL: Component weight assignment issues")
        return False


def test_confidence_score_normalization():
    """Test Requirement 3.3: Score normalization (0-1 range)"""
    print("\nTesting Requirement 3.3: Confidence score normalization")
    
    test_cases = [
        {
            'url_analysis': {'summary': {'total_urls': 5, 'safe_urls': 0, 'suspicious_urls': 0, 'high_risk_urls': 5}},
            'sensitive_request': {'is_sensitive_request': True, 'risk_level': 'high'},
            'polite_request': {'is_polite_request': True, 'risk_level': 'high'},
            'short_email_risk': {'is_short': True, 'risk_level': 'high'}
        },
        {
            'url_analysis': {'summary': {'total_urls': 0, 'safe_urls': 0, 'suspicious_urls': 0, 'high_risk_urls': 0}},
            'sensitive_request': {'is_sensitive_request': False, 'risk_level': 'low'},
            'polite_request': {'is_polite_request': False, 'risk_level': 'low'},
            'short_email_risk': {'is_short': False, 'risk_level': 'low'}
        },
        {
            'url_analysis': {'summary': {'total_urls': 3, 'safe_urls': 1, 'suspicious_urls': 2, 'high_risk_urls': 0}},
            'sensitive_request': {'is_sensitive_request': True, 'risk_level': 'medium'},
            'polite_request': {'is_polite_request': False, 'risk_level': 'low'},
            'short_email_risk': {'is_short': False, 'risk_level': 'low'}
        }
    ]
    
    all_normalized = True
    for i, test_case in enumerate(test_cases):
        result = score_analysis_confidence(test_case)
        confidence = result.overall_confidence
        
        print(f"  Test case {i+1}: confidence = {confidence:.3f}")
        
        if not (0.0 <= confidence <= 1.0):
            print(f"    ✗ FAIL: Score {confidence} not in range [0,1]")
            all_normalized = False
    
    if all_normalized:
        print("  ✓ PASS: All confidence scores normalized to [0,1] range")
        return True
    else:
        print("  ✗ FAIL: Some scores outside [0,1] range")
        return False


def test_confidence_breakdown_completeness():
    """Test Requirement 3.4: Detailed breakdown of contributing factors"""
    print("\nTesting Requirement 3.4: Confidence breakdown completeness")
    
    test_results = {
        'ml_classifier': {'classification': 'phishing'},
        'url_analysis': {
            'summary': {
                'total_urls': 2,
                'safe_urls': 0,
                'suspicious_urls': 2,
                'high_risk_urls': 0
            }
        },
        'sensitive_request': {
            'is_sensitive_request': True,
            'category': 'credentials',
            'risk_level': 'medium'
        },
        'polite_request': {
            'is_polite_request': True,
            'risk_level': 'low'
        }
    }
    
    result = score_analysis_confidence(test_results)
    
    has_component_scores = bool(result.component_scores)
    has_reasoning = bool(result.reasoning)
    has_risk_level = result.risk_level in ['low', 'medium', 'high']
    has_phishing_classification = isinstance(result.is_phishing, bool)
    
    print(f"  Component scores present: {has_component_scores}")
    print(f"  Reasoning provided: {has_reasoning}")
    print(f"  Risk level valid: {has_risk_level} ({result.risk_level})")
    print(f"  Phishing classification: {has_phishing_classification} ({result.is_phishing})")
    
    if has_reasoning:
        print(f"  Reasoning sample: {result.reasoning[:100]}...")
    
    if has_component_scores:
        print(f"  Component scores: {list(result.component_scores.keys())}")
    
    if has_component_scores and has_reasoning and has_risk_level and has_phishing_classification:
        print("  ✓ PASS: Complete breakdown provided")
        return True
    else:
        print("  ✗ FAIL: Incomplete breakdown")
        return False


def test_graceful_degradation():
    """Test Requirement 3.5: Graceful degradation when components fail"""
    print("\nTesting Requirement 3.5: Graceful degradation with component failures")
    
    partial_results = {
        'ml_classifier': {'error': 'API timeout'},
        'url_analysis': {
            'summary': {
                'total_urls': 1,
                'safe_urls': 0,
                'suspicious_urls': 1,
                'high_risk_urls': 0
            }
        },
        'sensitive_request': {'error': 'Analysis failed'},
        'polite_request': {
            'is_polite_request': True,
            'risk_level': 'medium'
        },
        'short_email_risk': {'error': 'Component unavailable'}
    }
    
    result = score_analysis_confidence(partial_results)
    
    has_valid_confidence = 0.0 <= result.overall_confidence <= 1.0
    has_risk_level = result.risk_level in ['low', 'medium', 'high']
    has_reasoning = bool(result.reasoning)
    
    print(f"  Confidence with failures: {result.overall_confidence:.3f}")
    print(f"  Risk level: {result.risk_level}")
    print(f"  Valid confidence score: {has_valid_confidence}")
    print(f"  Valid risk level: {has_risk_level}")
    print(f"  Reasoning provided: {has_reasoning}")
    
    all_failed_results = {
        'ml_classifier': {'error': 'Failed'},
        'url_analysis': {'error': 'Failed'},
        'sensitive_request': {'error': 'Failed'},
        'polite_request': {'error': 'Failed'},
        'short_email_risk': {'error': 'Failed'}
    }
    
    failed_result = score_analysis_confidence(all_failed_results)
    all_failed_valid = 0.0 <= failed_result.overall_confidence <= 1.0
    
    print(f"  All components failed confidence: {failed_result.overall_confidence:.3f}")
    print(f"  All failed result valid: {all_failed_valid}")
    
    if has_valid_confidence and has_risk_level and has_reasoning and all_failed_valid:
        print("  ✓ PASS: Graceful degradation working correctly")
        return True
    else:
        print("  ✗ FAIL: Degradation not working properly")
        return False


def test_custom_weights():
    """Test custom weight configuration"""
    print("\nTesting custom weight configuration")
    
    custom_weights = {
        'ml_classifier': 0.2,
        'url_analysis': 0.5,
        'sensitive_request': 0.15,
        'polite_request': 0.1,
        'short_email_risk': 0.05
    }
    
    test_results = {
        'url_analysis': {
            'summary': {
                'total_urls': 2,
                'safe_urls': 0,
                'suspicious_urls': 0,
                'high_risk_urls': 2
            }
        },
        'sensitive_request': {'is_sensitive_request': False, 'risk_level': 'low'},
        'polite_request': {'is_polite_request': False, 'risk_level': 'low'},
        'short_email_risk': {'is_short': False, 'risk_level': 'low'}
    }
    
    default_result = score_analysis_confidence(test_results)
    custom_result = score_analysis_confidence(test_results, custom_weights)
    
    print(f"  Default weights confidence: {default_result.overall_confidence:.3f}")
    print(f"  Custom weights confidence: {custom_result.overall_confidence:.3f}")
    
    if custom_result.overall_confidence > default_result.overall_confidence:
        print("  ✓ PASS: Custom weights working correctly")
        return True
    else:
        print("  ✗ FAIL: Custom weights not applied properly")
        return False


def main():
    """Run all confidence scorer tests"""
    print("Confidence Scorer Test Suite")
    print("=" * 60)
    
    tests = [
        test_weighted_confidence_calculation,
        test_component_weight_assignment,
        test_confidence_score_normalization,
        test_confidence_breakdown_completeness,
        test_graceful_degradation,
        test_custom_weights
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            results.append(False)
    
    print("\n" + "=" * 60)
    print("Test Summary:")
    print(f"  Passed: {sum(results)}/{len(results)}")
    print(f"  Failed: {len(results) - sum(results)}/{len(results)}")
    
    if all(results):
        print("  ✓ ALL TESTS PASSED - Confidence Scorer meets requirements")
        return 0
    else:
        print("  ✗ SOME TESTS FAILED - Review implementation")
        return 1

# THIS IS THE VITAL PART THAT WAS LIKELY MISSING!
if __name__ == "__main__":
    exit(main())