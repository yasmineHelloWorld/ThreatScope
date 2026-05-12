import sys
import os
import logging
import time

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from intelligence.analyzer import IntelligenceAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def test_pipeline():
    analyzer = IntelligenceAnalyzer()
    
    print("\n--- Testing Normal Event ---")
    normal_event = {
        "ip_address": "1.2.3.4",
        "service_type": "http",
        "request_type": "GET",
        "endpoint": "/",
        "user_agent": "Mozilla/5.0",
        "payload": ""
    }
    result = analyzer.analyze_event(normal_event)
    print(f"Risk Score: {result.risk_score}")
    print(f"Classification: {result.classification}")
    print(f"Is Attack: {result.is_attack}")
    
    print("\n--- Testing Brute Force Simulation (Batched) ---")
    # Simulate history without calling the API every time
    ip = "5.6.7.8"
    for i in range(14):
        event = {
            "ip_address": ip,
            "service_type": "http",
            "request_type": "POST",
            "endpoint": "/login",
            "username": f"user{i}",
            "password": "password",
            "user_agent": "Mozilla/5.0"
        }
        analyzer._update_history(ip, event)
        # We also need to manually trigger the detectors to update their internal state if they are stateful
        for detector in analyzer.detectors:
            if detector.name == "brute_force" or detector.name == "port_scanner":
                detector.detect(event, []) # Just to update state

    # Now call the full analyzer for the final attempt
    final_event = {
        "ip_address": ip,
        "service_type": "http",
        "request_type": "POST",
        "endpoint": "/login",
        "username": "admin",
        "password": "password",
        "user_agent": "Mozilla/5.0"
    }
    time.sleep(1) # Small pause
    result = analyzer.analyze_event(final_event)
    
    print(f"Final Risk Score: {result.risk_score}")
    print(f"Classification: {result.classification}")
    print(f"Attack Type: {result.attack_type}")
    print(f"Groq Reasoning: {result.details.get('groq_reasoning')}")
    print(f"AI Logic: {result.details.get('groq_classification', {}).get('ai_logic')}")
    
    print("\n--- Testing SQL Injection ---")
    sql_event = {
        "ip_address": "9.10.11.12",
        "service_type": "http",
        "request_type": "POST",
        "endpoint": "/search",
        "payload": "'; DROP TABLE users; --",
        "user_agent": "Mozilla/5.0"
    }
    time.sleep(1) # Small pause
    result = analyzer.analyze_event(sql_event)
    print(f"Risk Score: {result.risk_score}")
    print(f"Classification: {result.classification}")
    print(f"Attack Type: {result.attack_type}")
    print(f"Groq Reasoning: {result.details.get('groq_reasoning')}")

if __name__ == "__main__":
    test_pipeline()
