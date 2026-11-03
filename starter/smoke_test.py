"""Smoke test for the combined guardrail/trust take-home. 
 
Run from the candidate folder: 
    python starter/smoke_test.py 
""" 
import csv 
import os 
import sys 
 
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..")) 
sys.path.insert(0, ROOT) 
 
from mock_guardrail import check_guardrail, list_policies 
 
 
def main(): 
    print("Registered policies:") 
    for name, cfg in list_policies().items(): 
        print(f"  - {name} ({cfg['policy_id']}, direction={cfg['direction']}, threshold={cfg['threshold']})") 
 
    result = check_guardrail( "Should I invest my savings in index funds or pay off my mortgage first?", 
        "NO_FINANCIAL_ADVICE", 
    ) 
    print("\nSingle call example:") 
    print(" ", result) 
 
    total = 0 
    for filename in ("golden_dataset.csv", "response_dataset.csv"): 
        path = os.path.join(ROOT, "data", filename) 
        with open(path, newline="", encoding="utf-8") as f: 
            n = sum(1 for _ in csv.DictReader(f)) 
        total += n 
        print(f"{filename}: {n} rows") 
    print(f"Total supplied examples: {total}") 
 
 
if __name__ == "__main__": 
    main()