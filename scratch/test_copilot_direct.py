import requests
import sys

# Reconfigure stdout to use utf-8
sys.stdout.reconfigure(encoding='utf-8')

API_URL = "http://127.0.0.1:8000/api/v1"

def test_copilot():
    # Login
    print("Logging in...")
    login_res = requests.post(f"{API_URL}/auth/login", json={"email": "admin@niravan.ai", "password": "admin123"})
    token = login_res.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    prompts = [
        "What is the most critical threat right now?",
        "most critical",
        "critical threat",
        "biggest risk",
        "Explain brute force",
        "Generate incident response playbook"
    ]
    
    for p in prompts:
        print(f"\n--- Prompt: '{p}' ---")
        res = requests.post(f"{API_URL}/copilot", headers=headers, json={"prompt": p})
        print(f"Status: {res.status_code}")
        print("Response:")
        print(res.json().get("response"))

if __name__ == "__main__":
    test_copilot()
