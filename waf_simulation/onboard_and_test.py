import sys
import json
import requests

def onboard():
    print("=" * 60)
    print(" 🚀 AUTOMATED SAAS WAF CLIENT ONBOARDING TOOL")
    print("=" * 60)
    
    # 1. Prepare client payload
    onboard_url = "http://localhost:5050/api/onboard"
    client_payload = {
        "tenant_id": "test_sec",
        "name": "Global Security Test Portal",
        "domain": "test.localhost",
        "backend_url": "http://localhost:5001",
        "it_email": "test-it@securesite.com",
        "security_level": "HIGH"
    }
    
    print(f"[*] Calling dynamic WAF onboarding API: {onboard_url}...")
    print(f"[*] Onboarding Payload:\n{json.dumps(client_payload, indent=2)}")
    
    try:
        response = requests.post(onboard_url, json=client_payload)
        if response.status_code == 200:
            res_data = response.json()
            print("\n✨ SUCCESS: CLIENT ONBOARDED SUCCESSFULLY!")
            print(f"   Message: {res_data.get('message')}")
            print("\n🔑 PROTECTION CREDENTIALS ISSUED:")
            print(f"   - Tenant ID: {res_data['credentials']['tenant_id']}")
            print(f"   - Shield Header: {res_data['credentials']['shield_header']}")
            print(f"   - Shield Value: {res_data['credentials']['shield_value']}")
            print(f"   - WAF Protected URL: {res_data['credentials']['waf_gateway_url']}")
            
            print("\n" + "=" * 60)
            print(" 👉 HOW TO TEST YOUR SECURITY:")
            print(" 1. Run your second site backend: python \"test for sec/app.py\"")
            print(" 2. Open this link in your browser:")
            print(f"    {res_data['credentials']['waf_gateway_url']}")
            print(" 3. Submit a clean input like 'Safe Message' -> Works perfectly!")
            print(" 4. Submit an attack like '<script>alert(1)</script>' -> BLOCKED!")
            print("=" * 60)
        else:
            print(f"\n❌ FAILED: API returned status code {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"\n❌ ERROR: Could not connect to the WAF API on port 5050: {e}")
        print("[!] Make sure the main WAF engine is running (python defense_suite_master.py)")

if __name__ == "__main__":
    onboard()
