import os
import requests
import json
from config.settings import settings

def test_nso_connection():
    print(f"--- NSO Connection Test ---")
    print(f"Base URL: {settings.nso.base_url}")
    print(f"User: {settings.nso.username}")
    
    try:
        # 18080 포트(Web UI 포트)로도 시도
        url = "http://100.67.63.77:18080/restconf/data/tailf-ncs:devices/device"
        auth = (settings.nso.username, settings.nso.password)
        headers = {'Accept': 'application/yang-data+json'}
        
        print(f"Connecting to: {url}...")
        response = requests.get(url, auth=auth, headers=headers, timeout=10)
        
        if response.status_code == 200:
            print("✅ Successfully connected to NSO!")
            data = response.json()
            devices = data.get("tailf-ncs:device", [])
            print(f"Found {len(devices)} devices:")
            for d in devices:
                print(f"  - {d.get('name')}")
        else:
            print(f"❌ Failed to connect. Status Code: {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_nso_connection()
