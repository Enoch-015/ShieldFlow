#!/usr/bin/env python3
"""
Setup ShieldFlow Datadog Integration

This script:
1. Creates/updates the ShieldFlow dashboard
2. Creates monitor alerts
3. Validates the integration

Usage:
    python setup_datadog.py

Requires:
    DATADOG_API_KEY and DATADOG_APP_KEY environment variables
"""

import json
import os
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    print("Error: requests library required. Run: pip install requests")
    sys.exit(1)


def get_config():
    api_key = os.getenv("DATADOG_API_KEY")
    app_key = os.getenv("DATADOG_APP_KEY")
    site = os.getenv("DD_SITE", "datadoghq.com")
    
    if not api_key:
        print("Error: DATADOG_API_KEY not set")
        sys.exit(1)
    if not app_key:
        print("Error: DATADOG_APP_KEY not set")
        sys.exit(1)
    
    return {
        "api_key": api_key,
        "app_key": app_key,
        "base_url": f"https://api.{site}",
        "headers": {
            "DD-API-KEY": api_key,
            "DD-APPLICATION-KEY": app_key,
            "Content-Type": "application/json",
        }
    }


def create_dashboard(config):
    print("\n📊 Creating ShieldFlow Dashboard...")
    
    dashboard_path = Path(__file__).parent / "dashboard.json"
    with open(dashboard_path) as f:
        dashboard = json.load(f)
    
    url = f"{config['base_url']}/api/v1/dashboard"
    resp = requests.post(url, headers=config["headers"], json=dashboard)
    
    if resp.status_code == 200:
        data = resp.json()
        print(f"   ✓ Dashboard created: {data.get('url', 'Check Datadog UI')}")
        return data.get("id")
    elif resp.status_code == 400 and "already exists" in resp.text.lower():
        print("   ℹ Dashboard already exists")
        return None
    else:
        print(f"   ✗ Failed: {resp.status_code} - {resp.text[:200]}")
        return None


def create_monitors(config):
    print("\n🚨 Creating Monitors...")
    
    monitors_path = Path(__file__).parent / "monitors.json"
    with open(monitors_path) as f:
        data = json.load(f)
    
    url = f"{config['base_url']}/api/v1/monitor"
    created = 0
    
    for monitor in data.get("monitors", []):
        name = monitor.get("name", "Unknown")
        resp = requests.post(url, headers=config["headers"], json=monitor)
        
        if resp.status_code == 200:
            print(f"   ✓ {name}")
            created += 1
        elif resp.status_code == 400:
            # Check if monitor already exists with this name
            error_text = resp.text.lower()
            if "already exists" in error_text or "duplicate" in error_text:
                print(f"   ℹ {name} (already exists)")
            else:
                print(f"   ⚠ {name}: {resp.status_code} - {resp.text[:100]}")
        else:
            print(f"   ✗ {name}: {resp.status_code}")
    
    print(f"\n   Created {created} monitors")


def validate_integration(config):
    print("\n🔍 Validating Integration...")
    
    # Test API key
    url = f"{config['base_url']}/api/v1/validate"
    resp = requests.get(url, headers=config["headers"])
    
    if resp.status_code == 200:
        print("   ✓ API key valid")
    else:
        print(f"   ✗ API key invalid: {resp.status_code}")
        return False
    
    # Test sending a metric
    from datetime import datetime
    test_metric = {
        "series": [{
            "metric": "shieldflow.setup.test",
            "type": 1,
            "points": [{"timestamp": int(datetime.now().timestamp()), "value": 1}],
            "tags": ["test:setup"]
        }]
    }
    
    url = f"{config['base_url']}/api/v2/series"
    resp = requests.post(url, headers=config["headers"], json=test_metric)
    
    if resp.status_code < 300:
        print("   ✓ Metrics endpoint working")
    else:
        print(f"   ✗ Metrics failed: {resp.status_code}")
    
    # Test logs endpoint
    test_log = [{
        "message": "ShieldFlow setup test",
        "ddsource": "shieldflow",
        "service": "shieldflow",
        "ddtags": "test:setup"
    }]
    
    site = os.getenv("DD_SITE", "datadoghq.com")
    url = f"https://http-intake.logs.{site}/api/v2/logs"
    resp = requests.post(url, headers=config["headers"], json=test_log)
    
    if resp.status_code < 300:
        print("   ✓ Logs endpoint working")
    else:
        print(f"   ⚠ Logs may require additional setup: {resp.status_code}")
    
    return True


def main():
    print("=" * 50)
    print("ShieldFlow Datadog Setup")
    print("=" * 50)
    
    config = get_config()
    print(f"\nUsing Datadog site: {os.getenv('DD_SITE', 'datadoghq.com')}")
    
    if validate_integration(config):
        create_dashboard(config)
        create_monitors(config)
        
        print("\n" + "=" * 50)
        print("✅ Setup Complete!")
        print("=" * 50)
        print("\nNext steps:")
        print("1. Open Datadog → Dashboards → 'ShieldFlow Security Dashboard'")
        print("2. Run your ShieldFlow application to see metrics")
        print("3. Configure notification channels in monitors")
    else:
        print("\n❌ Setup failed - check your API keys")
        sys.exit(1)


if __name__ == "__main__":
    main()
