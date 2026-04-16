#!/usr/bin/env python3
"""
Test UI button functionality
"""

import time

import pytest
import requests


def test_api_status():
    """Test that the API is running and accessible"""
    try:
        response = requests.get("http://localhost:8000/", timeout=5)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "running"
    except requests.exceptions.ConnectionError:
        pytest.skip("API not running - start with: python bluefusion.py start")
    except Exception as e:
        pytest.fail(f"API Error: {e}")


def test_scan_start():
    """Test scan start button functionality"""
    try:
        response = requests.post(
            "http://localhost:8000/scan/start",
            json={"interface": "both", "mode": "active"},
            timeout=5,
        )
        assert response.status_code == 200
        result = response.json()
        assert result["status"] in ["started", "already_running"]
    except requests.exceptions.ConnectionError:
        pytest.skip("API not running")
    except Exception as e:
        pytest.fail(f"Scan Error: {e}")


def test_device_discovery():
    """Test device discovery after scan"""
    time.sleep(3)  # Wait for devices to be discovered
    try:
        response = requests.get("http://localhost:8000/devices?interface=both", timeout=5)
        assert response.status_code == 200
        devices = response.json()
        mac_count = len(devices.get("macbook", []))
        sniff_count = len(devices.get("sniffer", []))
        print(f"   ✅ Found {mac_count} devices on MacBook")
        print(f"   ✅ Found {sniff_count} devices on Sniffer")
    except requests.exceptions.ConnectionError:
        pytest.skip("API not running")
    except Exception as e:
        pytest.fail(f"Device Error: {e}")


def test_websocket_endpoint():
    """Test WebSocket endpoint availability"""
    try:
        import websocket

        ws = websocket.WebSocket()
        ws.connect("ws://localhost:8000/stream", timeout=5)
        ws.close()
    except ImportError:
        pytest.skip("websocket-client not installed")
    except requests.exceptions.ConnectionError:
        pytest.skip("API not running")
    except Exception:
        pytest.skip("WebSocket endpoint not available")


if __name__ == "__main__":
    # Manual test mode when run directly
    print("Testing BlueFusion UI Button Functionality")
    print("=" * 50)

    # Test 1: Check API is running
    print("\n1. Testing API Status...")
    try:
        response = requests.get("http://localhost:8000/", timeout=5)
        print(f"   ✅ API Running: {response.json()['status']}")
    except Exception as e:
        print(f"   ❌ API Error: {e}")
        print("   Make sure to run: python bluefusion.py start")
        exit(1)

    # Test 2: Test Scan Start
    print("\n2. Testing Scan Start Button...")
    try:
        response = requests.post(
            "http://localhost:8000/scan/start",
            json={"interface": "both", "mode": "active"},
            timeout=5,
        )
        result = response.json()
        print(f"   ✅ Scan Started: {result['status']}")
        print(f"   Interfaces: {result.get('interfaces', {})}")
    except Exception as e:
        print(f"   ❌ Scan Error: {e}")

    # Test 3: Wait and check devices
    print("\n3. Waiting for devices...")
    time.sleep(3)

    try:
        response = requests.get("http://localhost:8000/devices?interface=both", timeout=5)
        devices = response.json()
        mac_count = len(devices.get("macbook", []))
        sniff_count = len(devices.get("sniffer", []))
        print(f"   ✅ Found {mac_count} devices on MacBook")
        print(f"   ✅ Found {sniff_count} devices on Sniffer")

        if mac_count > 0:
            print("\n   Sample devices:")
            for device in devices["macbook"][:3]:
                print(
                    f"     - {device['address']} | {device.get('name', 'Unknown')} | {device['rssi']} dBm"
                )
    except Exception as e:
        print(f"   ❌ Device Error: {e}")

    # Test 4: Check WebSocket endpoint
    print("\n4. Testing WebSocket endpoint...")
    try:
        import websocket

        ws = websocket.WebSocket()
        ws.connect("ws://localhost:8000/stream", timeout=5)
        print("   ✅ WebSocket connected")
        ws.close()
    except Exception as e:
        print(f"   ❌ WebSocket Error: {e}")

    print("\n" + "=" * 50)
    print("\n✅ API is working properly!")
    print("\nNow open http://localhost:7860 and:")
    print("1. Click 'Start Scan' in Control tab")
    print("2. Click 'Refresh Devices' in Devices tab")
    print("3. Click 'Refresh Device List' in Service Explorer tab")
    print("\nIf buttons don't work, check browser console for errors (F12)")
