#!/usr/bin/env python3
"""
Simple dual interface test without pydantic dependencies
"""

import asyncio
import sys
from datetime import datetime

# Direct imports to avoid pydantic issues
import serial
import serial.tools.list_ports
from bleak import BleakScanner


async def test_macbook_ble():
    """Test MacBook's native BLE"""
    print("\n=== Testing MacBook BLE ===")
    print("Scanning for 5 seconds...")

    devices_found = {}

    def callback(device, adv_data):
        devices_found[device.address] = {"name": device.name, "rssi": adv_data.rssi}
        print(f"[MAC] Found: {device.address} | {device.name or 'Unknown'} | RSSI: {adv_data.rssi}")

    scanner = BleakScanner(detection_callback=callback)

    try:
        await scanner.start()
        await asyncio.sleep(5)
        await scanner.stop()

        print(f"\n✅ MacBook BLE working! Found {len(devices_found)} devices")
        return True
    except Exception as e:
        print(f"❌ MacBook BLE error: {e}")
        return False


async def test_sniffer_dongle():
    """Test sniffer dongle detection"""
    print("\n=== Detecting Sniffer Dongle ===")

    ports = serial.tools.list_ports.comports()

    if not ports:
        print("❌ No serial ports detected!")
        return None

    print(f"Found {len(ports)} serial port(s):")
    for i, port in enumerate(ports):
        print(f"  [{i}] {port.device}")
        print(f"      Description: {port.description}")
        if port.manufacturer:
            print(f"      Manufacturer: {port.manufacturer}")
        if port.vid and port.pid:
            print(f"      VID:PID: {port.vid:04X}:{port.pid:04X}")

    # Check for known sniffer identifiers
    sniffer_port = None
    for port in ports:
        if any(
            keyword in port.description.lower()
            for keyword in ["sniffer", "ble", "nordic", "ti", "uart", "usb serial"]
        ):
            sniffer_port = port.device
            print(f"\n✅ Potential sniffer detected on: {sniffer_port}")
            break

    if not sniffer_port and ports:
        print("\n⚠️  No auto-detected sniffer. Using first available port for testing.")
        sniffer_port = ports[0].device

    # Try to open the port
    if sniffer_port:
        try:
            ser = serial.Serial(sniffer_port, 115200, timeout=1)
            print(f"✅ Successfully opened {sniffer_port}")

            # Try to send a test command
            ser.write(b"TEST\n")
            response = ser.read(100)
            if response:
                print(f"   Response: {response}")

            ser.close()
            return sniffer_port
        except Exception as e:
            print(f"⚠️  Could not communicate with {sniffer_port}: {e}")
            return None

    return None


async def main():
    print("=== BlueFusion Simple Dual Interface Test ===")
    print(f"Starting at {datetime.now()}")

    print("\n⚠️  Requirements:")
    print("   1. Bluetooth must be enabled on your Mac")
    print("   2. BLE sniffer dongle should be connected")
    print("\nStarting tests...")
    await asyncio.sleep(1)

    # Test both interfaces
    mac_ok = await test_macbook_ble()
    sniffer_port = await test_sniffer_dongle()

    # Summary
    print("\n=== Test Summary ===")
    print(f"MacBook BLE: {'✅ WORKING' if mac_ok else '❌ FAILED'}")
    print(f"Sniffer Dongle: {'✅ DETECTED' if sniffer_port else '❌ NOT FOUND'}")

    if mac_ok and sniffer_port:
        print("\n🎉 Both interfaces are ready to use!")
        print(f"   Sniffer port: {sniffer_port}")
    elif mac_ok:
        print("\n✅ MacBook BLE is working. Check sniffer connection.")
    else:
        print("\n❌ Please check your Bluetooth settings.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nTest interrupted")
        sys.exit(0)
