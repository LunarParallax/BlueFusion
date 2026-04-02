<div align="center">
  <img src="public/assets/BlueFusion_icon_pack/bluefusion_512x512.png" alt="BlueFusion Logo" width="200" height="200">
  
  # BlueFusion
  ### Advanced Bluetooth Low Energy (BLE) Analysis & Security Testing Platform
</div>

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Platform: macOS](https://img.shields.io/badge/platform-macOS-lightgrey.svg)](https://www.apple.com/macos/)

## 🌍 Professional BLE Security Analysis Tool for Researchers, Developers & Security Professionals Worldwide

BlueFusion is an enterprise-grade, AI-powered Bluetooth Low Energy (BLE) analysis platform that combines macOS native BLE capabilities with professional USB sniffer dongles for comprehensive wireless protocol analysis, security testing, and IoT device research.

### 🔍 Keywords: BLE Security, Bluetooth Analysis, IoT Security Testing, Wireless Protocol Analyzer, BLE Sniffer, Bluetooth Hacking Tool, IoT Penetration Testing, GATT Protocol Analyzer, BLE Packet Inspector, Wireless Security Research

## 🎯 Who Uses BlueFusion?

- **Security Researchers** - Analyze BLE vulnerabilities in IoT devices
- **Penetration Testers** - Professional wireless security assessments
- **IoT Developers** - Debug and optimize BLE implementations
- **Forensic Analysts** - Investigate BLE communications
- **Academic Researchers** - Study wireless protocols and security
- **Hardware Engineers** - Reverse engineer BLE devices

## 🚀 Key Features

### 🔐 Security Analysis
- **Real-time BLE packet capture** and analysis
- **GATT protocol dissection** with deep packet inspection
- **Vulnerability scanning** for common BLE security issues
- **Man-in-the-Middle (MITM)** testing capabilities
- **Encryption analysis** with AES-CCM support
- **Custom fuzzing** for BLE services and characteristics

### 🛠️ Professional Tools
- **Dual Interface Technology** - Simultaneous macOS BLE + USB sniffer support
- **AI-Powered Pattern Recognition** - Detect anomalies and security patterns
- **WebSocket Streaming** - Real-time packet streaming for automation
- **RESTful API** - Integrate with existing security workflows
- **Hex Pattern Matching** - Advanced packet filtering and analysis
- **Channel Hopping** - Monitor all BLE advertising channels

### 📊 Analysis & Reporting
- **Interactive Web Dashboard** - Real-time visualization
- **Packet Inspector** - Detailed protocol analysis
- **Export Capabilities** - PCAP, JSON, CSV formats
- **Custom Scripting** - Python API for automation
- **Comprehensive Logging** - Audit trail for compliance

## 🌐 Global Compatibility

BlueFusion supports BLE analysis worldwide with:
- **Multi-language documentation** (Coming soon: 中文, 日本語, Español, Deutsch, Français)
- **International BLE standards** compliance
- **Region-specific frequency support**
- **Global IoT device database** integration

## 📦 Installation

### Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/LunarParallax/BlueFusion.git
cd BlueFusion

# Run the installer
./install.sh
```

### Manual Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start BlueFusion
python -m src.api.fastapi_server
```

### Docker Installation (Coming Soon)

```bash
docker pull bluefusion/bluefusion:latest
docker run -p 8000:8000 bluefusion/bluefusion
```

## 🎮 Usage Examples

### 1. Basic BLE Scanning
```bash
# Start BlueFusion
python bluefusion.py start

# Quick scan for nearby devices
python bluefusion.py scan

# Connect to specific device
python bluefusion.py connect AA:BB:CC:DD:EE:FF
```

### 2. Security Analysis
```python
# Example: Analyze GATT services
from src.analyzers.packet_inspector import PacketInspector
from src.interfaces.macbook_ble import MacBookBLE

# Initialize interfaces
ble = MacBookBLE()
inspector = PacketInspector()

# Start security analysis
await ble.scan_for_vulnerabilities()
```

### 3. API Integration
```bash
# Start API server
python -m src.api.fastapi_server

# Access API documentation
open http://localhost:8000/docs

# WebSocket streaming
wscat -c ws://localhost:8000/stream
```

## 🏗️ Architecture

```
BlueFusion/
├── src/
│   ├── analyzers/          # Protocol analysis engines
│   │   ├── hex_pattern_matcher.py
│   │   ├── packet_inspector.py
│   │   └── protocol_parsers/
│   ├── interfaces/         # Hardware interfaces
│   │   ├── macbook_ble.py
│   │   ├── sniffer_dongle.py
│   │   └── auto_connect_manager.py
│   ├── api/               # RESTful API
│   │   └── fastapi_server.py
│   ├── ui/                # Web interface
│   │   ├── gradio_interface.py
│   │   └── characteristic_monitor.py
│   └── utils/             # Security utilities
│       └── ble_crypto/
├── tests/                 # Comprehensive test suite
├── docs/                  # Documentation
└── examples/              # Usage examples
```

## 🔧 Advanced Configuration

### Custom Sniffer Support
```python
# config.json
{
  "sniffer": {
    "type": "ubertooth",
    "port": "/dev/ttyUSB0",
    "baudrate": 115200
  }
}
```

### Security Policies
```python
# Enable advanced security features
{
  "security": {
    "enable_mitm_detection": true,
    "log_encrypted_packets": true,
    "vulnerability_scanning": true
  }
}
```

## 🌟 Use Cases

### 1. IoT Security Assessment
- Analyze smart home devices (locks, cameras, sensors)
- Test medical device BLE security
- Audit industrial IoT implementations

### 2. Automotive Security
- Test vehicle keyless entry systems
- Analyze in-car BLE communications
- Research V2X communications

### 3. Mobile Security
- Test mobile app BLE implementations
- Analyze wearable device security
- Research beacon technologies

## 📊 Performance Metrics

- **Packet Capture Rate**: Up to 1000 packets/second
- **Simultaneous Connections**: 20+ devices
- **Analysis Latency**: <10ms per packet
- **Storage Efficiency**: Compressed packet storage
- **API Response Time**: <50ms average

## 🤝 Contributing

We welcome contributions from the global security community! See [CONTRIBUTORS.md](CONTRIBUTORS.md) for guidelines.

### Development Setup
```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Code formatting
black src/ tests/

# Linting
ruff check src/
```

## 📚 Documentation

- [Getting Started Guide](docs/getting_started.md)
- [API Reference](docs/api_reference.md)
- [Security Best Practices](docs/security_guide.md)
- [Protocol Analysis Guide](docs/protocol_analysis.md)
- [Troubleshooting](docs/troubleshooting.md)

## 🔒 Security Considerations

BlueFusion is designed for legitimate security research and testing:
- Always obtain proper authorization before testing
- Follow responsible disclosure practices
- Comply with local laws and regulations
- Use ethically and responsibly

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🗺️ Roadmap

- [ ] Windows & Linux support
- [ ] Cloud-based analysis platform
- [ ] Machine learning anomaly detection
- [ ] Automated vulnerability reporting
- [ ] Integration with popular security frameworks

---

**BlueFusion** - Empowering security researchers worldwide to analyze and secure the Internet of Things.

🔵 Made with ❤️ by the Ebowwa Labs Team | 🌍 Global BLE Security Community
