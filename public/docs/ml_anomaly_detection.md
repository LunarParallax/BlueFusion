# ML-Based Anomaly Detection for BLE Packets

BlueFusion now includes machine learning-powered anomaly detection for BLE traffic analysis. This feature uses multiple algorithms to detect unusual patterns in BLE packet data, helping identify potential security threats and abnormal behavior.

## Features

### Multiple Detection Methods

The anomaly detection system uses an ensemble approach combining:

1. **Isolation Forest** - Unsupervised ML algorithm for outlier detection
2. **Local Outlier Factor (LOF)** - Density-based anomaly detection
3. **Statistical Z-Score Analysis** - Detects statistical deviations from normal behavior
4. **Rule-Based Security Checks** - Identifies known suspicious patterns

### Feature Extraction

Automatic extraction of relevant features from BLE packets:
- Data length
- RSSI (signal strength)
- Byte entropy (randomness measure)
- Unique byte ratio
- Repeating pattern detection
- Opcode analysis
- Payload variance
- Inter-arrival timing

### Anomaly Types

The system detects various types of anomalies:
- **Statistical** - Deviations from learned statistical norms
- **Behavioral** - Patterns differing from historical behavior
- **Temporal** - Unusual timing patterns
- **Protocol** - Abnormal protocol usage
- **Security** - Potential security threats
- **Pattern** - Inconsistent data patterns

### Severity Levels

Anomalies are classified by severity:
- **LOW** - Minor deviations
- **MEDIUM** - Notable anomalies worth monitoring
- **HIGH** - Significant anomalies requiring investigation
- **CRITICAL** - Severe anomalies needing immediate attention

## Installation

The ML anomaly detection requires scikit-learn:

```bash
pip install scikit-learn
```

Or install with the AI extras:

```bash
pip install "bluefusion[ai]"
```

## Usage

### Basic Usage

```python
from datetime import datetime
from src.analyzers import MLAnomalyDetector
from src.interfaces.base import BLEPacket, DeviceType

# Create detector
detector = MLAnomalyDetector(
    contamination=0.05,  # Expected proportion of anomalies
    n_estimators=100,     # Number of trees in Isolation Forest
    window_size=100,      # Sliding window size
    min_training_samples=50  # Samples before training
)

# Process packets
for packet in ble_packets:
    result = detector.detect(packet)
    
    if result.is_anomaly:
        print(f"Anomaly detected!")
        print(f"  Score: {result.anomaly_score:.2f}")
        print(f"  Severity: {result.severity.value}")
        print(f"  Types: {[t.value for t in result.anomaly_types]}")
        print(f"  Description: {result.description}")
        print(f"  Recommendation: {result.recommended_action}")
```

### Using the High-Level Engine

```python
from src.analyzers import AnomalyDetectionEngine

# Create engine
engine = AnomalyDetectionEngine()

# Add alert callback for critical anomalies
def on_alert(result):
    print(f"ALERT: {result.description}")
    print(f"Action: {result.recommended_action}")

engine.add_alert_callback(on_alert)

# Analyze packets
result = engine.analyze_packet(packet)
if result:
    print(f"Anomaly found: {result.description}")

# Get statistics
stats = engine.get_statistics()
print(f"Total packets: {stats.total_packets_analyzed}")
print(f"Anomalies detected: {stats.total_anomalies_detected}")
print(f"Anomaly rate: {stats.anomaly_rate:.2%}")
```

### Integration with Packet Inspector

```python
from src.analyzers import PacketInspector, AnomalyDetectionEngine

# Create both components
inspector = PacketInspector()
anomaly_engine = AnomalyDetectionEngine()

# Process packets through both
for packet in ble_packets:
    # Traditional inspection
    inspection = inspector.inspect_packet(packet)
    
    # ML anomaly detection
    anomaly = anomaly_engine.analyze_packet(packet)
    
    # Combine results
    if anomaly:
        print(f"Security Alert: {anomaly.description}")
        print(f"Protocol: {inspection.protocol}")
```

### Training Modes

#### Online Learning (Default)
The detector learns incrementally from each packet:

```python
detector = MLAnomalyDetector()

for packet in packets:
    # Automatically updates model
    result = detector.detect(packet, update_model=True)
```

#### Batch Training
Train on historical data first:

```python
detector = MLAnomalyDetector(min_training_samples=100)

# Feed training data
for packet in training_packets:
    detector.partial_fit(packet)

# Now detect anomalies
for packet in test_packets:
    result = detector.detect(packet, update_model=False)
```

### Configuration Options

```python
detector = MLAnomalyDetector(
    contamination=0.05,       # Expected anomaly proportion (0-0.5)
    n_estimators=100,         # Trees in Isolation Forest
    window_size=100,          # Sliding window size
    training_required=False,   # Allow detection before training
    min_training_samples=50   # Minimum samples for training
)
```

## API Reference

### MLAnomalyDetector

Core anomaly detection class.

**Methods:**
- `detect(packet, update_model=True)` - Detect anomalies in a packet
- `partial_fit(packet)` - Incrementally train on a packet
- `get_statistics()` - Get detection statistics
- `reset()` - Reset detector state

### AnomalyDetectionEngine

High-level interface with alert callbacks.

**Methods:**
- `analyze_packet(packet)` - Analyze packet for anomalies
- `add_alert_callback(callback)` - Add callback for alerts
- `enable()` / `disable()` - Toggle detection
- `get_statistics()` - Get statistics
- `reset()` - Reset detector

### AnomalyDetectionResult

Result object returned by detection.

**Fields:**
- `packet_id` - Unique packet identifier
- `timestamp` - Detection timestamp
- `is_anomaly` - Whether anomaly detected
- `anomaly_score` - Score from 0.0 to 1.0
- `anomaly_types` - List of detected anomaly types
- `severity` - Severity level
- `confidence` - Confidence score
- `features` - Extracted features
- `description` - Human-readable description
- `recommended_action` - Suggested response

### AnomalyStatistics

Statistics about detection performance.

**Fields:**
- `total_packets_analyzed` - Total packets processed
- `total_anomalies_detected` - Total anomalies found
- `anomaly_rate` - Percentage of anomalous packets
- `anomalies_by_type` - Count by anomaly type
- `anomalies_by_severity` - Count by severity
- `average_anomaly_score` - Mean anomaly score
- `time_range` - Time range of analysis

## Examples

### Detecting Replay Attacks

```python
detector = MLAnomalyDetector()

# Normal traffic pattern
for i in range(50):
    packet = create_normal_packet()
    detector.partial_fit(packet)

# Suspicious repeated packets
repeated_packet = create_packet(data=b"\x01\x02\x03")
for _ in range(5):
    result = detector.detect(repeated_packet)
    if result.is_anomaly:
        print(f"Possible replay attack detected!")
        print(f"Confidence: {result.confidence:.2f}")
```

### Monitoring Signal Strength Anomalies

```python
detector = MLAnomalyDetector()

# Learn normal RSSI pattern
for i in range(50):
    packet = BLEPacket(
        address="AA:BB:CC:DD:EE:FF",
        data=b"\x01\x02\x03",
        rssi=-50 + (i % 10),  # Normal variation
        ...
    )
    detector.partial_fit(packet)

# Detect unusual signal
strong_signal = BLEPacket(..., rssi=-10, ...)  # Unusually strong
result = detector.detect(strong_signal)

if AnomalyType.STATISTICAL in result.anomaly_types:
    print("Unusual signal strength detected!")
```

### Security Monitoring Dashboard

```python
import time
from src.analyzers import AnomalyDetectionEngine

engine = AnomalyDetectionEngine()

# Real-time monitoring loop
while True:
    packet = get_next_ble_packet()
    result = engine.analyze_packet(packet)
    
    if result and result.severity in ['high', 'critical']:
        log_security_event(result)
        send_alert(result)
    
    # Periodic statistics report
    if time.time() % 300 < 1:  # Every 5 minutes
        stats = engine.get_statistics()
        print(f"5-min report: {stats.total_anomalies_detected} anomalies")
    
    time.sleep(0.01)
```

## Best Practices

1. **Training Period**: Allow the detector to learn normal behavior before relying on detections (50-100 packets minimum)

2. **Threshold Tuning**: Adjust `contamination` parameter based on your environment's expected anomaly rate

3. **Alert Management**: Use severity levels to prioritize responses - focus on HIGH and CRITICAL alerts

4. **Context Awareness**: Combine ML detection with domain knowledge and rule-based checks

5. **Continuous Learning**: Keep `update_model=True` for adaptive detection in changing environments

6. **Performance**: For high-throughput scenarios, consider batch processing and larger window sizes

## Limitations

- Requires initial training period for optimal performance
- ML models require scikit-learn installation
- May produce false positives during initial learning phase
- Effectiveness depends on quality and representativeness of training data

## Troubleshooting

### Import Errors
```
ModuleNotFoundError: No module named 'sklearn'
```
**Solution**: Install scikit-learn: `pip install scikit-learn`

### Insufficient Training Data
```
Warning: Insufficient samples for training
```
**Solution**: Process more packets or reduce `min_training_samples`

### High False Positive Rate
**Solution**: 
- Increase `contamination` parameter
- Allow longer training period
- Review and tune detection thresholds

## Contributing

Contributions to improve anomaly detection algorithms, add new features, or enhance performance are welcome!

## License

MIT License - See LICENSE file for details
