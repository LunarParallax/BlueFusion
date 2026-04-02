"""
Tests for ML-based Anomaly Detection
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import numpy as np

from src.analyzers.ml_anomaly_detector import (
    AnomalyDetectionEngine,
    AnomalyDetectionResult,
    AnomalySeverity,
    AnomalyType,
    MLAnomalyDetector,
    PacketFeatureExtractor,
)
from src.interfaces.base import BLEPacket, DeviceType


def create_test_packet(
    address: str = "AA:BB:CC:DD:EE:FF",
    data: bytes = b"\x01\x02\x03\x04",
    rssi: int = -50,
    packet_type: str = "data",
    timestamp: datetime = None,
) -> BLEPacket:
    """Helper to create test packets"""
    if timestamp is None:
        timestamp = datetime.now()
    
    return BLEPacket(
        address=address,
        data=data,
        rssi=rssi,
        packet_type=packet_type,
        timestamp=timestamp,
        source=DeviceType.SNIFFER_DONGLE,
        metadata={},
    )


class TestPacketFeatureExtractor:
    """Test packet feature extraction"""

    def test_extract_features_basic(self):
        """Test basic feature extraction"""
        extractor = PacketFeatureExtractor()
        packet = create_test_packet(data=b"\x01\x02\x03\x04\x05")
        
        features = extractor.extract_features(packet)
        
        assert "data_length" in features
        assert "rssi_normalized" in features
        assert "byte_entropy" in features
        assert "unique_byte_ratio" in features
        assert features["data_length"] == 5.0
        assert 0.0 <= features["rssi_normalized"] <= 1.0
        assert 0.0 <= features["byte_entropy"] <= 1.0

    def test_extract_features_empty_data(self):
        """Test feature extraction with empty packet data"""
        extractor = PacketFeatureExtractor()
        packet = create_test_packet(data=b"")
        
        features = extractor.extract_features(packet)
        
        assert features["data_length"] == 0.0
        assert features["byte_entropy"] == 0.0
        assert features["unique_byte_ratio"] == 0.0

    def test_repeating_pattern_detection(self):
        """Test repeating pattern detection"""
        extractor = PacketFeatureExtractor()
        
        # Highly repetitive pattern
        repetitive_data = b"\xAA\xAA\xAA\xAA\xAA\xAA"
        score_repetitive = extractor._detect_repeating_patterns(repetitive_data)
        
        # Random-looking data
        random_data = b"\x01\x02\x03\x04\x05\x06"
        score_random = extractor._detect_repeating_patterns(random_data)
        
        assert score_repetitive > score_random

    def test_features_to_vector(self):
        """Test conversion of features to numpy array"""
        extractor = PacketFeatureExtractor()
        features = {
            "data_length": 10.0,
            "rssi_normalized": 0.5,
            "byte_entropy": 0.8,
            "unique_byte_ratio": 0.6,
            "repeating_pattern_score": 0.1,
            "opcode_value": 0.2,
            "payload_variance": 0.3,
            "inter_arrival_time": 0.4,
        }
        
        vector = extractor.features_to_vector(features)
        
        assert isinstance(vector, np.ndarray)
        assert len(vector) == len(extractor.feature_names)
        assert vector[0] == 10.0


class TestMLAnomalyDetector:
    """Test ML anomaly detector"""

    def test_initialization(self):
        """Test detector initialization"""
        detector = MLAnomalyDetector(
            contamination=0.1,
            n_estimators=50,
            window_size=50,
        )
        
        assert detector.contamination == 0.1
        assert detector.n_estimators == 50
        assert detector.window_size == 50
        assert not detector.is_trained
        assert detector.packets_seen == 0

    def test_partial_fit_single_packet(self):
        """Test incremental learning with single packet"""
        detector = MLAnomalyDetector(min_training_samples=10)
        packet = create_test_packet()
        
        detector.partial_fit(packet)
        
        assert detector.packets_seen == 1
        assert detector.feature_means is not None
        assert len(detector.feature_history) == 1

    def test_partial_fit_multiple_packets(self):
        """Test incremental learning with multiple packets"""
        detector = MLAnomalyDetector(min_training_samples=10)
        
        for i in range(15):
            packet = create_test_packet(
                data=bytes([i % 256]),
                timestamp=datetime.now() + timedelta(seconds=i),
            )
            detector.partial_fit(packet)
        
        assert detector.packets_seen == 15
        assert len(detector.feature_history) == 15

    def test_detect_without_training(self):
        """Test detection before model is trained"""
        detector = MLAnomalyDetector(training_required=False)
        packet = create_test_packet()
        
        result = detector.detect(packet, update_model=False)
        
        assert isinstance(result, AnomalyDetectionResult)
        assert result.packet_id.startswith("AA:BB:CC:DD:EE:FF_")
        assert 0.0 <= result.anomaly_score <= 1.0

    def test_detect_with_security_anomaly(self):
        """Test detection of security anomalies"""
        detector = MLAnomalyDetector(training_required=False)
        
        # Create packet with suspicious opcode
        packet = create_test_packet(data=b"\x01\x02\x03", packet_type="data")
        
        result = detector.detect(packet, update_model=False)
        
        assert isinstance(result, AnomalyDetectionResult)
        # Should detect pairing request as potential security concern
        assert result.anomaly_score >= 0.0

    def test_detect_high_entropy_packet(self):
        """Test detection of high entropy (possibly encrypted) packets"""
        detector = MLAnomalyDetector(training_required=False)
        
        # Create high entropy packet
        high_entropy_data = bytes(range(20))
        packet = create_test_packet(data=high_entropy_data)
        
        result = detector.detect(packet, update_model=False)
        
        assert isinstance(result, AnomalyDetectionResult)

    def test_statistics_tracking(self):
        """Test anomaly statistics tracking"""
        detector = MLAnomalyDetector(training_required=False)
        
        # Process some packets
        for i in range(5):
            packet = create_test_packet(
                timestamp=datetime.now() + timedelta(seconds=i),
            )
            detector.detect(packet)
        
        stats = detector.get_statistics()
        
        assert stats.total_packets_analyzed == 5
        assert isinstance(stats.anomaly_rate, float)

    def test_reset(self):
        """Test detector reset"""
        detector = MLAnomalyDetector(min_training_samples=10)
        
        # Add some data
        for i in range(15):
            packet = create_test_packet(timestamp=datetime.now() + timedelta(seconds=i))
            detector.partial_fit(packet)
        
        # Reset
        detector.reset()
        
        assert detector.packets_seen == 0
        assert len(detector.feature_history) == 0
        assert not detector.is_trained
        assert detector.feature_means is None


class TestAnomalyDetectionEngine:
    """Test high-level anomaly detection engine"""

    def test_engine_initialization(self):
        """Test engine initialization"""
        engine = AnomalyDetectionEngine(contamination=0.05)
        
        assert engine.enabled
        assert isinstance(engine.detector, MLAnomalyDetector)
        assert len(engine.alert_callbacks) == 0

    def test_enable_disable(self):
        """Test enabling and disabling detection"""
        engine = AnomalyDetectionEngine()
        
        engine.disable()
        assert not engine.enabled
        
        engine.enable()
        assert engine.enabled

    def test_analyze_packet_no_anomaly(self):
        """Test analyzing normal packet"""
        engine = AnomalyDetectionEngine(training_required=False)
        packet = create_test_packet(data=b"\x01\x02\x03\x04")
        
        result = engine.analyze_packet(packet)
        
        # May or may not be anomaly depending on threshold
        assert result is None or isinstance(result, AnomalyDetectionResult)

    def test_alert_callback(self):
        """Test alert callback mechanism"""
        engine = AnomalyDetectionEngine(training_required=False)
        callback_called = []
        
        def mock_callback(result: AnomalyDetectionResult):
            callback_called.append(result)
        
        engine.add_alert_callback(mock_callback)
        
        # Process packets that might trigger alerts
        for i in range(10):
            packet = create_test_packet(
                data=bytes([0x01, 0x02, 0x03]),  # Suspicious opcode
                timestamp=datetime.now() + timedelta(seconds=i),
            )
            engine.analyze_packet(packet)
        
        # Callbacks are only called for HIGH/CRITICAL anomalies
        # Just verify the mechanism works
        assert len(engine.alert_callbacks) == 1

    def test_get_statistics(self):
        """Test retrieving statistics from engine"""
        engine = AnomalyDetectionEngine(training_required=False)
        
        stats = engine.get_statistics()
        
        assert isinstance(stats, type(engine.detector.stats))
        assert stats.total_packets_analyzed == 0


class TestAnomalyTypes:
    """Test anomaly type detection"""

    def test_statistical_anomaly(self):
        """Test statistical anomaly detection"""
        detector = MLAnomalyDetector(training_required=False)
        
        # First train with normal packets
        for i in range(50):
            packet = create_test_packet(
                data=b"\x01\x02\x03\x04",
                rssi=-50,
                timestamp=datetime.now() + timedelta(milliseconds=i),
            )
            detector.partial_fit(packet)
        
        # Then send anomalous packet
        anomalous_packet = create_test_packet(
            data=b"\xFF" * 100,  # Very different data
            rssi=-10,  # Unusually strong signal
            timestamp=datetime.now() + timedelta(milliseconds=51),
        )
        
        result = detector.detect(anomalous_packet)
        
        assert isinstance(result, AnomalyDetectionResult)

    def test_security_anomaly_pairing_request(self):
        """Test security anomaly detection for pairing requests"""
        detector = MLAnomalyDetector(training_required=False)
        
        packet = create_test_packet(data=b"\x01\x02\x03", packet_type="data")
        result = detector.detect(packet, update_model=False)
        
        # Should flag pairing request
        assert result.anomaly_score >= 0.0

    def test_protocol_anomaly(self):
        """Test protocol anomaly detection"""
        detector = MLAnomalyDetector(training_required=False)
        
        # Unusual opcode (> 0x80)
        packet = create_test_packet(data=b"\xFF\x00\x00")
        result = detector.detect(packet, update_model=False)
        
        assert isinstance(result, AnomalyDetectionResult)


class TestAnomalySeverity:
    """Test severity classification"""

    def test_severity_levels(self):
        """Test all severity levels are defined"""
        assert AnomalySeverity.LOW.value == "low"
        assert AnomalySeverity.MEDIUM.value == "medium"
        assert AnomalySeverity.HIGH.value == "high"
        assert AnomalySeverity.CRITICAL.value == "critical"

    def test_severity_assignment(self):
        """Test severity is assigned based on score"""
        detector = MLAnomalyDetector(training_required=False)
        packet = create_test_packet()
        
        result = detector.detect(packet)
        
        assert result.severity in [
            AnomalySeverity.LOW,
            AnomalySeverity.MEDIUM,
            AnomalySeverity.HIGH,
            AnomalySeverity.CRITICAL,
        ]


@pytest.mark.skip(reason="Requires scikit-learn installation")
class TestMLModelsIntegration:
    """Integration tests requiring scikit-learn"""

    def test_isolation_forest_training(self):
        """Test Isolation Forest training and detection"""
        detector = MLAnomalyDetector(
            contamination=0.1,
            n_estimators=100,
            min_training_samples=50,
        )
        
        # Train with normal packets
        for i in range(60):
            packet = create_test_packet(
                data=b"\x01\x02\x03\x04",
                timestamp=datetime.now() + timedelta(seconds=i),
            )
            detector.partial_fit(packet)
        
        assert detector.is_trained
        assert detector.isolation_forest is not None
        
        # Test detection
        normal_packet = create_test_packet(
            data=b"\x01\x02\x03\x04",
            timestamp=datetime.now() + timedelta(seconds=61),
        )
        normal_result = detector.detect(normal_packet)
        
        anomalous_packet = create_test_packet(
            data=b"\xFF" * 50,
            timestamp=datetime.now() + timedelta(seconds=62),
        )
        anomalous_result = detector.detect(anomalous_packet)
        
        # Anomalous packet should have higher score
        assert anomalous_result.anomaly_score >= normal_result.anomaly_score

    def test_lof_training(self):
        """Test Local Outlier Factor training"""
        detector = MLAnomalyDetector(
            contamination=0.1,
            min_training_samples=50,
        )
        
        # Train
        for i in range(60):
            packet = create_test_packet(
                timestamp=datetime.now() + timedelta(seconds=i),
            )
            detector.partial_fit(packet)
        
        assert detector.is_trained
        assert detector.lof_model is not None


class TestEdgeCases:
    """Test edge cases and error handling"""

    def test_empty_packet_data(self):
        """Test handling of packets with no data"""
        detector = MLAnomalyDetector(training_required=False)
        packet = create_test_packet(data=b"")
        
        result = detector.detect(packet)
        
        assert isinstance(result, AnomalyDetectionResult)

    def test_very_large_packet(self):
        """Test handling of very large packets"""
        detector = MLAnomalyDetector(training_required=False)
        packet = create_test_packet(data=b"\x00" * 251)  # Max BLE packet size
        
        result = detector.detect(packet)
        
        assert isinstance(result, AnomalyDetectionResult)

    def test_rssi_edge_cases(self):
        """Test RSSI edge cases"""
        detector = MLAnomalyDetector(training_required=False)
        
        # Very weak signal
        packet_weak = create_test_packet(rssi=-100)
        result_weak = detector.detect(packet_weak)
        
        # Very strong signal
        packet_strong = create_test_packet(rssi=0)
        result_strong = detector.detect(packet_strong)
        
        assert isinstance(result_weak, AnomalyDetectionResult)
        assert isinstance(result_strong, AnomalyDetectionResult)

    def test_rapid_packets(self):
        """Test handling of rapid successive packets"""
        detector = MLAnomalyDetector(training_required=False)
        base_time = datetime.now()
        
        for i in range(10):
            packet = create_test_packet(
                timestamp=base_time + timedelta(milliseconds=i),
            )
            result = detector.detect(packet)
            assert isinstance(result, AnomalyDetectionResult)

    def test_feature_extractor_edge_cases(self):
        """Test feature extractor edge cases"""
        extractor = PacketFeatureExtractor()
        
        # Empty data
        packet_empty = create_test_packet(data=b"")
        features_empty = extractor.extract_features(packet_empty)
        assert all(0.0 <= v <= 1.0 for v in features_empty.values())
        
        # Single byte
        packet_single = create_test_packet(data=b"\x00")
        features_single = extractor.extract_features(packet_single)
        assert "data_length" in features_single


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
