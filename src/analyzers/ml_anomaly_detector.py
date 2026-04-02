"""
ML-Based Anomaly Detection for BLE Packets

This module provides machine learning-powered anomaly detection for BLE traffic analysis.
It uses multiple algorithms including Isolation Forest, Local Outlier Factor, and 
statistical methods to detect unusual patterns in BLE packet data.
"""

import logging
from collections import deque
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from pydantic import BaseModel, Field

from ..interfaces.base import BLEPacket

logger = logging.getLogger(__name__)


class AnomalySeverity(str, Enum):
    """Severity levels for detected anomalies"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnomalyType(str, Enum):
    """Types of anomalies that can be detected"""

    STATISTICAL = "statistical"
    BEHAVIORAL = "behavioral"
    TEMPORAL = "temporal"
    PROTOCOL = "protocol"
    SECURITY = "security"
    PATTERN = "pattern"
    INFORMATION_DISCLOSURE = "information_disclosure"


class AnomalyDetectionResult(BaseModel):
    """Result of anomaly detection for a single packet or sequence"""

    packet_id: str
    timestamp: datetime
    is_anomaly: bool = False
    anomaly_score: float = Field(ge=0.0, le=1.0, default=0.0)
    anomaly_types: List[AnomalyType] = []
    severity: AnomalySeverity = AnomalySeverity.LOW
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    features: Dict[str, float] = {}
    description: str = ""
    recommended_action: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True


class AnomalyStatistics(BaseModel):
    """Statistics about detected anomalies"""

    total_packets_analyzed: int = 0
    total_anomalies_detected: int = 0
    anomaly_rate: float = 0.0
    anomalies_by_type: Dict[str, int] = {}
    anomalies_by_severity: Dict[str, int] = {}
    average_anomaly_score: float = 0.0
    time_range: Optional[Tuple[datetime, datetime]] = None


class PacketFeatureExtractor:
    """Extract numerical features from BLE packets for ML analysis"""

    def __init__(self):
        self.feature_names = [
            "data_length",
            "rssi_normalized",
            "byte_entropy",
            "unique_byte_ratio",
            "repeating_pattern_score",
            "opcode_value",
            "payload_variance",
            "inter_arrival_time",
        ]

    def extract_features(
        self, packet: BLEPacket, previous_timestamp: Optional[datetime] = None
    ) -> Dict[str, float]:
        """
        Extract numerical features from a BLE packet

        Args:
            packet: BLE packet to analyze
            previous_timestamp: Timestamp of previous packet for timing analysis

        Returns:
            Dictionary of feature names to values
        """
        features = {}

        # Data length feature
        data_length = len(packet.data) if packet.data else 0
        features["data_length"] = float(data_length)

        # RSSI normalization (map -100 to 0 range to 0-1)
        rssi_normalized = max(0.0, min(1.0, (packet.rssi + 100) / 100))
        features["rssi_normalized"] = rssi_normalized

        # Byte entropy (measure of randomness)
        if packet.data:
            byte_array = np.frombuffer(packet.data, dtype=np.uint8)
            byte_counts = np.bincount(byte_array, minlength=256)
            probabilities = byte_counts / len(packet.data)
            entropy = -np.sum(
                probabilities * np.log2(probabilities + 1e-10)
            )
            # Normalize entropy (max entropy for bytes is 8 bits)
            features["byte_entropy"] = entropy / 8.0
        else:
            features["byte_entropy"] = 0.0

        # Unique byte ratio
        if packet.data:
            unique_bytes = len(set(packet.data))
            features["unique_byte_ratio"] = unique_bytes / min(len(packet.data), 256)
        else:
            features["unique_byte_ratio"] = 0.0

        # Repeating pattern detection
        if packet.data and len(packet.data) >= 4:
            repeating_score = self._detect_repeating_patterns(packet.data)
            features["repeating_pattern_score"] = repeating_score
        else:
            features["repeating_pattern_score"] = 0.0

        # Opcode value (first byte)
        if packet.data:
            features["opcode_value"] = float(packet.data[0]) / 255.0
        else:
            features["opcode_value"] = 0.0

        # Payload variance
        if packet.data and len(packet.data) > 1:
            byte_array = np.frombuffer(packet.data, dtype=np.uint8)
            features["payload_variance"] = float(np.var(byte_array)) / 255.0
        else:
            features["payload_variance"] = 0.0

        # Inter-arrival time
        if previous_timestamp:
            delta = (packet.timestamp - previous_timestamp).total_seconds()
            # Cap at 10 seconds and normalize
            delta = min(delta, 10.0)
            features["inter_arrival_time"] = delta / 10.0
        else:
            features["inter_arrival_time"] = 0.0

        return features

    def _detect_repeating_patterns(self, data: bytes, max_pattern_length: int = 8) -> float:
        """
        Detect repeating byte patterns in data
        
        Returns a score from 0 (no repetition) to 1 (highly repetitive)
        """
        if len(data) < 4:
            return 0.0

        max_score = 0.0
        for pattern_len in range(2, min(max_pattern_length + 1, len(data) // 2)):
            pattern = data[:pattern_len]
            occurrences = 0
            for i in range(0, len(data) - pattern_len + 1, pattern_len):
                if data[i : i + pattern_len] == pattern:
                    occurrences += 1
            
            if occurrences > 1:
                score = (occurrences * pattern_len) / len(data)
                max_score = max(max_score, min(score, 1.0))

        return max_score

    def features_to_vector(self, features: Dict[str, float]) -> np.ndarray:
        """Convert feature dictionary to numpy array in consistent order"""
        return np.array([features.get(name, 0.0) for name in self.feature_names])


class MLAnomalyDetector:
    """
    Machine Learning-based anomaly detector for BLE packets
    
    Uses ensemble of methods:
    - Isolation Forest for outlier detection
    - Local Outlier Factor for density-based anomalies
    - Statistical z-score analysis
    - Rule-based security checks
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 100,
        window_size: int = 100,
        training_required: bool = True,
        min_training_samples: int = 50,
    ):
        """
        Initialize the ML anomaly detector

        Args:
            contamination: Expected proportion of anomalies in data (0-0.5)
            n_estimators: Number of estimators for Isolation Forest
            window_size: Size of sliding window for recent packet analysis
            training_required: Whether model must be trained before detection
            min_training_samples: Minimum samples required before training models
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.window_size = window_size
        self.training_required = training_required
        self.min_training_samples = min_training_samples

        self.feature_extractor = PacketFeatureExtractor()
        
        # Feature history for context-aware detection
        self.feature_history: deque = deque(maxlen=window_size)
        self.timestamp_history: deque = deque(maxlen=window_size)
        
        # ML models (initialized on first fit)
        self.isolation_forest = None
        self.lof_model = None
        
        # Statistical baselines
        self.feature_means: Optional[np.ndarray] = None
        self.feature_stds: Optional[np.ndarray] = None
        
        # Training state
        self.is_trained = False
        self.packets_seen = 0
        self.min_training_samples = 50

        # Anomaly statistics
        self.stats = AnomalyStatistics()

    def partial_fit(self, packet: BLEPacket) -> None:
        """
        Incrementally update the model with a new packet
        
        This allows online learning without full retraining

        Args:
            packet: BLE packet to learn from
        """
        try:
            prev_timestamp = (
                self.timestamp_history[-1] if self.timestamp_history else None
            )
            features = self.feature_extractor.extract_features(packet, prev_timestamp)
            feature_vector = self.feature_extractor.features_to_vector(features)

            # Update history
            self.feature_history.append(feature_vector)
            self.timestamp_history.append(packet.timestamp)

            # Update running statistics
            if self.feature_means is None:
                self.feature_means = feature_vector.copy()
                self.feature_stds = np.zeros_like(feature_vector)
            else:
                # Online mean and std update
                n = len(self.feature_history)
                delta = feature_vector - self.feature_means
                self.feature_means += delta / n
                if n > 1:
                    self.feature_stds = np.std(list(self.feature_history), axis=0)

            self.packets_seen += 1

            # Retrain models periodically
            if (
                not self.is_trained
                and len(self.feature_history) >= self.min_training_samples
            ):
                self._train_models()

        except Exception as e:
            logger.error(f"Error in partial_fit: {e}")

    def _train_models(self) -> None:
        """Train ML models on accumulated feature history"""
        try:
            if len(self.feature_history) < self.min_training_samples:
                logger.warning("Insufficient samples for training")
                return

            X = np.array(list(self.feature_history))

            # Train Isolation Forest
            try:
                from sklearn.ensemble import IsolationForest

                self.isolation_forest = IsolationForest(
                    n_estimators=self.n_estimators,
                    contamination=self.contamination,
                    random_state=42,
                    n_jobs=-1,
                )
                self.isolation_forest.fit(X)
                logger.info("Isolation Forest trained successfully")
            except ImportError:
                logger.warning("scikit-learn not available, skipping Isolation Forest")

            # Train Local Outlier Factor
            try:
                from sklearn.neighbors import LocalOutlierFactor

                n_neighbors = min(20, len(X) - 1)
                self.lof_model = LocalOutlierFactor(
                    n_neighbors=n_neighbors,
                    contamination=self.contamination,
                    novelty=True,
                    n_jobs=-1,
                )
                self.lof_model.fit(X)
                logger.info("Local Outlier Factor trained successfully")
            except ImportError:
                logger.warning("scikit-learn not available, skipping LOF")

            self.is_trained = True
            logger.info(f"ML models trained on {len(X)} samples")

        except Exception as e:
            logger.error(f"Error training models: {e}")

    def detect(
        self, packet: BLEPacket, update_model: bool = True
    ) -> AnomalyDetectionResult:
        """
        Detect anomalies in a BLE packet

        Args:
            packet: BLE packet to analyze
            update_model: Whether to update model with this packet

        Returns:
            AnomalyDetectionResult with analysis
        """
        # Generate packet ID
        packet_id = f"{packet.address}_{packet.timestamp.timestamp()}"

        # Extract features
        prev_timestamp = self.timestamp_history[-1] if self.timestamp_history else None
        features = self.feature_extractor.extract_features(packet, prev_timestamp)
        feature_vector = self.feature_extractor.features_to_vector(features)

        # Initialize result
        result = AnomalyDetectionResult(
            packet_id=packet_id,
            timestamp=packet.timestamp,
            features=features,
        )

        # Collect anomaly scores from different methods
        anomaly_scores = []
        anomaly_types = []

        # 1. Statistical analysis (z-score)
        if self.feature_means is not None and self.feature_stds is not None:
            stat_score, stat_anomalies = self._statistical_anomaly_detection(
                feature_vector, features
            )
            anomaly_scores.append(stat_score)
            anomaly_types.extend(stat_anomalies)

        # 2. Isolation Forest
        if self.is_trained and self.isolation_forest is not None:
            try:
                iso_score = self._isolation_forest_detection(feature_vector)
                anomaly_scores.append(iso_score)
                if iso_score > 0.5:
                    anomaly_types.append(AnomalyType.BEHAVIORAL)
            except Exception as e:
                logger.debug(f"Isolation Forest error: {e}")

        # 3. Local Outlier Factor
        if self.is_trained and self.lof_model is not None:
            try:
                lof_score = self._lof_detection(feature_vector)
                anomaly_scores.append(lof_score)
                if lof_score > 0.5:
                    anomaly_types.append(AnomalyType.PATTERN)
            except Exception as e:
                logger.debug(f"LOF error: {e}")

        # 4. Security rule-based checks
        security_score, security_anomalies = self._security_anomaly_detection(packet)
        if security_score > 0:
            anomaly_scores.append(security_score)
            anomaly_types.extend(security_anomalies)

        # Combine scores
        if anomaly_scores:
            combined_score = np.mean(anomaly_scores)
            result.anomaly_score = float(np.clip(combined_score, 0.0, 1.0))
            result.anomaly_types = list(set(anomaly_types))
            result.is_anomaly = result.anomaly_score > 0.5

            # Determine severity
            if result.anomaly_score > 0.9:
                result.severity = AnomalySeverity.CRITICAL
            elif result.anomaly_score > 0.7:
                result.severity = AnomalySeverity.HIGH
            elif result.anomaly_score > 0.5:
                result.severity = AnomalySeverity.MEDIUM
            else:
                result.severity = AnomalySeverity.LOW

            # Confidence based on number of agreeing methods
            result.confidence = min(1.0, len(anomaly_scores) / 4.0)

            # Generate description
            result.description = self._generate_description(result)

            # Recommend action
            result.recommended_action = self._recommend_action(result)

            # Update statistics
            self._update_statistics(result)

        # Update model with new packet
        if update_model:
            self.partial_fit(packet)

        return result

    def _statistical_anomaly_detection(
        self, feature_vector: np.ndarray, features: Dict[str, float]
    ) -> Tuple[float, List[AnomalyType]]:
        """Detect anomalies using statistical z-scores"""
        anomalies = []
        max_zscore = 0.0

        # Calculate z-scores
        with np.errstate(divide="ignore", invalid="ignore"):
            zscores = np.abs((feature_vector - self.feature_means) / (self.feature_stds + 1e-10))

        # Check individual features
        if zscores[0] > 3.0:  # Data length
            anomalies.append(AnomalyType.STATISTICAL)
            max_zscore = max(max_zscore, zscores[0] / 5.0)

        if zscores[1] > 3.0:  # RSSI
            anomalies.append(AnomalyType.STATISTICAL)
            max_zscore = max(max_zscore, zscores[1] / 5.0)

        if zscores[2] > 3.0:  # Entropy
            anomalies.append(AnomalyType.STATISTICAL)
            max_zscore = max(max_zscore, zscores[2] / 5.0)

        return min(max_zscore, 1.0), list(set(anomalies))

    def _isolation_forest_detection(self, feature_vector: np.ndarray) -> float:
        """Detect anomalies using Isolation Forest"""
        if self.isolation_forest is None:
            return 0.0

        # Get anomaly score (-1 for outliers, 1 for inliers)
        prediction = self.isolation_forest.predict([feature_vector])[0]
        score = self.isolation_forest.score_samples([feature_vector])[0]

        # Convert to 0-1 range (higher = more anomalous)
        if prediction == -1:
            # Outlier detected
            normalized_score = 0.5 + 0.5 * (1.0 + score)
        else:
            # Inlier
            normalized_score = 0.5 * (1.0 + score)

        return float(np.clip(normalized_score, 0.0, 1.0))

    def _lof_detection(self, feature_vector: np.ndarray) -> float:
        """Detect anomalies using Local Outlier Factor"""
        if self.lof_model is None:
            return 0.0

        # LOF returns negative scores for outliers
        score = self.lof_model.score_samples([feature_vector])[0]

        # Convert to 0-1 range
        # More negative = more anomalous
        normalized_score = 1.0 / (1.0 + np.exp(score))

        return float(np.clip(normalized_score, 0.0, 1.0))

    def _security_anomaly_detection(
        self, packet: BLEPacket
    ) -> Tuple[float, List[AnomalyType]]:
        """Rule-based security anomaly detection"""
        anomalies = []
        score = 0.0

        if not packet.data:
            return 0.0, []

        # Check for known malicious patterns
        # Pairing requests from unknown devices
        if packet.data[0] == 0x01 and packet.packet_type != "advertisement":
            anomalies.append(AnomalyType.SECURITY)
            score += 0.3

        # Unusual opcodes
        if packet.data[0] > 0x80:
            anomalies.append(AnomalyType.PROTOCOL)
            score += 0.2

        # Very high entropy in small packets (possible encryption attack)
        if len(packet.data) < 20:
            byte_array = np.frombuffer(packet.data, dtype=np.uint8)
            byte_counts = np.bincount(byte_array, minlength=256)
            probabilities = byte_counts / len(packet.data)
            entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
            if entropy > 7.5:  # Very high entropy
                anomalies.append(AnomalyType.SECURITY)
                score += 0.4

        # Repeated identical packets (possible replay attack)
        if len(self.feature_history) > 5:
            recent_vectors = list(self.feature_history)[-5:]
            current_vector = self.feature_extractor.features_to_vector(
                self.feature_extractor.extract_features(packet)
            )
            matches = sum(
                np.allclose(current_vector, v, rtol=0.01) for v in recent_vectors
            )
            if matches >= 4:
                anomalies.append(AnomalyType.SECURITY)
                score += 0.5

        return min(score, 1.0), list(set(anomalies))

    def _generate_description(self, result: AnomalyDetectionResult) -> str:
        """Generate human-readable description of anomaly"""
        descriptions = []

        if AnomalyType.STATISTICAL in result.anomaly_types:
            descriptions.append("Statistical deviation from normal behavior")

        if AnomalyType.BEHAVIORAL in result.anomaly_types:
            descriptions.append("Behavioral pattern differs from learned norms")

        if AnomalyType.SECURITY in result.anomaly_types:
            descriptions.append("Potential security concern detected")

        if AnomalyType.PROTOCOL in result.anomaly_types:
            descriptions.append("Unusual protocol usage")

        if AnomalyType.PATTERN in result.anomaly_types:
            descriptions.append("Pattern inconsistent with historical data")

        if not descriptions:
            return "Minor deviation detected"

        return "; ".join(descriptions)

    def _recommend_action(self, result: AnomalyDetectionResult) -> Optional[str]:
        """Recommend action based on anomaly type and severity"""
        if result.severity == AnomalySeverity.CRITICAL:
            return "Immediate investigation recommended. Consider blocking source."
        elif result.severity == AnomalySeverity.HIGH:
            if AnomalyType.SECURITY in result.anomaly_types:
                return "Review security logs and verify device authenticity."
            else:
                return "Investigate unusual behavior pattern."
        elif result.severity == AnomalySeverity.MEDIUM:
            return "Monitor for recurring anomalies."
        else:
            return None

    def _update_statistics(self, result: AnomalyDetectionResult) -> None:
        """Update anomaly statistics"""
        self.stats.total_packets_analyzed += 1

        if result.is_anomaly:
            self.stats.total_anomalies_detected += 1
            self.stats.anomaly_rate = (
                self.stats.total_anomalies_detected
                / self.stats.total_packets_analyzed
            )

            # Update by type
            for anomaly_type in result.anomaly_types:
                key = anomaly_type.value
                self.stats.anomalies_by_type[key] = (
                    self.stats.anomalies_by_type.get(key, 0) + 1
                )

            # Update by severity
            severity_key = result.severity.value
            self.stats.anomalies_by_severity[severity_key] = (
                self.stats.anomalies_by_severity.get(severity_key, 0) + 1
            )

            # Update average score
            n = self.stats.total_anomalies_detected
            self.stats.average_anomaly_score = (
                (self.stats.average_anomaly_score * (n - 1) + result.anomaly_score) / n
            )

            # Update time range
            if self.stats.time_range is None:
                self.stats.time_range = (result.timestamp, result.timestamp)
            else:
                self.stats.time_range = (
                    self.stats.time_range[0],
                    result.timestamp,
                )

    def get_statistics(self) -> AnomalyStatistics:
        """Get current anomaly detection statistics"""
        return self.stats

    def reset(self) -> None:
        """Reset detector state and retrain models"""
        self.feature_history.clear()
        self.timestamp_history.clear()
        self.is_trained = False
        self.packets_seen = 0
        self.feature_means = None
        self.feature_stds = None
        self.stats = AnomalyStatistics()
        logger.info("Anomaly detector reset")


class AnomalyDetectionEngine:
    """
    High-level interface for ML-based anomaly detection
    
    Integrates with PacketInspector to provide seamless anomaly detection
    """

    def __init__(self, **detector_kwargs):
        """
        Initialize anomaly detection engine

        Args:
            **detector_kwargs: Arguments passed to MLAnomalyDetector
        """
        self.detector = MLAnomalyDetector(**detector_kwargs)
        self.enabled = True
        self.alert_callbacks = []

    def enable(self) -> None:
        """Enable anomaly detection"""
        self.enabled = True
        logger.info("Anomaly detection enabled")

    def disable(self) -> None:
        """Disable anomaly detection"""
        self.enabled = False
        logger.info("Anomaly detection disabled")

    def add_alert_callback(self, callback) -> None:
        """
        Add callback function for anomaly alerts

        Callback signature: callback(result: AnomalyDetectionResult)
        """
        self.alert_callbacks.append(callback)

    def analyze_packet(self, packet: BLEPacket) -> Optional[AnomalyDetectionResult]:
        """
        Analyze a packet for anomalies

        Args:
            packet: BLE packet to analyze

        Returns:
            AnomalyDetectionResult if anomaly detected, None otherwise
        """
        if not self.enabled:
            return None

        result = self.detector.detect(packet)

        # Trigger alerts for significant anomalies
        if result.is_anomaly and result.severity in [
            AnomalySeverity.HIGH,
            AnomalySeverity.CRITICAL,
        ]:
            for callback in self.alert_callbacks:
                try:
                    callback(result)
                except Exception as e:
                    logger.error(f"Alert callback error: {e}")

        return result if result.is_anomaly else None

    def get_statistics(self) -> AnomalyStatistics:
        """Get detection statistics"""
        return self.detector.get_statistics()

    def reset(self) -> None:
        """Reset detector"""
        self.detector.reset()
