"""
ML Anomaly Detection
====================
Isolation Forest-based anomaly detector for network traffic.

Uses lightweight model that can run in near-real-time.
Fallback to rule-based scoring if sklearn not available.

Security:
  - Model loaded once, inference is fast
  - No network calls in hot path
  - Bounded output scores
"""

import logging
from typing import Optional, TYPE_CHECKING
from pathlib import Path
import json

if TYPE_CHECKING:
    from .features import TrafficFeatures

logger = logging.getLogger(__name__)

# Optional sklearn
try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not installed. Using rule-based fallback.")


class AnomalyDetector:
    """
    Isolation Forest anomaly detector.
    
    If sklearn is not available, falls back to rule-based scoring.
    
    Thread Safety: Model is read-only after init, safe for concurrent use.
    """
    
    # Anomaly score thresholds
    THRESHOLD_HIGH = 0.7
    THRESHOLD_CRITICAL = 0.9
    
    def __init__(self, model_path: Optional[Path] = None):
        """
        Initialize detector.
        
        Args:
            model_path: Optional path to pre-trained model.
                       If None, uses untrained model (cold start).
        """
        self.model: Optional["IsolationForest"] = None
        self.is_trained = False
        self.using_fallback = not SKLEARN_AVAILABLE
        
        if SKLEARN_AVAILABLE:
            self._init_model(model_path)
        else:
            logger.info("Using rule-based fallback for anomaly detection")
    
    def _init_model(self, model_path: Optional[Path]):
        """Initialize or load Isolation Forest model."""
        if model_path and model_path.exists():
            try:
                import joblib
                self.model = joblib.load(model_path)
                self.is_trained = True
                logger.info(f"Loaded anomaly model from {model_path}")
            except Exception as e:
                logger.warning(f"Failed to load model: {e}")
                self._create_default_model()
        else:
            self._create_default_model()
    
    def _create_default_model(self):
        """Create default untrained model."""
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,  # Expected 10% anomalies
            random_state=42,
            n_jobs=1,  # Single thread for speed
        )
        self.is_trained = False
    
    def predict(self, features: "TrafficFeatures") -> float:
        """
        Predict anomaly score for features.
        
        Args:
            features: Extracted traffic features
            
        Returns:
            Anomaly score 0.0 (normal) to 1.0 (anomalous)
        """
        if self.using_fallback:
            return self._rule_based_score(features)
        
        if not self.is_trained:
            # Cold start: use rule-based until trained
            return self._rule_based_score(features)
        
        try:
            X = features.to_array().reshape(1, -1)
            
            # IsolationForest returns -1 (anomaly) to +1 (normal)
            raw_score = self.model.decision_function(X)[0]
            
            # Convert to 0-1 range (higher = more anomalous)
            # decision_function: negative = anomaly
            anomaly_score = max(0.0, min(1.0, -raw_score / 0.5 + 0.5))
            
            return anomaly_score
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return self._rule_based_score(features)
    
    def _rule_based_score(self, features: "TrafficFeatures") -> float:
        """
        Fallback rule-based anomaly scoring.
        
        This provides reasonable results without ML training.
        """
        score = 0.0
        
        # High speed ratio is suspicious
        if features.speed_ratio > 1.5:
            score += 0.3
        elif features.speed_ratio > 1.0:
            score += 0.15
        
        # High throttle ratio indicates attack
        if features.throttle_ratio > 0.5:
            score += 0.25
        elif features.throttle_ratio > 0.2:
            score += 0.1
        
        # Burst behavior
        if features.burst_score > 0.7:
            score += 0.2
        
        # Protocol (UDP more suspicious for VRChat crashes)
        if features.protocol_udp > 0.5:
            score += 0.05
        
        # Geo risk
        if features.is_high_risk_country > 0.5:
            score += 0.15
        
        # Hosting/VPS
        if features.is_known_hosting > 0.5:
            score += 0.1
        
        return min(1.0, score)
    
    def train(self, samples: list["TrafficFeatures"]):
        """
        Train model on collected samples.
        
        Call this after collecting baseline traffic.
        """
        if not SKLEARN_AVAILABLE:
            logger.warning("Cannot train: sklearn not available")
            return
        
        if len(samples) < 100:
            logger.warning(f"Need at least 100 samples, got {len(samples)}")
            return
        
        try:
            import numpy as np
            X = np.array([f.to_array() for f in samples])
            
            self.model.fit(X)
            self.is_trained = True
            
            logger.info(f"Model trained on {len(samples)} samples")
            
        except Exception as e:
            logger.error(f"Training failed: {e}")
    
    def save(self, path: Path):
        """Save trained model to file."""
        if not SKLEARN_AVAILABLE or not self.is_trained:
            logger.warning("No trained model to save")
            return
        
        try:
            import joblib
            path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(self.model, path)
            logger.info(f"Model saved to {path}")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
    
    def get_classification(self, score: float) -> str:
        """Get human-readable classification."""
        if score >= self.THRESHOLD_CRITICAL:
            return "CRITICAL"
        elif score >= self.THRESHOLD_HIGH:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        else:
            return "NORMAL"
