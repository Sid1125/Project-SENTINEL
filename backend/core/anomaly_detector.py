import logging
import numpy as np
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import joblib
import os

logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self, db_session=None):
        self.db = db_session
        self.model = None
        self.is_trained = False
        self.feature_names = [
            'port_count', 'unique_ports', 'avg_port', 'std_port',
            'http_ports', 'https_ports', 'remote_ports', 'common_ports',
            'suspicious_port_count', 'port_variance'
        ]
        self._init_model()
    
    def _init_model(self):
        """Initialize Isolation Forest model"""
        try:
            from sklearn.ensemble import IsolationForest
            self.model = IsolationForest(
                contamination=0.1,
                n_estimators=100,
                max_samples='auto',
                random_state=42,
                n_jobs=-1
            )
            logger.info("Isolation Forest model initialized")
        except ImportError:
            logger.warning("scikit-learn not available, anomaly detection disabled")
            self.model = None
    
    def _extract_features(self, port_data: List[Dict]) -> np.ndarray:
        """Extract features from port scan data"""
        if not port_data:
            return np.zeros(len(self.feature_names))
        
        ports = [p.get('port', 0) for p in port_data]
        
        http_ports = [80, 8080, 8000, 8888, 3000]
        https_ports = [443, 8443, 4443]
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080]
        suspicious_ports = [23, 135, 139, 445, 4444, 5554, 6667, 31337]
        
        features = [
            len(ports),
            len(set(ports)),
            np.mean(ports) if ports else 0,
            np.std(ports) if len(ports) > 1 else 0,
            sum(1 for p in ports if p in http_ports),
            sum(1 for p in ports if p in https_ports),
            sum(1 for p in ports if p > 1024),
            sum(1 for p in ports if p in common_ports),
            sum(1 for p in ports if p in suspicious_ports),
            np.var(ports) if len(ports) > 1 else 0
        ]
        
        return np.array(features).reshape(1, -1)
    
    def train(self, training_data: List[List[Dict]]) -> bool:
        """Train the model on historical port scan data"""
        if self.model is None:
            return False
        
        try:
            X = []
            for port_data in training_data:
                features = self._extract_features(port_data)
                X.append(features[0])
            
            if len(X) < 10:
                logger.warning("Insufficient training data")
                return False
            
            X = np.array(X)
            self.model.fit(X)
            self.is_trained = True
            logger.info(f"Model trained on {len(X)} samples")
            return True
        except Exception as e:
            logger.error(f"Training failed: {e}")
            return False
    
    def predict(self, port_data: List[Dict]) -> Dict[str, Any]:
        """Predict if a device has anomalous port patterns"""
        if self.model is None or not self.is_trained:
            return self._rule_based_analysis(port_data)
        
        try:
            features = self._extract_features(port_data)
            prediction = self.model.predict(features[0].reshape(1, -1))
            score = self.model.score_samples(features[0].reshape(1, -1))[0]
            
            is_anomaly = prediction[0] == -1
            anomaly_score = abs(score)
            
            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': float(anomaly_score),
                'confidence': float(min(anomaly_score * 2, 1.0)),
                'method': 'isolation_forest'
            }
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return self._rule_based_analysis(port_data)
    
    def _rule_based_analysis(self, port_data: List[Dict]) -> Dict[str, Any]:
        """Fallback rule-based anomaly detection"""
        if not port_data:
            return {'is_anomaly': False, 'anomaly_score': 0, 'method': 'rule_based'}
        
        ports = [p.get('port', 0) for p in port_data]
        services = [p.get('service', '').lower() for p in port_data]
        
        score = 0
        flags = []
        
        if 445 in ports:
            score += 30
            flags.append('SMB port open (EternalBlue risk)')
        
        if 3389 in ports:
            score += 25
            flags.append('RDP exposed (BlueKeep risk)')
        
        if 23 in ports:
            score += 20
            flags.append('Telnet exposed')
        
        if 4444 in ports or 5554 in ports:
            score += 40
            flags.append('Metasploit/backdoor ports')
        
        if len([p for p in ports if p > 1024]) > 10:
            score += 15
            flags.append('Many high ports open')
        
        suspicious_services = ['telnet', 'ftp', 'telnetd', 'vsftpd']
        if any(s in services for s in suspicious_services):
            score += 20
            flags.append('Insecure services detected')
        
        return {
            'is_anomaly': score > 40,
            'anomaly_score': min(score / 100, 1.0),
            'flags': flags,
            'method': 'rule_based'
        }
    
    def analyze_device(self, device_ip: str, port_data: List[Dict]) -> Dict[str, Any]:
        """Full analysis for a device"""
        result = self.predict(port_data)
        result['device_ip'] = device_ip
        result['timestamp'] = datetime.utcnow().isoformat()
        result['port_count'] = len(port_data)
        
        if port_data:
            result['ports'] = [p.get('port') for p in port_data]
        
        return result
    
    def get_feature_importance(self) -> List[Dict[str, Any]]:
        """Get feature importance (approximation for Isolation Forest)"""
        return [
            {'feature': name, 'importance': 1.0 / len(self.feature_names)}
            for name in self.feature_names
        ]


anomaly_detector = AnomalyDetector()
