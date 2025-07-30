
import asyncio
import json
import logging
import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
import hashlib
import ipaddress
import socket
import struct
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import hmac
import secrets
from pathlib import Path

# External dependencies (would be installed via pip)
try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    import joblib
except ImportError:
    print("Installing required ML libraries...")
    # In production, these would be pre-installed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/cyberguard_firewall.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('CyberGuardFirewall')

class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class Action(Enum):
    """Firewall actions"""
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    QUARANTINE = "quarantine"
    LOG = "log"

class Protocol(Enum):
    """Network protocols"""
    TCP = 6
    UDP = 17
    ICMP = 1
    HTTP = 80
    HTTPS = 443
    SSH = 22
    DNS = 53

@dataclass
class NetworkPacket:
    """Network packet representation"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    payload: bytes
    timestamp: float
    size: int
    flags: str = ""
    session_id: str = ""

@dataclass
class ThreatEvent:
    """Security threat event"""
    event_id: str
    timestamp: float
    threat_type: str
    severity: ThreatLevel
    source_ip: str
    destination_ip: str
    description: str
    confidence: float
    mitigation_action: Action
    additional_data: Dict[str, Any] = None

@dataclass
class FirewallRule:
    """Firewall rule definition"""
    rule_id: str
    priority: int
    source_ip: str
    destination_ip: str
    source_port: str
    destination_port: str
    protocol: str
    action: Action
    enabled: bool = True
    description: str = ""
    created_at: float = 0.0
    ai_generated: bool = False

class AIThreatDetector:
    """AI-powered threat detection engine"""
    
    def __init__(self):
        self.anomaly_detector = None
        self.threat_classifier = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_columns = [
            'packet_size', 'port_entropy', 'flow_duration', 
            'packets_per_second', 'bytes_per_second', 'protocol_anomaly',
            'geographic_risk', 'reputation_score', 'behavioral_score'
        ]
        
    def initialize_models(self):
        """Initialize AI models"""
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=200
        )
        self.threat_classifier = RandomForestClassifier(
            n_estimators=300,
            max_depth=15,
            random_state=42
        )
        logger.info("AI models initialized")
    
    def extract_features(self, packet: NetworkPacket, flow_data: Dict) -> np.ndarray:
        """Extract features from network packet and flow data"""
        features = {
            'packet_size': packet.size,
            'port_entropy': self._calculate_port_entropy(flow_data.get('ports', [])),
            'flow_duration': flow_data.get('duration', 0),
            'packets_per_second': flow_data.get('pps', 0),
            'bytes_per_second': flow_data.get('bps', 0),
            'protocol_anomaly': self._detect_protocol_anomaly(packet),
            'geographic_risk': self._get_geographic_risk(packet.src_ip),
            'reputation_score': self._get_reputation_score(packet.src_ip),
            'behavioral_score': flow_data.get('behavioral_score', 0.5)
        }
        return np.array([[features[col] for col in self.feature_columns]])
    
    def _calculate_port_entropy(self, ports: List[int]) -> float:
        """Calculate entropy of port usage"""
        if not ports:
            return 0.0
        port_counts = defaultdict(int)
        for port in ports:
            port_counts[port] += 1
        total = len(ports)
        entropy = 0.0
        for count in port_counts.values():
            p = count / total
            if p > 0:
                entropy -= p * np.log2(p)
        return entropy
    
    def _detect_protocol_anomaly(self, packet: NetworkPacket) -> float:
        """Detect protocol-level anomalies"""
        anomaly_score = 0.0
        
        # Check for unusual port combinations
        if packet.protocol == Protocol.TCP.value:
            if packet.dst_port in [22, 23, 3389] and packet.src_port < 1024:
                anomaly_score += 0.3
        
        # Check for suspicious payload patterns
        if packet.payload:
            if b'\x90' * 10 in packet.payload:  # NOP sled detection
                anomaly_score += 0.5
            if re.search(rb'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\xff]{20,}', packet.payload):
                anomaly_score += 0.3
        
        return min(anomaly_score, 1.0)
    
    def _get_geographic_risk(self, ip: str) -> float:
        """Get geographic risk score for IP"""
        # Simplified geographic risk assessment
        private_ranges = [
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16')
        ]
        
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            for network in private_ranges:
                if ip_obj in network:
                    return 0.1  # Low risk for private IPs
        except:
            pass
        
        # In production, this would query GeoIP databases
        return 0.5  # Default medium risk
    
    def _get_reputation_score(self, ip: str) -> float:
        """Get IP reputation score"""
        # Simplified reputation scoring
        # In production, this would query threat intelligence feeds
        known_bad_patterns = [
            r'^192\.168\.1\.666$',  # Example malicious IP pattern
            r'^10\.0\.0\.1$'        # Another example
        ]
        
        for pattern in known_bad_patterns:
            if re.match(pattern, ip):
                return 0.9  # High threat score
        
        return 0.1  # Default low threat score
    
    def detect_anomaly(self, packet: NetworkPacket, flow_data: Dict) -> Tuple[bool, float]:
        """Detect anomalies in network traffic"""
        if not self.is_trained:
            return False, 0.0
        
        features = self.extract_features(packet, flow_data)
        scaled_features = self.scaler.transform(features)
        
        anomaly_score = self.anomaly_detector.decision_function(scaled_features)[0]
        is_anomaly = self.anomaly_detector.predict(scaled_features)[0] == -1
        
        # Convert to confidence score (0-1)
        confidence = max(0, min(1, (anomaly_score + 0.5) * 2))
        
        return is_anomaly, confidence
    
    def classify_threat(self, packet: NetworkPacket, flow_data: Dict) -> Tuple[str, float]:
        """Classify threat type"""
        if not self.is_trained:
            return "unknown", 0.0
        
        features = self.extract_features(packet, flow_data)
        scaled_features = self.scaler.transform(features)
        
        threat_proba = self.threat_classifier.predict_proba(scaled_features)[0]
        threat_classes = self.threat_classifier.classes_
        
        max_idx = np.argmax(threat_proba)
        threat_type = threat_classes[max_idx]
        confidence = threat_proba[max_idx]
        
        return threat_type, confidence
    
    def train_models(self, training_data: pd.DataFrame):
        """Train AI models with historical data"""
        logger.info("Training AI models...")
        
        if training_data.empty:
            # Generate synthetic training data for demo
            training_data = self._generate_synthetic_data()
        
        X = training_data[self.feature_columns]
        y_anomaly = training_data['is_anomaly']
        y_threat = training_data['threat_type']
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train anomaly detector
        self.anomaly_detector.fit(X_scaled[y_anomaly == 0])  # Train on normal data
        
        # Train threat classifier
        self.threat_classifier.fit(X_scaled, y_threat)
        
        self.is_trained = True
        logger.info("AI models trained successfully")
    
    def _generate_synthetic_data(self) -> pd.DataFrame:
        """Generate synthetic training data for demonstration"""
        np.random.seed(42)
        n_samples = 10000
        
        data = {
            'packet_size': np.random.lognormal(6, 1, n_samples),
            'port_entropy': np.random.beta(2, 5, n_samples),
            'flow_duration': np.random.exponential(10, n_samples),
            'packets_per_second': np.random.gamma(2, 10, n_samples),
            'bytes_per_second': np.random.gamma(3, 1000, n_samples),
            'protocol_anomaly': np.random.beta(1, 10, n_samples),
            'geographic_risk': np.random.beta(2, 3, n_samples),
            'reputation_score': np.random.beta(1, 9, n_samples),
            'behavioral_score': np.random.beta(3, 3, n_samples),
        }
        
        # Generate labels
        anomaly_threshold = 0.9
        is_anomaly = []
        threat_types = []
        
        for i in range(n_samples):
            # Simple rule-based labeling for synthetic data
            anomaly_score = (
                data['protocol_anomaly'][i] * 0.3 +
                data['reputation_score'][i] * 0.4 +
                (1 - data['behavioral_score'][i]) * 0.3
            )
            
            is_anom = anomaly_score > anomaly_threshold
            is_anomaly.append(1 if is_anom else 0)
            
            if is_anom:
                if data['reputation_score'][i] > 0.8:
                    threat_types.append('malware')
                elif data['protocol_anomaly'][i] > 0.7:
                    threat_types.append('intrusion')
                else:
                    threat_types.append('suspicious')
            else:
                threat_types.append('benign')
        
        data['is_anomaly'] = is_anomaly
        data['threat_type'] = threat_types
        
        return pd.DataFrame(data)

class FlowTracker:
    """Network flow tracking and analysis"""
    
    def __init__(self, timeout: int = 300):
        self.flows = {}
        self.timeout = timeout
        self.lock = threading.Lock()
    
    def get_flow_key(self, packet: NetworkPacket) -> str:
        """Generate flow key from packet"""
        return f"{packet.src_ip}:{packet.src_port}-{packet.dst_ip}:{packet.dst_port}-{packet.protocol}"
    
    def update_flow(self, packet: NetworkPacket) -> Dict:
        """Update flow statistics"""
        flow_key = self.get_flow_key(packet)
        
        with self.lock:
            if flow_key not in self.flows:
                self.flows[flow_key] = {
                    'start_time': packet.timestamp,
                    'last_seen': packet.timestamp,
                    'packet_count': 0,
                    'byte_count': 0,
                    'ports': set(),
                    'behavioral_score': 0.5
                }
            
            flow = self.flows[flow_key]
            flow['last_seen'] = packet.timestamp
            flow['packet_count'] += 1
            flow['byte_count'] += packet.size
            flow['ports'].add(packet.dst_port)
            
            # Calculate derived metrics
            duration = packet.timestamp - flow['start_time']
            flow['duration'] = duration
            flow['pps'] = flow['packet_count'] / max(duration, 0.001)
            flow['bps'] = flow['byte_count'] / max(duration, 0.001)
            
            # Update behavioral score based on flow characteristics
            flow['behavioral_score'] = self._calculate_behavioral_score(flow)
            
            return flow.copy()
    
    def _calculate_behavioral_score(self, flow: Dict) -> float:
        """Calculate behavioral score for flow"""
        score = 0.5  # Baseline
        
        # Adjust based on flow characteristics
        if flow['pps'] > 1000:  # High packet rate
            score += 0.2
        if len(flow['ports']) > 10:  # Port scanning behavior
            score += 0.3
        if flow['duration'] > 3600:  # Long duration flows
            score -= 0.1
        
        return max(0.0, min(1.0, score))
    
    def cleanup_expired_flows(self):
        """Remove expired flows"""
        current_time = time.time()
        expired_keys = []
        
        with self.lock:
            for key, flow in self.flows.items():
                if current_time - flow['last_seen'] > self.timeout:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.flows[key]
        
        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired flows")

class PolicyEngine:
    """Firewall policy management engine"""
    
    def __init__(self):
        self.rules = []
        self.rule_cache = {}
        self.lock = threading.Lock()
        self.load_default_rules()
    
    def load_default_rules(self):
        """Load default firewall rules"""
        default_rules = [
            FirewallRule(
                rule_id="default_allow_out",
                priority=1000,
                source_ip="any",
                destination_ip="any",
                source_port="any",
                destination_port="any",
                protocol="any",
                action=Action.ALLOW,
                description="Default allow outbound"
            ),
            FirewallRule(
                rule_id="block_suspicious",
                priority=100,
                source_ip="any",
                destination_ip="any",
                source_port="any",
                destination_port="any",
                protocol="any",
                action=Action.DENY,
                description="Block suspicious traffic",
                ai_generated=True
            ),
            FirewallRule(
                rule_id="allow_http",
                priority=200,
                source_ip="any",
                destination_ip="any",
                source_port="any",
                destination_port="80,443",
                protocol="tcp",
                action=Action.ALLOW,
                description="Allow HTTP/HTTPS"
            ),
            FirewallRule(
                rule_id="allow_dns",
                priority=200,
                source_ip="any",
                destination_ip="any",
                source_port="any",
                destination_port="53",
                protocol="udp",
                action=Action.ALLOW,
                description="Allow DNS"
            )
        ]
        
        with self.lock:
            self.rules = sorted(default_rules, key=lambda r: r.priority)
        
        logger.info(f"Loaded {len(default_rules)} default rules")
    
    def add_rule(self, rule: FirewallRule) -> bool:
        """Add new firewall rule"""
        with self.lock:
            # Check for duplicate rule IDs
            if any(r.rule_id == rule.rule_id for r in self.rules):
                return False
            
            rule.created_at = time.time()
            self.rules.append(rule)
            self.rules.sort(key=lambda r: r.priority)
            self.rule_cache.clear()  # Clear cache
        
        logger.info(f"Added rule: {rule.rule_id}")
        return True
    
    def evaluate_packet(self, packet: NetworkPacket, threat_info: Dict = None) -> Tuple[Action, str]:
        """Evaluate packet against firewall rules"""
        cache_key = f"{packet.src_ip}:{packet.dst_ip}:{packet.dst_port}:{packet.protocol}"
        
        # Check cache first
        if cache_key in self.rule_cache:
            cached_result = self.rule_cache[cache_key]
            if time.time() - cached_result['timestamp'] < 60:  # 1-minute cache
                return cached_result['action'], cached_result['rule_id']
        
        with self.lock:
            for rule in self.rules:
                if not rule.enabled:
                    continue
                
                if self._rule_matches(rule, packet, threat_info):
                    # Cache result
                    self.rule_cache[cache_key] = {
                        'action': rule.action,
                        'rule_id': rule.rule_id,
                        'timestamp': time.time()
                    }
                    return rule.action, rule.rule_id
        
        # Default action if no rules match
        return Action.DENY, "default_deny"
    
    def _rule_matches(self, rule: FirewallRule, packet: NetworkPacket, threat_info: Dict = None) -> bool:
        """Check if rule matches packet"""
        # Source IP matching
        if not self._ip_matches(rule.source_ip, packet.src_ip):
            return False
        
        # Destination IP matching
        if not self._ip_matches(rule.destination_ip, packet.dst_ip):
            return False
        
        # Protocol matching
        if rule.protocol != "any" and rule.protocol != str(packet.protocol):
            return False
        
        # Port matching
        if not self._port_matches(rule.destination_port, packet.dst_port):
            return False
        
        # AI-generated rules may have additional threat-based conditions
        if rule.ai_generated and threat_info:
            if threat_info.get('confidence', 0) < 0.7:
                return False
        
        return True
    
    def _ip_matches(self, rule_ip: str, packet_ip: str) -> bool:
        """Check if IP matches rule"""
        if rule_ip == "any":
            return True
        
        try:
            if '/' in rule_ip:  # CIDR notation
                network = ipaddress.IPv4Network(rule_ip, strict=False)
                return ipaddress.IPv4Address(packet_ip) in network
            else:
                return rule_ip == packet_ip
        except:
            return False
    
    def _port_matches(self, rule_port: str, packet_port: int) -> bool:
        """Check if port matches rule"""
        if rule_port == "any":
            return True
        
        # Handle port ranges and lists
        if ',' in rule_port:
            ports = [p.strip() for p in rule_port.split(',')]
            return any(self._port_matches(p, packet_port) for p in ports)
        
        if '-' in rule_port:
            start, end = map(int, rule_port.split('-'))
            return start <= packet_port <= end
        
        try:
            return int(rule_port) == packet_port
        except:
            return False

class IncidentResponseEngine:
    """Automated incident response and mitigation"""
    
    def __init__(self):
        self.response_playbooks = {}
        self.active_incidents = {}
        self.quarantine_list = set()
        self.lock = threading.Lock()
        self.setup_playbooks()
    
    def setup_playbooks(self):
        """Setup incident response playbooks"""
        self.response_playbooks = {
            'malware': {
                'actions': ['quarantine_ip', 'block_traffic', 'alert_admin'],
                'escalation_time': 300,  # 5 minutes
                'auto_resolve': False
            },
            'intrusion': {
                'actions': ['block_traffic', 'collect_forensics', 'alert_admin'],
                'escalation_time': 180,  # 3 minutes
                'auto_resolve': False
            },
            'suspicious': {
                'actions': ['monitor_closely', 'log_enhanced'],
                'escalation_time': 600,  # 10 minutes
                'auto_resolve': True
            },
            'anomaly': {
                'actions': ['log_event', 'monitor_closely'],
                'escalation_time': 900,  # 15 minutes
                'auto_resolve': True
            }
        }
    
    def handle_threat(self, threat_event: ThreatEvent) -> List[str]:
        """Handle detected threat event"""
        playbook = self.response_playbooks.get(threat_event.threat_type, {})
        actions_taken = []
        
        with self.lock:
            # Record incident
            self.active_incidents[threat_event.event_id] = {
                'event': threat_event,
                'start_time': time.time(),
                'actions_taken': [],
                'status': 'active'
            }
        
        # Execute playbook actions
        for action in playbook.get('actions', []):
            try:
                success = self._execute_action(action, threat_event)
                if success:
                    actions_taken.append(action)
                    
                    with self.lock:
                        self.active_incidents[threat_event.event_id]['actions_taken'].append({
                            'action': action,
                            'timestamp': time.time(),
                            'success': success
                        })
            except Exception as e:
                logger.error(f"Failed to execute action {action}: {e}")
        
        logger.info(f"Handled threat {threat_event.event_id} with actions: {actions_taken}")
        return actions_taken
    
    def _execute_action(self, action: str, threat_event: ThreatEvent) -> bool:
        """Execute specific response action"""
        try:
            if action == 'quarantine_ip':
                self.quarantine_list.add(threat_event.source_ip)
                logger.warning(f"Quarantined IP: {threat_event.source_ip}")
                return True
            
            elif action == 'block_traffic':
                # In production, this would add iptables rules or similar
                logger.warning(f"Blocked traffic from {threat_event.source_ip}")
                return True
            
            elif action == 'alert_admin':
                self._send_alert(threat_event)
                return True
            
            elif action == 'collect_forensics':
                self._collect_forensics(threat_event)
                return True
            
            elif action == 'monitor_closely':
                logger.info(f"Enhanced monitoring for {threat_event.source_ip}")
                return True
            
            elif action == 'log_enhanced':
                logger.info(f"Enhanced logging for event {threat_event.event_id}")
                return True
            
            elif action == 'log_event':
                logger.info(f"Logged threat event {threat_event.event_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            return False
    
    def _send_alert(self, threat_event: ThreatEvent):
        """Send alert to administrators"""
        alert_message = {
            'event_id': threat_event.event_id,
            'timestamp': datetime.fromtimestamp(threat_event.timestamp).isoformat(),
            'severity': threat_event.severity.name,
            'threat_type': threat_event.threat_type,
            'source_ip': threat_event.source_ip,
            'description': threat_event.description,
            'confidence': threat_event.confidence
        }
        
        # In production, this would send emails, SMS, or push notifications
        logger.critical(f"SECURITY ALERT: {json.dumps(alert_message, indent=2)}")
    
    def _collect_forensics(self, threat_event: ThreatEvent):
        """Collect forensic data"""
        forensic_data = {
            'event_id': threat_event.event_id,
            'timestamp': threat_event.timestamp,
            'source_ip': threat_event.source_ip,
            'network_context': self._get_network_context(threat_event.source_ip),
            'process_context': self._get_process_context(),
            'file_hashes': self._collect_file_hashes()
        }
        
        # Store forensic data
        forensics_file = f"/var/log/forensics_{threat_event.event_id}.json"
        try:
            with open(forensics_file, 'w') as f:
                json.dump(forensic_data, f, indent=2)
            logger.info(f"Forensic data collected: {forensics_file}")
        except Exception as e:
            logger.error(f"Failed to collect forensics: {e}")
    
    def _get_network_context(self, ip: str) -> Dict:
        """Get network context for forensics"""
        return {
            'connections': f"Active connections for {ip}",
            'dns_history': f"DNS queries from {ip}",
            'traffic_patterns': f"Traffic analysis for {ip}"
        }
    
    def _get_process_context(self) -> Dict:
        """Get process context for forensics"""
        return {
            'running_processes': "List of running processes",
            'network_processes': "Processes with network connections",
            'suspicious_processes': "Potentially suspicious processes"
        }
    
    def _collect_file_hashes(self) -> List[str]:
        """Collect file hashes for forensics"""
        return ["hash1", "hash2", "hash3"]  # Placeholder
    
    def is_quarantined(self, ip: str) -> bool:
        """Check if IP is quarantined"""
        return ip in self.quarantine_list
    
    def remove_quarantine(self, ip: str) -> bool:
        """Remove IP from quarantine"""
        with self.lock:
            if ip in self.quarantine_list:
                self.quarantine_list.remove(ip)
                logger.info(f"Removed {ip} from quarantine")
                return True
        return False

class DatabaseManager:
    """Database management for logging and persistence"""
    
    def __init__(self, db_path: str = "/var/lib/cyberguard/firewall.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol INTEGER,
                    action TEXT,
                    rule_id TEXT,
                    packet_size INTEGER
                );
                
                CREATE TABLE IF NOT EXISTS threat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE,
                    timestamp REAL,
                    threat_type TEXT,
                    severity TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    description TEXT,
                    confidence REAL,
                    mitigation_action TEXT,
                    additional_data TEXT
                );
                
                CREATE TABLE IF NOT EXISTS firewall_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT UNIQUE,
                    priority INTEGER,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port TEXT,
                    destination_port TEXT,
                    protocol TEXT,
                    action TEXT,
                    enabled BOOLEAN,
                    description TEXT,
                    created_at REAL,
                    ai_generated BOOLEAN
                );
                
                CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_logs(timestamp);
                CREATE INDEX IF NOT EXISTS idx_threat_timestamp ON threat_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_rule_priority ON firewall_rules(priority);
            """)
    
    def log_traffic(self, packet: NetworkPacket, action: Action, rule_id: str):
        """Log traffic event"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO traffic_logs 
                (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, action, rule_id, packet_size)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                packet.timestamp, packet.src_ip, packet.dst_ip,
                packet.src_port, packet.dst_port, packet.protocol,
                action.value, rule_id, packet.size
            ))
    
    def log_threat_event(self, threat_event: ThreatEvent):
        """Log threat event"""
        with sqlite3.connect(self.db_path) as conn:
            additional_data = json.dumps(threat_event.additional_data) if threat_event.additional_data else None
            conn.execute("""
                INSERT OR REPLACE INTO threat_events
                (event_id, timestamp, threat_type, severity, source_ip, destination_ip,
                 description, confidence, mitigation_action, additional_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                threat_event.event_id, threat_event.timestamp, threat_event.threat_type,
                threat_event.severity.name, threat_event.source_ip, threat_event.destination_ip,
                threat_event.description, threat_event.confidence,
                threat_event.mitigation_action.value, additional_data
            ))
    
    def save_rule(self, rule: FirewallRule):
        """Save firewall rule to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO firewall_rules
                (rule_id, priority, source_ip, destination_ip, source_port, destination_port,
                 protocol, action, enabled, description, created_at, ai_generated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule.rule_id, rule.priority, rule.source_ip, rule.destination_ip,
                rule.source_port, rule.destination_port, rule.protocol,
                rule.action.value, rule.enabled, rule.description,
                rule.created_at, rule.ai_generated
            ))
    
    def load_rules(self) -> List[FirewallRule]:
        """Load firewall rules from database"""
        rules = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM firewall_rules WHERE enabled = 1 ORDER BY priority")
            for row in cursor.fetchall():
                rule = FirewallRule(
                    rule_id=row[1],
                    priority=row[2],
                    source_ip=row[3],
                    destination_ip=row[4],
                    source_port=row[5],
                    destination_port=row[6],
                    protocol=row[7],
                    action=Action(row[8]),
                    enabled=bool(row[9]),
                    description=row[10],
                    created_at=row[11],
                    ai_generated=bool(row[12])
                )
                rules.append(rule)
        return rules
    
    def get_traffic_stats(self, hours: int = 24) -> Dict:
        """Get traffic statistics"""
        cutoff_time = time.time() - (hours * 3600)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT action, COUNT(*) as count, SUM(packet_size) as bytes
                FROM traffic_logs 
                WHERE timestamp > ?
                GROUP BY action
            """, (cutoff_time,))
            
            stats = {}
            for row in cursor.fetchall():
                stats[row[0]] = {
                    'count': row[1],
                    'bytes': row[2] or 0
                }
            
            return stats
    
    def get_threat_summary(self, hours: int = 24) -> Dict:
        """Get threat event summary"""
        cutoff_time = time.time() - (hours * 3600)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT threat_type, severity, COUNT(*) as count, AVG(confidence) as avg_confidence
                FROM threat_events 
                WHERE timestamp > ?
                GROUP BY threat_type, severity
            """, (cutoff_time,))
            
            threats = {}
            for row in cursor.fetchall():
                key = f"{row[0]}_{row[1]}"
                threats[key] = {
                    'type': row[0],
                    'severity': row[1],
                    'count': row[2],
                    'avg_confidence': row[3]
                }
            
            return threats

class WebDashboard:
    """Web-based management dashboard"""
    
    def __init__(self, firewall_engine):
        self.firewall_engine = firewall_engine
        self.auth_tokens = {}
        self.session_timeout = 3600  # 1 hour
    
    def generate_auth_token(self, username: str) -> str:
        """Generate authentication token"""
        token = secrets.token_urlsafe(32)
        self.auth_tokens[token] = {
            'username': username,
            'created': time.time(),
            'last_used': time.time()
        }
        return token
    
    def validate_token(self, token: str) -> bool:
        """Validate authentication token"""
        if token not in self.auth_tokens:
            return False
        
        session = self.auth_tokens[token]
        if time.time() - session['last_used'] > self.session_timeout:
            del self.auth_tokens[token]
            return False
        
        session['last_used'] = time.time()
        return True
    
    def get_dashboard_data(self, token: str) -> Dict:
        """Get dashboard data for web interface"""
        if not self.validate_token(token):
            return {'error': 'Invalid or expired token'}
        
        db = self.firewall_engine.db_manager
        
        dashboard_data = {
            'status': {
                'active': True,
                'uptime': time.time() - self.firewall_engine.start_time,
                'processed_packets': self.firewall_engine.packet_count,
                'active_flows': len(self.firewall_engine.flow_tracker.flows),
                'quarantined_ips': len(self.firewall_engine.incident_response.quarantine_list)
            },
            'traffic_stats': db.get_traffic_stats(24),
            'threat_summary': db.get_threat_summary(24),
            'recent_threats': self._get_recent_threats(10),
            'top_blocked_ips': self._get_top_blocked_ips(10),
            'performance_metrics': self._get_performance_metrics()
        }
        
        return dashboard_data
    
    def _get_recent_threats(self, limit: int) -> List[Dict]:
        """Get recent threat events"""
        db = self.firewall_engine.db_manager
        
        with sqlite3.connect(db.db_path) as conn:
            cursor = conn.execute("""
                SELECT event_id, timestamp, threat_type, severity, source_ip, description, confidence
                FROM threat_events 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
            
            threats = []
            for row in cursor.fetchall():
                threats.append({
                    'event_id': row[0],
                    'timestamp': datetime.fromtimestamp(row[1]).isoformat(),
                    'threat_type': row[2],
                    'severity': row[3],
                    'source_ip': row[4],
                    'description': row[5],
                    'confidence': row[6]
                })
            
            return threats
    
    def _get_top_blocked_ips(self, limit: int) -> List[Dict]:
        """Get top blocked IP addresses"""
        db = self.firewall_engine.db_manager
        
        with sqlite3.connect(db.db_path) as conn:
            cursor = conn.execute("""
                SELECT src_ip, COUNT(*) as block_count
                FROM traffic_logs 
                WHERE action IN ('deny', 'drop') 
                AND timestamp > ?
                GROUP BY src_ip 
                ORDER BY block_count DESC 
                LIMIT ?
            """, (time.time() - 86400, limit))  # Last 24 hours
            
            blocked_ips = []
            for row in cursor.fetchall():
                blocked_ips.append({
                    'ip': row[0],
                    'block_count': row[1]
                })
            
            return blocked_ips
    
    def _get_performance_metrics(self) -> Dict:
        """Get system performance metrics"""
        return {
            'cpu_usage': 0.0,  # Would integrate with system monitoring
            'memory_usage': 0.0,
            'network_throughput': 0.0,
            'packet_processing_rate': getattr(self.firewall_engine, 'processing_rate', 0),
            'ai_model_latency': getattr(self.firewall_engine.ai_detector, 'avg_latency', 0.001)
        }

class CyberGuardFirewall:
    """Main firewall engine coordinating all components"""
    
    def __init__(self, config_file: str = "/etc/cyberguard/config.json"):
        self.config = self._load_config(config_file)
        self.start_time = time.time()
        self.packet_count = 0
        self.processing_rate = 0.0
        self.is_running = False
        
        # Initialize components
        self.ai_detector = AIThreatDetector()
        self.flow_tracker = FlowTracker()
        self.policy_engine = PolicyEngine()
        self.incident_response = IncidentResponseEngine()
        self.db_manager = DatabaseManager()
        self.web_dashboard = WebDashboard(self)
        
        # Threading components
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.packet_queue = asyncio.Queue(maxsize=10000)
        
        logger.info("CyberGuard Firewall initialized")
    
    def _load_config(self, config_file: str) -> Dict:
        """Load configuration from file"""
        default_config = {
            "interfaces": ["eth0"],
            "log_level": "INFO",
            "ai_training_interval": 3600,
            "flow_timeout": 300,
            "max_packet_size": 65535,
            "enable_ai": True,
            "enable_geo_blocking": True,
            "enable_reputation_filtering": True,
            "dashboard_port": 8443,
            "database_path": "/var/lib/cyberguard/firewall.db"
        }
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                return {**default_config, **config}
        except FileNotFoundError:
            logger.warning(f"Config file {config_file} not found, using defaults")
            return default_config
    
    async def start(self):
        """Start the firewall engine"""
        logger.info("Starting CyberGuard Firewall...")
        
        self.is_running = True
        
        # Initialize AI models
        if self.config.get("enable_ai", True):
            self.ai_detector.initialize_models()
            await self._train_ai_models()
        
        # Load saved rules
        saved_rules = self.db_manager.load_rules()
        for rule in saved_rules:
            self.policy_engine.add_rule(rule)
        
        # Start background tasks
        asyncio.create_task(self._packet_processor())
        asyncio.create_task(self._flow_cleanup_task())
        asyncio.create_task(self._ai_training_task())
        asyncio.create_task(self._performance_monitor())
        
        logger.info("CyberGuard Firewall started successfully")
    
    async def stop(self):
        """Stop the firewall engine"""
        logger.info("Stopping CyberGuard Firewall...")
        
        self.is_running = False
        self.executor.shutdown(wait=True)
        
        logger.info("CyberGuard Firewall stopped")
    
    async def process_packet(self, packet: NetworkPacket) -> Tuple[Action, str]:
        """Process a single network packet"""
        try:
            self.packet_count += 1
            
            # Check if source IP is quarantined
            if self.incident_response.is_quarantined(packet.src_ip):
                action = Action.QUARANTINE
                rule_id = "quarantine_list"
                self.db_manager.log_traffic(packet, action, rule_id)
                return action, rule_id
            
            # Update flow tracking
            flow_data = self.flow_tracker.update_flow(packet)
            
            # AI-based threat detection
            threat_info = {}
            if self.config.get("enable_ai", True) and self.ai_detector.is_trained:
                is_anomaly, anomaly_confidence = self.ai_detector.detect_anomaly(packet, flow_data)
                threat_type, threat_confidence = self.ai_detector.classify_threat(packet, flow_data)
                
                threat_info = {
                    'is_anomaly': is_anomaly,
                    'anomaly_confidence': anomaly_confidence,
                    'threat_type': threat_type,
                    'threat_confidence': threat_confidence,
                    'confidence': max(anomaly_confidence, threat_confidence)
                }
                
                # Generate threat event if confidence is high
                if threat_info['confidence'] > 0.7:
                    await self._handle_threat_detection(packet, flow_data, threat_info)
            
            # Apply firewall rules
            action, rule_id = self.policy_engine.evaluate_packet(packet, threat_info)
            
            # Log the decision
            self.db_manager.log_traffic(packet, action, rule_id)
            
            return action, rule_id
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            return Action.DENY, "error_default"
    
    async def _handle_threat_detection(self, packet: NetworkPacket, flow_data: Dict, threat_info: Dict):
        """Handle detected threat"""
        event_id = hashlib.md5(f"{packet.src_ip}:{packet.dst_ip}:{time.time()}".encode()).hexdigest()
        
        # Determine threat severity
        confidence = threat_info['confidence']
        if confidence > 0.9:
            severity = ThreatLevel.CRITICAL
        elif confidence > 0.8:
            severity = ThreatLevel.HIGH
        elif confidence > 0.7:
            severity = ThreatLevel.MEDIUM
        else:
            severity = ThreatLevel.LOW
        
        threat_event = ThreatEvent(
            event_id=event_id,
            timestamp=packet.timestamp,
            threat_type=threat_info['threat_type'],
            severity=severity,
            source_ip=packet.src_ip,
            destination_ip=packet.dst_ip,
            description=f"AI detected {threat_info['threat_type']} with {confidence:.2f} confidence",
            confidence=confidence,
            mitigation_action=Action.DENY,
            additional_data={
                'flow_data': flow_data,
                'packet_info': {
                    'size': packet.size,
                    'protocol': packet.protocol,
                    'src_port': packet.src_port,
                    'dst_port': packet.dst_port
                }
            }
        )
        
        # Log threat event
        self.db_manager.log_threat_event(threat_event)
        
        # Execute incident response
        actions_taken = self.incident_response.handle_threat(threat_event)
        
        # Consider generating new firewall rule
        if confidence > 0.85 and threat_info['threat_type'] in ['malware', 'intrusion']:
            await self._generate_ai_rule(threat_event, threat_info)
    
    async def _generate_ai_rule(self, threat_event: ThreatEvent, threat_info: Dict):
        """Generate AI-based firewall rule"""
        rule_id = f"ai_rule_{threat_event.event_id[:8]}"
        
        new_rule = FirewallRule(
            rule_id=rule_id,
            priority=50,  # High priority for AI-generated rules
            source_ip=threat_event.source_ip,
            destination_ip="any",
            source_port="any",
            destination_port="any",
            protocol="any",
            action=Action.DENY,
            description=f"AI-generated rule for {threat_event.threat_type} (confidence: {threat_event.confidence:.2f})",
            ai_generated=True
        )
        
        if self.policy_engine.add_rule(new_rule):
            self.db_manager.save_rule(new_rule)
            logger.info(f"Generated AI rule: {rule_id} for threat {threat_event.event_id}")
    
    async def _packet_processor(self):
        """Background packet processing task"""
        while self.is_running:
            try:
                # In a real implementation, this would read from network interfaces
                # For demo purposes, we'll simulate packet processing
                await asyncio.sleep(0.001)  # Prevent tight loop
                
                # Process queued packets
                while not self.packet_queue.empty():
                    packet = await self.packet_queue.get()
                    await self.process_packet(packet)
                    
            except Exception as e:
                logger.error(f"Packet processor error: {e}")
                await asyncio.sleep(1)
    
    async def _flow_cleanup_task(self):
        """Background flow cleanup task"""
        while self.is_running:
            try:
                self.flow_tracker.cleanup_expired_flows()
                await asyncio.sleep(60)  # Run every minute
            except Exception as e:
                logger.error(f"Flow cleanup error: {e}")
                await asyncio.sleep(60)
    
    async def _ai_training_task(self):
        """Background AI model training task"""
        training_interval = self.config.get("ai_training_interval", 3600)
        
        while self.is_running:
            try:
                await asyncio.sleep(training_interval)
                if self.config.get("enable_ai", True):
                    await self._train_ai_models()
            except Exception as e:
                logger.error(f"AI training error: {e}")
                await asyncio.sleep(training_interval)
    
    async def _train_ai_models(self):
        """Train AI models with recent data"""
        logger.info("Training AI models...")
        
        # In production, this would query recent traffic data from the database
        # For demo, we'll use synthetic data
        training_data = pd.DataFrame()  # Empty DataFrame triggers synthetic data generation
        
        # Train models in a separate thread to avoid blocking
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            self.executor,
            self.ai_detector.train_models,
            training_data
        )
        
        logger.info("AI model training completed")
    
    async def _performance_monitor(self):
        """Monitor system performance"""
        last_packet_count = 0
        
        while self.is_running:
            try:
                await asyncio.sleep(10)  # Update every 10 seconds
                
                # Calculate processing rate
                current_count = self.packet_count
                packets_processed = current_count - last_packet_count
                self.processing_rate = packets_processed / 10.0  # packets per second
                last_packet_count = current_count
                
                # Log performance metrics
                if self.packet_count % 10000 == 0 and self.packet_count > 0:
                    uptime = time.time() - self.start_time
                    logger.info(f"Performance: {self.packet_count} packets processed, "
                              f"{self.processing_rate:.1f} pps, uptime: {uptime:.0f}s")
                
            except Exception as e:
                logger.error(f"Performance monitor error: {e}")
                await asyncio.sleep(10)
    
    def simulate_network_traffic(self, duration: int = 60):
        """Simulate network traffic for testing"""
        logger.info(f"Simulating network traffic for {duration} seconds...")
        
        import random
        
        def generate_packet():
            return NetworkPacket(
                src_ip=f"192.168.1.{random.randint(1, 254)}",
                dst_ip=f"10.0.0.{random.randint(1, 254)}",
                src_port=random.randint(1024, 65535),
                dst_port=random.choice([80, 443, 22, 53, 21, 25]),
                protocol=random.choice([6, 17]),  # TCP or UDP
                payload=b"test_payload_" + bytes([random.randint(0, 255) for _ in range(100)]),
                timestamp=time.time(),
                size=random.randint(64, 1500)
            )
        
        async def traffic_generator():
            end_time = time.time() + duration
            while time.time() < end_time and self.is_running:
                packet = generate_packet()
                
                # Occasionally generate suspicious traffic
                if random.random() < 0.1:  # 10% suspicious traffic
                    packet.src_ip = "192.168.1.666"  # Known bad IP from reputation scoring
                    packet.payload = b"\x90" * 20 + b"malicious_payload"  # NOP sled
                
                try:
                    await self.packet_queue.put(packet)
                except asyncio.QueueFull:
                    logger.warning("Packet queue full, dropping packet")
                
                await asyncio.sleep(0.001)  # 1000 packets per second
        
        return traffic_generator()

async def main():
    """Main function to run the firewall"""
    firewall = CyberGuardFirewall()
    
    try:
        # Start the firewall
        await firewall.start()
        
        # Simulate some network traffic for demonstration
        traffic_task = asyncio.create_task(firewall.simulate_network_traffic(30))
        
        # Run for demonstration period
        await asyncio.sleep(35)
        
        # Display some statistics
        print("\n" + "="*60)
        print("CYBERGUARD FIREWALL STATISTICS")
        print("="*60)
        
        dashboard_data = firewall.web_dashboard.get_dashboard_data(
            firewall.web_dashboard.generate_auth_token("admin")
        )
        
        if 'error' not in dashboard_data:
            status = dashboard_data['status']
            print(f"Status: {'Active' if status['active'] else 'Inactive'}")
            print(f"Uptime: {status['uptime']:.1f} seconds")
            print(f"Packets Processed: {status['processed_packets']}")
            print(f"Active Flows: {status['active_flows']}")
            print(f"Quarantined IPs: {status['quarantined_ips']}")
            print(f"Processing Rate: {firewall.processing_rate:.1f} packets/sec")
            
            print(f"\nTraffic Statistics:")
            for action, stats in dashboard_data['traffic_stats'].items():
                print(f"  {action.upper()}: {stats['count']} packets, {stats['bytes']} bytes")
            
            print(f"\nThreat Summary:")
            for threat_key, threat_data in dashboard_data['threat_summary'].items():
                print(f"  {threat_data['type'].upper()} ({threat_data['severity']}): "
                      f"{threat_data['count']} events, "
                      f"avg confidence: {threat_data['avg_confidence']:.2f}")
            
            print(f"\nRecent Threats:")
            for threat in dashboard_data['recent_threats'][:5]:
                print(f"  [{threat['timestamp']}] {threat['threat_type']} from {threat['source_ip']} "
                      f"(confidence: {threat['confidence']:.2f})")
        
        print("="*60)
        
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    except Exception as e:
        logger.error(f"Firewall error: {e}")
    finally:
        await firewall.stop()

if __name__ == "__main__":
    # Setup proper signal handling for graceful shutdown
    import signal
    
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}")
        raise KeyboardInterrupt
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run the firewall
    asyncio.run(main())
