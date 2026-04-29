"""
Flask Backend Implementation Guide
Complete guide to implement SOC Dashboard backend endpoints
"""

# ========== DATABASE MODELS ==========

"""
Add to website/requirements.txt:
- Flask 2.3.0+
- Flask-SQLAlchemy 3.0+
- SQLAlchemy 2.0+
- psutil (for system metrics)
"""

# models.py - Add to website/

"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class DetectionRule(db.Model):
    __tablename__ = 'detection_rules'
    
    id = db.Column(db.String(64), primary_key=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    description = db.Column(db.Text)
    enabled = db.Column(db.Boolean, default=True)
    severity = db.Column(db.String(16), nullable=False)  # critical/high/medium/low
    conditions = db.Column(db.JSON, nullable=False)  # Stored as JSON array
    actions = db.Column(db.JSON, nullable=False)  # Stored as JSON array
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    hit_count = db.Column(db.Integer, default=0)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'enabled': self.enabled,
            'severity': self.severity,
            'conditions': self.conditions,
            'actions': self.actions,
            'created_at': self.created_at.isoformat(),
            'hit_count': self.hit_count
        }

class ThreatIndicator(db.Model):
    __tablename__ = 'threat_indicators'
    
    id = db.Column(db.String(64), primary_key=True)
    type = db.Column(db.String(32), nullable=False)  # malware_hash/c2_domain/etc
    value = db.Column(db.String(512), nullable=False, unique=True, index=True)
    severity = db.Column(db.String(16), nullable=False)  # critical/high/medium/low
    source = db.Column(db.String(128), nullable=False, index=True)
    confidence = db.Column(db.Float, default=0.0)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    feed_id = db.Column(db.String(64), nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'value': self.value,
            'severity': self.severity,
            'source': self.source,
            'confidence': self.confidence,
            'added_at': self.added_at.isoformat(),
            'last_seen': self.last_seen.isoformat()
        }

class ThreatFeed(db.Model):
    __tablename__ = 'threat_feeds'
    
    id = db.Column(db.String(64), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    url = db.Column(db.String(512), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    last_synced = db.Column(db.DateTime, nullable=True)
    indicator_count = db.Column(db.Integer, default=0)
    update_interval_hours = db.Column(db.Integer, default=12)
    format = db.Column(db.String(16))  # json/csv/txt
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'url': self.url,
            'enabled': self.enabled,
            'last_synced': self.last_synced.isoformat() if self.last_synced else None,
            'indicator_count': self.indicator_count,
            'update_interval_hours': self.update_interval_hours,
            'format': self.format
        }

class AdminStats(db.Model):
    __tablename__ = 'admin_stats'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    uptime_hours = db.Column(db.Float)
    cpu_usage_percent = db.Column(db.Float)
    memory_usage_percent = db.Column(db.Float)
    db_size_mb = db.Column(db.Float)
    total_ioc_reports = db.Column(db.Integer)
    total_scans = db.Column(db.Integer)
    total_event_logs = db.Column(db.Integer)
    total_dns_events = db.Column(db.Integer)
    threat_feeds_synced = db.Column(db.Integer)
    api_requests_today = db.Column(db.Integer)
"""

# ========== API ENDPOINTS ==========

# routes.py or add to existing server.py routes

"""
import psutil
import os
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request

api = Blueprint('api', __name__, url_prefix='/api')

# ===== YARA SCANNING =====
@api.route('/yara/scan', methods=['POST'])
def yara_scan():
    '''Scan events against YARA rules'''
    try:
        data = request.get_json()
        events = data.get('events', [])
        source = data.get('source', 'api')
        
        # Import YARA scanning logic from dynamic_analysis_sandbox.py
        # This is a stub - implement based on existing YARA matcher
        matches = []
        for event in events:
            # Check event against YARA rules
            # Example rule matching
            if 'malicious' in str(event).lower():
                matches.append({
                    'rule_name': 'Suspicious_Pattern_Detected',
                    'severity': 'high',
                    'matched_strings': ['malicious'],
                    'affected_events': 1
                })
        
        return jsonify({
            'status': 'success',
            'scan_id': f'scan-{datetime.utcnow().timestamp()}',
            'matches': matches,
            'total_matches': len(matches)
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ===== ADMIN STATS =====
@api.route('/admin/stats', methods=['GET'])
def get_admin_stats():
    '''Get system health and statistics'''
    try:
        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = psutil.virtual_memory().percent
        
        # Get database size
        db_path = 'database.db'  # Adjust path
        db_size_mb = os.path.getsize(db_path) / (1024 * 1024) if os.path.exists(db_path) else 0
        
        # Query counts from database
        total_ioc_reports = IocReport.query.count()  # Adjust model name
        total_scans = Scan.query.count()
        total_event_logs = EventLog.query.count()
        total_dns_events = DnsQueryEvent.query.count()
        
        # Get uptime (from server start time or from last stat entry)
        start_time = getattr(app, 'start_time', datetime.utcnow())
        uptime = (datetime.utcnow() - start_time).total_seconds() / 3600
        
        return jsonify({
            'timestamp': datetime.utcnow().isoformat(),
            'uptime_hours': round(uptime, 2),
            'cpu_usage_percent': round(cpu_percent, 2),
            'memory_usage_percent': round(memory_percent, 2),
            'db_size_mb': round(db_size_mb, 2),
            'total_ioc_reports': total_ioc_reports,
            'total_scans': total_scans,
            'total_event_logs': total_event_logs,
            'total_dns_events': total_dns_events,
            'threat_feeds_synced': ThreatFeed.query.filter_by(enabled=True).count(),
            'api_requests_today': 2340  # Track in middleware
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== THREAT FEED SYNCING =====
@api.route('/threat-feeds/sync', methods=['POST'])
def sync_threat_feeds():
    '''Sync threat indicators from enabled feeds'''
    try:
        data = request.get_json()
        feed_sources = data.get('feed_sources', [])
        
        total_feeds_synced = 0
        total_new_indicators = 0
        
        for feed_id in feed_sources:
            feed = ThreatFeed.query.get(feed_id)
            if not feed or not feed.enabled:
                continue
            
            # Implement feed-specific API calls
            # Example: OTX, Abuse.ch, etc.
            indicators = fetch_feed_indicators(feed)
            
            # Deduplicate and store
            for indicator in indicators:
                existing = ThreatIndicator.query.filter_by(
                    value=indicator['value']
                ).first()
                
                if not existing:
                    new_indicator = ThreatIndicator(
                        id=f"ind-{datetime.utcnow().timestamp()}",
                        type=indicator['type'],
                        value=indicator['value'],
                        severity=indicator['severity'],
                        source=feed.name,
                        confidence=indicator.get('confidence', 0.0),
                        feed_id=feed_id
                    )
                    db.session.add(new_indicator)
                    total_new_indicators += 1
                else:
                    existing.last_seen = datetime.utcnow()
                    existing.confidence = max(existing.confidence, indicator.get('confidence', 0.0))
            
            feed.last_synced = datetime.utcnow()
            feed.indicator_count = ThreatIndicator.query.filter_by(feed_id=feed_id).count()
            total_feeds_synced += 1
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'feeds_synced': total_feeds_synced,
            'new_indicators': total_new_indicators,
            'created_at_utc': datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ===== THREAT INDICATORS RETRIEVAL =====
@api.route('/threat-indicators', methods=['GET'])
def get_threat_indicators():
    '''Get threat indicators with optional filtering'''
    try:
        severity = request.args.get('severity')
        limit = request.args.get('limit', default=100, type=int)
        
        query = ThreatIndicator.query.order_by(ThreatIndicator.last_seen.desc())
        
        if severity:
            query = query.filter_by(severity=severity)
        
        indicators = query.limit(limit).all()
        
        return jsonify({
            'fetched_at_utc': datetime.utcnow().isoformat(),
            'count': len(indicators),
            'items': [ind.to_dict() for ind in indicators]
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== DETECTION RULES - CREATE =====
@api.route('/detection-rules', methods=['POST'])
def create_detection_rule():
    '''Create a new detection rule'''
    try:
        data = request.get_json()
        
        rule = DetectionRule(
            id=data['id'],
            name=data['name'],
            description=data.get('description', ''),
            enabled=data.get('enabled', True),
            severity=data['severity'],
            conditions=data.get('conditions', []),
            actions=data.get('actions', [])
        )
        
        db.session.add(rule)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'rule_id': rule.id,
            'created_at_utc': rule.created_at.isoformat(),
            'message': 'Rule created successfully'
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

# ===== DETECTION RULES - LIST =====
@api.route('/detection-rules', methods=['GET'])
def list_detection_rules():
    '''Get all detection rules'''
    try:
        rules = DetectionRule.query.all()
        
        return jsonify({
            'rules': [{
                'id': r.id,
                'name': r.name,
                'description': r.description,
                'severity': r.severity,
                'enabled': r.enabled,
                'hit_count': r.hit_count
            } for r in rules],
            'total_count': len(rules)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== DETECTION RULES - UPDATE =====
@api.route('/detection-rules/<rule_id>', methods=['PATCH'])
def update_detection_rule(rule_id):
    '''Update a detection rule'''
    try:
        rule = DetectionRule.query.get(rule_id)
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        data = request.get_json()
        
        if 'enabled' in data:
            rule.enabled = data['enabled']
        if 'severity' in data:
            rule.severity = data['severity']
        if 'conditions' in data:
            rule.conditions = data['conditions']
        if 'actions' in data:
            rule.actions = data['actions']
        
        rule.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'rule_id': rule.id,
            'created_at_utc': rule.created_at.isoformat(),
            'message': 'Rule updated successfully'
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

# ===== DETECTION RULES - DELETE =====
@api.route('/detection-rules/<rule_id>', methods=['DELETE'])
def delete_detection_rule(rule_id):
    '''Delete a detection rule'''
    try:
        rule = DetectionRule.query.get(rule_id)
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        db.session.delete(rule)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'rule_id': rule_id,
            'created_at_utc': datetime.utcnow().isoformat(),
            'message': 'Rule deleted successfully'
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ===== HELPER FUNCTIONS =====

def fetch_feed_indicators(feed):
    '''Fetch indicators from external threat feed API'''
    # Implementation depends on feed format and API
    # Example for AlienVault OTX:
    if feed.id == 'alienvault-otx':
        # import requests
        # response = requests.get(feed.url, headers={'X-OTX-API-KEY': os.getenv('OTX_API_KEY')})
        # return parse_otx_response(response.json())
        pass
    
    # Add feed-specific implementations
    return []
"""

# ========== INITIALIZATION IN APP ==========

"""
In website/server.py, add:

from flask import Flask
from models import db, DetectionRule, ThreatIndicator, ThreatFeed, AdminStats
from routes import api

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///soc_dashboard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)
app.register_blueprint(api)

with app.app_context():
    db.create_all()
    app.start_time = datetime.utcnow()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
"""

# ========== MIGRATION SCRIPT ==========

"""
Run this to add new tables to existing database:

from flask import Flask
from models import db, DetectionRule, ThreatIndicator, ThreatFeed, AdminStats

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db.init_app(app)

with app.app_context():
    db.create_all()
    print('Database tables created successfully')
"""
