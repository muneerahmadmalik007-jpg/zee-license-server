"""
Turso Online License Server API - Vercel Serverless
Complete license validation system with database
"""

import json
import os
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
import urllib.request
import urllib.error

# ============================================================
# TURSO DATABASE CONFIGURATION
# ============================================================
TURSO_DB_URL = os.environ.get('TURSO_DB_URL', 'libsql://zee-licenses-mychannelmanageraccess-netizen.aws-ap-south-1.turso.io')
TURSO_AUTH_TOKEN = os.environ.get('TURSO_AUTH_TOKEN', 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3NjgyMjcyNjQsImlkIjoiZTgyMTA5ZjgtMWU1Ni00NmVhLWFhZmMtNDhiYzMyZjNkYjgwIiwicmlkIjoiMmNhOGEwMzQtYjYwNy00MWQ2LWJjMTItZDNiNzAzMzhiNzkyIn0.aBgFusPuY9ze46PGzcNQJOxrhT47Zcwz-PG8xTFelic-KB34VzzNSEV6MvjzyB4qjA-ZH8LQTpg8e4IPJlwxBw')

# Admin password
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'Zahid9244')
SECRET_KEY = os.environ.get('LICENSE_SECRET_KEY', 'ZeeSoftHub_License_2024_Premium_Automation')

# ============================================================
# TURSO HTTP API HELPER
# ============================================================
class TursoClient:
    """Turso Database HTTP Client"""
    
    def __init__(self, db_url, auth_token):
        self.db_url = db_url
        self.auth_token = auth_token
    
    def execute(self, sql, params=None):
        """Execute SQL query"""
        try:
            url = f"{self.db_url}/v2/pipeline"
            
            statements = []
            if params:
                stmt = {"q": {"sql": sql, "args": params if isinstance(params, list) else [params]}}
            else:
                stmt = {"q": {"sql": sql}}
            
            statements.append(stmt)
            payload = json.dumps({"statements": statements}).encode()
            
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    'Authorization': f'Bearer {self.auth_token}',
                    'Content-Type': 'application/json'
                },
                method='POST'
            )
            
            response = urllib.request.urlopen(req, timeout=10)
            data = json.loads(response.read().decode())
            return data.get('results', [{}])[0]
        
        except Exception as e:
            print(f"Turso Error: {e}")
            return {"error": str(e)}
    
    def init_database(self):
        """Initialize database tables"""
        self.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            license_key TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            user_name TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            duration_days INTEGER,
            rdp_limit INTEGER DEFAULT 1,
            active BOOLEAN DEFAULT 1,
            machine_count INTEGER DEFAULT 0
        )
        """)
        
        self.execute("""
        CREATE TABLE IF NOT EXISTS machine_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            hwid TEXT NOT NULL,
            machine_name TEXT,
            first_used DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_used DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(license_key, hwid),
            FOREIGN KEY(license_key) REFERENCES licenses(license_key)
        )
        """)
        
        self.execute("""
        CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            admin_id TEXT,
            target_license TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        )
        """)


turso = TursoClient(TURSO_DB_URL, TURSO_AUTH_TOKEN)

# ============================================================
# UTILITY FUNCTIONS
# ============================================================
def generate_license_key(user_id, user_name, duration_days=30, rdp_limit=1):
    """Generate license key"""
    random_part = secrets.token_hex(8)
    user_hash = hashlib.md5(f"{user_id}{user_name}".encode()).hexdigest()[:8]
    return f"ZEE-{random_part.upper()}-{user_hash.upper()}"


def calculate_signature(license_key):
    """Calculate HMAC signature"""
    return hmac.new(
        SECRET_KEY.encode(),
        license_key.encode(),
        hashlib.sha256
    ).hexdigest()


def validate_signature(license_key, signature):
    """Validate HMAC signature"""
    expected = calculate_signature(license_key)
    return hmac.compare_digest(expected, signature)


def json_response(data, status_code=200):
    """Create JSON response for Vercel"""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps(data)
    }


def validate_license(data):
    """Validate license key with HWID tracking"""
    license_key = data.get('license_key', '').strip()
    hwid = data.get('hwid', '').strip()
    
    if not license_key or not hwid:
        return json_response({"valid": False, "reason": "Missing license_key or hwid"}, 400)
    
    try:
        result = turso.execute("SELECT * FROM licenses WHERE license_key = ? AND active = 1", [license_key])
        
        if not result.get('rows') or len(result['rows']) == 0:
            return json_response({"valid": False, "reason": "License not found"}, 200)
        
        license_data = result['rows'][0]
        expires_at = license_data[4]
        
        if datetime.fromisoformat(expires_at) < datetime.utcnow():
            return json_response({"valid": False, "reason": "License expired"}, 200)
        
        rdp_limit = license_data[6]
        
        usage_result = turso.execute(
            "SELECT COUNT(*) as count FROM machine_usage WHERE license_key = ? AND hwid = ?",
            [license_key, hwid]
        )
        
        machine_count = usage_result['rows'][0][0] if usage_result.get('rows') else 0
        
        total_result = turso.execute(
            "SELECT COUNT(DISTINCT hwid) as total FROM machine_usage WHERE license_key = ?",
            [license_key]
        )
        
        total_machines = total_result['rows'][0][0] if total_result.get('rows') else 0
        
        if machine_count == 0 and total_machines >= rdp_limit:
            return json_response({
                "valid": False,
                "reason": f"RDP limit exceeded ({rdp_limit} allowed)",
                "machines_used": total_machines
            }, 200)
        
        if machine_count == 0:
            turso.execute(
                "INSERT INTO machine_usage (license_key, hwid, machine_name, last_used) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                [license_key, hwid, data.get('machine_name', 'Unknown')]
            )
        else:
            turso.execute(
                "UPDATE machine_usage SET last_used = CURRENT_TIMESTAMP WHERE license_key = ? AND hwid = ?",
                [license_key, hwid]
            )
        
        return json_response({
            "valid": True,
            "user_id": license_data[1],
            "user_name": license_data[2],
            "expires_at": expires_at,
            "rdp_limit": rdp_limit,
            "machines_used": total_machines + (1 if machine_count == 0 else 0),
            "signature": calculate_signature(license_key)
        }, 200)
    
    except Exception as e:
        return json_response({"error": str(e)}, 500)


def admin_generate_license(data):
    """Generate new license (admin only)"""
    admin_password = data.get('admin_password', '')
    
    if not admin_password or admin_password != ADMIN_PASSWORD:
        return json_response({"error": "Unauthorized"}, 401)
    
    user_id = data.get('user_id', '')
    user_name = data.get('user_name', 'User')
    duration_days = data.get('duration_days', 30)
    rdp_limit = data.get('rdp_limit', 1)
    
    if not user_id:
        return json_response({"error": "Missing user_id"}, 400)
    
    try:
        license_key = generate_license_key(user_id, user_name, duration_days, rdp_limit)
        expires_at = (datetime.utcnow() + timedelta(days=duration_days)).isoformat()
        
        turso.execute(
            "INSERT INTO licenses (license_key, user_id, user_name, expires_at, duration_days, rdp_limit) VALUES (?, ?, ?, ?, ?, ?)",
            [license_key, user_id, user_name, expires_at, duration_days, rdp_limit]
        )
        
        turso.execute(
            "INSERT INTO admin_logs (action, admin_id, target_license, details) VALUES (?, ?, ?, ?)",
            ['GENERATE', 'admin', license_key, f"{user_id}:{user_name}"]
        )
        
        return json_response({
            "success": True,
            "license_key": license_key,
            "expires_at": expires_at,
            "signature": calculate_signature(license_key)
        }, 200)
    
    except Exception as e:
        return json_response({"error": str(e)}, 500)


def admin_revoke_license(data):
    """Revoke license"""
    admin_password = data.get('admin_password', '')
    
    if not admin_password or admin_password != ADMIN_PASSWORD:
        return json_response({"error": "Unauthorized"}, 401)
    
    license_key = data.get('license_key', '')
    
    if not license_key:
        return json_response({"error": "Missing license_key"}, 400)
    
    try:
        turso.execute("UPDATE licenses SET active = 0 WHERE license_key = ?", [license_key])
        turso.execute("INSERT INTO admin_logs (action, admin_id, target_license) VALUES (?, ?, ?)", ['REVOKE', 'admin', license_key])
        return json_response({"success": True, "message": "License revoked"}, 200)
    
    except Exception as e:
        return json_response({"error": str(e)}, 500)


def admin_deactivate_license(data):
    """Deactivate license"""
    admin_password = data.get('admin_password', '')
    
    if not admin_password or admin_password != ADMIN_PASSWORD:
        return json_response({"error": "Unauthorized"}, 401)
    
    license_key = data.get('license_key', '')
    
    if not license_key:
        return json_response({"error": "Missing license_key"}, 400)
    
    try:
        turso.execute("UPDATE licenses SET active = 0 WHERE license_key = ?", [license_key])
        return json_response({"success": True}, 200)
    
    except Exception as e:
        return json_response({"error": str(e)}, 500)


def admin_list_licenses(data):
    """List all licenses"""
    admin_password = data.get('admin_password', '')
    
    if not admin_password or admin_password != ADMIN_PASSWORD:
        return json_response({"error": "Unauthorized"}, 401)
    
    try:
        result = turso.execute("SELECT license_key, user_id, user_name, expires_at, active FROM licenses ORDER BY created_at DESC LIMIT 100")
        
        licenses = []
        if result.get('rows'):
            for row in result['rows']:
                licenses.append({
                    "license_key": row[0],
                    "user_id": row[1],
                    "user_name": row[2],
                    "expires_at": row[3],
                    "active": row[4]
                })
        
        return json_response({"licenses": licenses}, 200)
    
    except Exception as e:
        return json_response({"error": str(e)}, 500)


# ============================================================
# MAIN HANDLER - Vercel Entry Point
# ============================================================
def handler(event, context):
    """Main Vercel serverless handler (AWS Lambda compatible)"""
    
    method = event.get('httpMethod', 'GET')
    path = event.get('path', '/')
    
    # Handle CORS preflight
    if method == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type'
            },
            'body': ''
        }
    
    # Health check endpoints
    if path == '/api/health':
        return json_response({"status": "healthy", "service": "Zee License Server", "database": "turso"}, 200)
    
    # POST endpoints
    if method == 'POST':
        try:
            body_str = event.get('body', '{}')
            body = json.loads(body_str) if isinstance(body_str, str) else body_str
        except:
            return json_response({"error": "Invalid JSON"}, 400)
        
        if path == '/api/validate-license':
            return validate_license(body)
        elif path == '/api/admin/generate':
            return admin_generate_license(body)
        elif path == '/api/admin/revoke':
            return admin_revoke_license(body)
        elif path == '/api/admin/list':
            return admin_list_licenses(body)
        elif path == '/api/admin/deactivate':
            return admin_deactivate_license(body)
    
    return json_response({"error": "Endpoint not found"}, 404)


# Initialize database on first import
try:
    turso.init_database()
except Exception:
    pass
