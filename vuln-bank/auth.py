from flask import jsonify, request
import jwt
from datetime import datetime
import sqlite3  
from functools import wraps
from urllib.parse import unquote

# Vulnerable JWT implementation with common security issues

# Weak secret key (CWE-326)
JWT_SECRET = "secret123"

# Vulnerable algorithm selection - allows 'none' algorithm
ALGORITHMS = ['HS256', 'none']

def validate_SQL_INJECTION(username):
    dangerous_keywords = ["' OR","' --","/*","*/","UNION","SELECT"]
    for keyword in dangerous_keywords:
        if keyword in username.upper():
            return False
    return True


def generate_token(user_id, username, is_admin=False):
    """
    Generate a JWT token with weak implementation
    Vulnerability: No token expiration (CWE-613)
    """
    payload = {
        'user_id': user_id,
        'username': username,
        'is_admin': is_admin,
        # Missing 'exp' claim - tokens never expire
        'iat': datetime.utcnow()
    }
    
    # Vulnerability: Using a weak secret key
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token

def verify_token(token):
    """
    Verify JWT token with multiple vulnerabilities
    - Accepts 'none' algorithm (CWE-347)
    - No signature verification in some cases
    - No expiration check
    """
    try:
        # Vulnerability: Accepts any algorithm, including 'none'
        payload = jwt.decode(token, JWT_SECRET, algorithms=ALGORITHMS)
        return payload
    except jwt.exceptions.InvalidSignatureError:
        # Vulnerability: Still accepts tokens in some error cases
        try:
            # Second try without verification
            payload = jwt.decode(token, options={'verify_signature': False})
            return payload
        except:
            return None
    except Exception as e:
        # Vulnerability: Detailed error exposure in logs
        print(f"Token verification error: {str(e)}")
        return None


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Try to get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                # Handle 'Bearer' token format
                if 'Bearer' in auth_header:
                    token = auth_header.split(' ')[1]
                else:
                    token = auth_header
            except IndexError:
                token = None
                
        # Vulnerability: Multiple token locations (token hijacking risk)
        # Also check query parameters (vulnerable by design)
        if not token and 'token' in request.args:
            token = request.args['token']
            
        # Also check form data (vulnerable by design)
        if not token and 'token' in request.form:
            token = request.form['token']
            
        # Also check cookies (vulnerable by design)
        if not token and 'token' in request.cookies:
            token = request.cookies['token']
            
        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        try:
            current_user = verify_token(token)
            if current_user is None:
                return jsonify({'error': 'Invalid token'}), 401
                
            # Vulnerability: No token expiration check
            return f(current_user, *args, **kwargs)
            
        except Exception as e:
            # Vulnerability: Detailed error exposure
            return jsonify({
                'error': 'Invalid token', 
                'details': str(e)
            }), 401
            
    return decorated
failed_attempts = {}
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = 300 
# New API endpoints with JWT authentication
def init_auth_routes(app):
    @app.route('/api/login', methods=['POST'])
    def api_login():
        auth = request.get_json()
        
        # Decode username and password FIRST
        username = unquote(auth.get('username', ''))
        password = unquote(auth.get('password', ''))
        
        print(f"\n[DEBUG LOGIN] Username received: {repr(username)}")
        print(f"[DEBUG LOGIN] Password received: {repr(password)}")
        
        if not auth or not username or not password:
            return jsonify({'error': 'Missing credentials'}), 401
        
        # Check rate limiting BEFORE validation
        if username in failed_attempts:
            recent = [t for t in failed_attempts[username] if (datetime.now() - t).seconds < LOCKOUT_DURATION]
            failed_attempts[username] = recent
            
            if len(recent) >= LOCKOUT_THRESHOLD:
                return jsonify({'error': 'Account temporarily locked'}), 429
        
        # Validate DECODED username
        is_safe = validate_SQL_INJECTION(username)
        print(f"[DEBUG LOGIN] Validation result: {is_safe}")
        
        if not is_safe:
            print(f"[DEBUG LOGIN] ✗ REJECTING - Malicious input detected")
            return jsonify({'error': 'Invalid input detected'}), 401
        
        print(f"[DEBUG LOGIN] ✓ ACCEPTING - Executing query")
        
        # Execute query with DECODED values
        try:
            conn = sqlite3.connect('bank.db')
            c = conn.cursor()
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            print(f"[DEBUG LOGIN] SQL Query: {query}")
            c.execute(query)
            user = c.fetchone()
            conn.close()
        except Exception as e:
            print(f"[DEBUG LOGIN] Database error: {e}")
            return jsonify({'error': 'Database error'}), 500
        
        if not user:
            # Track failed attempt with DECODED username
            if username not in failed_attempts:
                failed_attempts[username] = []
            failed_attempts[username].append(datetime.now())
            print(f"[DEBUG LOGIN] No user found")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        print(f"[DEBUG LOGIN] User found: {user[1]}")
        
        # Clear failed attempts on success
        if username in failed_attempts:
            del failed_attempts[username]
        
        # Generate token
        token = generate_token(user[0], user[1], user[5])
        
        # Return response WITHOUT is_admin
        return jsonify({
            'token': token,
            'user_id': user[0],
            'username': user[1],
            'account_number': user[3],
            'debug_info': {
                'login_time': str(datetime.now()),
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent')
            }
        }), 200

    @app.route('/api/check_balance', methods=['GET'])
    @token_required
    def api_check_balance(current_user):
        # Vulnerability: No additional authorization check
        # Any valid token can check any account balance
        account_number = request.args.get('account_number')
        
        conn = sqlite3.connect('bank.db')
        c = conn.cursor()
        c.execute(f"SELECT username, balance FROM users WHERE account_number='{account_number}'")
        user = c.fetchone()
        conn.close()
        
        if user:
            return jsonify({
                'username': user[0],
                'balance': user[1],
                'checked_by': current_user['username']
            })
        return jsonify({'error': 'Account not found'}), 404

    @app.route('/api/transfer', methods=['POST'])
    @token_required
    def api_transfer(current_user):
        data = request.get_json()
        
        if not data or not data.get('to_account') or not data.get('amount'):
            return jsonify({'error': 'Missing transfer details'}), 400
            
        # Vulnerability: No amount validation
        amount = float(data.get('amount'))
        to_account = data.get('to_account')
        
        conn = sqlite3.connect('bank.db')
        c = conn.cursor()
        
        # Vulnerability: Race condition in transfer
        c.execute(f"SELECT balance FROM users WHERE id={current_user['user_id']}")
        balance = c.fetchone()[0]
        
        if balance >= amount:
            # Vulnerability: SQL injection possible in to_account
            c.execute(f"UPDATE users SET balance = balance - {amount} WHERE id={current_user['user_id']}")
            c.execute(f"UPDATE users SET balance = balance + {amount} WHERE account_number='{to_account}'")
            conn.commit()
            
            # Vulnerability: Information disclosure
            c.execute(f"SELECT username, balance FROM users WHERE account_number='{to_account}'")
            recipient = c.fetchone()
            
            conn.close()
            return jsonify({
                'status': 'success',
                'new_balance': balance - amount,
                'recipient': recipient[0],
                'recipient_new_balance': recipient[1]
            })
            
        conn.close()
        return jsonify({'error': 'Insufficient funds'}), 400