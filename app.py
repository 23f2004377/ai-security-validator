from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from collections import defaultdict
import time

app = Flask(__name__)

# Store request timestamps per user
user_requests = defaultdict(list)

LIMIT_PER_MINUTE = 31
BURST_LIMIT = 10

def clean_old_requests(timestamps, window_seconds):
    """Remove timestamps older than the window"""
    cutoff = time.time() - window_seconds
    return [ts for ts in timestamps if ts > cutoff]

def check_rate_limit(user_id):
    """Check if user exceeded rate limits"""
    now = time.time()
    
    # Get user's request history
    timestamps = user_requests[user_id]
    
    # Clean old requests (older than 60 seconds)
    timestamps = clean_old_requests(timestamps, 60)
    user_requests[user_id] = timestamps
    
    # Check burst limit (10 requests in 1 second)
    recent_burst = clean_old_requests(timestamps, 1)
    if len(recent_burst) >= BURST_LIMIT:
        return False, "Rate limit exceeded (burst)", 1
    
    # Check per-minute limit (31 requests in 60 seconds)
    if len(timestamps) >= LIMIT_PER_MINUTE:
        oldest = timestamps[0]
        retry_after = int(60 - (now - oldest)) + 1
        return False, "Rate limit exceeded (per-minute)", retry_after
    
    # Allow request and record timestamp
    user_requests[user_id].append(now)
    return True, "Input passed all security checks", 0

@app.route('/security/validate', methods=['POST'])
def validate():
    try:
        data = request.get_json()
        
        # Validate input
        if not data or 'userId' not in data or 'input' not in data:
            return jsonify({
                "blocked": True,
                "reason": "Invalid request",
                "sanitizedOutput": "",
                "confidence": 0.6
            }), 400
        
        user_id = data['userId']
        user_input = data['input']
        
        # Check rate limit
        allowed, reason, retry_after = check_rate_limit(user_id)
        
        if not allowed:
            response = jsonify({
                "blocked": True,
                "reason": reason,
                "sanitizedOutput": "",
                "confidence": 0.99
            })
            response.status_code = 429
            response.headers['Retry-After'] = str(retry_after)
            
            # Log security event
            print(f"[BLOCKED] User: {user_id}, Reason: {reason}, Retry-After: {retry_after}s")
            return response
        
        # Request allowed
        return jsonify({
            "blocked": False,
            "reason": reason,
            "sanitizedOutput": "",
            "confidence": 0.95
        }), 200
        
    except Exception as e:
        # Don't leak system info
        return jsonify({
            "blocked": True,
            "reason": "Server error",
            "sanitizedOutput": "",
            "confidence": 0.5
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)
