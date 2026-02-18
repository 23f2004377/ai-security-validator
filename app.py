from flask import Flask, request, jsonify
from flask_cors import CORS
from collections import defaultdict
import time

app = Flask(__name__)
CORS(app)  # <--- This enables CORS for all domains

# Store request timestamps per user
user_requests = defaultdict(list)

LIMIT_PER_MINUTE = 31
BURST_LIMIT = 10

def clean_old_requests(timestamps, window_seconds):
    cutoff = time.time() - window_seconds
    return [ts for ts in timestamps if ts > cutoff]

def check_rate_limit(user_id):
    now = time.time()
    timestamps = user_requests[user_id]
    
    timestamps = clean_old_requests(timestamps, 60)
    user_requests[user_id] = timestamps
    
    recent_burst = clean_old_requests(timestamps, 1)
    if len(recent_burst) >= BURST_LIMIT:
        return False, "Rate limit exceeded (burst)", 1
    
    if len(timestamps) >= LIMIT_PER_MINUTE:
        oldest = timestamps
        retry_after = int(60 - (now - oldest)) + 1
        return False, "Rate limit exceeded (per-minute)", retry_after
    
    user_requests[user_id].append(now)
    return True, "Input passed all security checks", 0

@app.route('/security/validate', methods=['POST', 'OPTIONS'])
def validate():
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        if not data or 'userId' not in data or 'input' not in data:
            return jsonify({"blocked": True, "reason": "Invalid request"}), 400
        
        user_id = data['userId']
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
            return response
        
        return jsonify({
            "blocked": False,
            "reason": reason,
            "sanitizedOutput": "",
            "confidence": 0.95
        }), 200
        
    except Exception:
        return jsonify({"blocked": True, "reason": "Server error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)
