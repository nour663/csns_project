from flask import Flask, request, session, redirect, render_template_string, url_for
import os
import time

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'insecure-demo-key')  # replace in real deploys

# FIX #4 (defense in depth / session hygiene): lock session cookies down.
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True  # requires HTTPS in real deploys

# FIX #5 (Cache Poisoning): the canonical host is fixed server-side
# config, never taken from a client-controlled header. There is nothing
# left for an attacker to inject via X-Forwarded-Host.
CANONICAL_HOST = os.environ.get('CANONICAL_HOST', 'localhost:8081')

USERS = {
    'alice': {
        'password': 'password123',
        'balance': '$12,345.67',
        'ssn': '123-45-6789'
    },
    'bob': {
        'password': 'bob123',
        'balance': '$9,876.54',
        'ssn': '987-65-4321'
    }
}

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Vulnerable Bank - Login</title></head>
<body>
    <h1>Vulnerable Bank Login</h1>
    {% if error %}
        <p style="color:red">{{ error }}</p>
    {% endif %}
    <form method="POST" action="{{ url_for('login') }}">
        <label>Username: <input type="text" name="username" required></label><br><br>
        <label>Password: <input type="password" name="password" required></label><br><br>
        <button type="submit">Login</button>
    </form>
    <p>Demo credentials: alice / password123</p>
</body>
</html>
'''

HOME_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Vulnerable Bank</title></head>
<body>
    <h1>Welcome to Vulnerable Bank</h1>
    <a href="{{ demo_base }}/login/">Login</a> |
    <a href="{{ demo_base }}/account/">My Account</a>
    <br><br>
    <p style="color:green">Host used (fixed, server-side config): {{ host }}</p>
</body>
</html>
'''

ACCOUNT_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Demo Account</title></head>
<body>
    <h1>Account: {{ user }}</h1>
    <p>Balance: {{ balance }}</p>
    <p>SSN: {{ ssn }}</p>
    <p>Timestamp: {{ timestamp }}</p>
    <p>This is fictional training data for a local lab.</p>
    <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
'''

STATIC_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Static Page Demo</title></head>
<body>
    <h1>Static Page (cached by Nginx)</h1>
    <p>Host used (fixed, server-side config): <b>{host}</b></p>
    <script src="http://{host}/static/app.js"></script>
</body>
</html>
'''


@app.after_request
def set_security_headers(response):
    # FIX #6 (defense in depth): belt-and-suspenders — even if nginx
    # config ever drifts, the app itself tells any cache not to store
    # responses from authenticated/sensitive paths.
    if request.path.startswith(('/account', '/login', '/logout')):
        response.headers['Cache-Control'] = 'private, no-store'
    return response


@app.route('/')
def home():
    # No longer reads X-Forwarded-Host from the client at all.
    host = CANONICAL_HOST
    demo_base = f"http://{host}"
    return render_template_string(
        HOME_TEMPLATE,
        host=host,
        demo_base=demo_base
    )


@app.route('/login', methods=['GET', 'POST'], strict_slashes=False)
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        user = USERS.get(username)
        if user and user['password'] == password:
            session['user'] = username
            return redirect(url_for('account'))
        return render_template_string(
            LOGIN_TEMPLATE,
            error='Invalid credentials'
        ), 401
    return render_template_string(LOGIN_TEMPLATE, error=None)


@app.route('/account', strict_slashes=False)
def account():
    username = session.get('user')
    if not username or username not in USERS:
        return redirect(url_for('login'))
    data = USERS[username]
    return render_template_string(
        ACCOUNT_TEMPLATE,
        user=username,
        balance=data['balance'],
        ssn=data['ssn'],
        timestamp=time.time()
    )

# FIX #7 (Cache Deception): the vulnerable /account/<path:anything> route
# is removed entirely. That route was what let /account/nonexistent.css
# or /account/photo.jpg resolve to the real account page in the first
# place (the "URL interpretation mismatch" the attack relies on). Without
# it, any such path simply returns Flask's normal 404 — there's no
# sensitive response for nginx to mistakenly cache as a static asset,
# even if a cache misconfiguration were reintroduced later.


@app.route('/static-page')
def static_page():
    # No longer reads X-Forwarded-Host from the client.
    host = CANONICAL_HOST
    return STATIC_TEMPLATE.format(host=host)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)  # debug off outside the lab
