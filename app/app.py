from flask import Flask, request, session, redirect, make_response, render_template_string
import time

app = Flask(__name__)
app.secret_key = 'insecure-demo-key'

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
<html>
<head><title>Vulnerable Bank - Login</title></head>
<body>
    <h1>Vulnerable Bank Login</h1>
    {% if error %}
        <p style="color:red">{{ error }}</p>
    {% endif %}
    <form method="POST" action="/login">
        <label>Username: <input type="text" name="username" /></label><br><br>
        <label>Password: <input type="password" name="password" /></label><br><br>
        <button type="submit">Login</button>
    </form>
    <br>
    <p>Test credentials: alice / password123</p>
</body>
</html>
'''

HOME_TEMPLATE = '''
<html>
<head><title>Vulnerable Bank</title></head>
<body>
    <h1>Welcome to Vulnerable Bank</h1>
    <!-- VULNERABILITY: X-Forwarded-Host reflected into links -->
    <a href="http://{{ host }}/login">Login</a> |
    <a href="http://{{ host }}/account">My Account</a>
    <br><br>
    <p style="color:red">Debug - Host used: {{ host }}</p>
</body>
</html>
'''

ACCOUNT_TEMPLATE = '''
<html>
<head><title>Account</title></head>
<body>
    <h1>Account: {{ user }}</h1>
    <p>Balance: {{ balance }}</p>
    <p>SSN: {{ ssn }}</p>
    <p>Timestamp: {{ time }}</p>
    <br>
    <a href="/logout">Logout</a>
</body>
</html>
'''

# -------------------------------------------------------
# Home page — vulnerable to X-Forwarded-Host poisoning
# -------------------------------------------------------
@app.route('/')
def home():
    host = request.headers.get('X-Forwarded-Host', request.host)
    return render_template_string(HOME_TEMPLATE, host=host)

# -------------------------------------------------------
# Login — GET shows form, POST processes credentials
# -------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        user = USERS.get(username)
        if user and user['password'] == password:
            session['user'] = username
            return redirect('/account')
        else:
            return render_template_string(LOGIN_TEMPLATE, error='Invalid credentials')

    return render_template_string(LOGIN_TEMPLATE, error=None)

# -------------------------------------------------------
# Account — protected page
# -------------------------------------------------------
@app.route('/account')
def account():
    user = session.get('user')
    if not user:
        return redirect('/login')
    data = USERS.get(user, {})
    return render_template_string(
        ACCOUNT_TEMPLATE,
        user=user,
        balance=data.get('balance'),
        ssn=data.get('ssn'),
        time=time.time()
    )

# -------------------------------------------------------
# VULNERABILITY: path confusion
# -------------------------------------------------------
@app.route('/account/<path:anything>')
def account_with_path(anything):
    return account()

# -------------------------------------------------------
# Static page — vulnerable to JS injection via poisoning
# -------------------------------------------------------
@app.route('/static-page')
def static_page():
    host = request.headers.get('X-Forwarded-Host', request.host)
    return f'''<html>
<body>
    <h1>Static Page (cached by nginx)</h1>
    <script src="http://{host}/static/app.js"></script>
    <p>JS loaded from: <b>{host}</b></p>
</body>
</html>'''

# -------------------------------------------------------
# Logout
# -------------------------------------------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)