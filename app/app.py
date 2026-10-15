from flask import Flask, request, session, redirect

app = Flask(__name__)
app.secret_key = 'insecure-demo-key'

# Simulated user database
USERS = {'alice': {'balance': '$12,345.67', 'ssn': '123-45-6789'}}

@app.route('/login')
def login():
    session['user'] = 'alice'
    return redirect('/')

@app.route('/')
def home():
    # Poisoning point: uses X-Forwarded-Host to build links
    host = request.headers.get('X-Forwarded-Host', request.host)
    return f'<html><body><a href="http://{host}/login">Login</a></body></html>'

@app.route('/account')
def account():
    user = session.get('user')
    if not user:
        return 'Unauthorized', 401
    data = USERS.get(user, {})
    return f'<h1>Account: {user}</h1><p>Balance: {data.get("balance")}</p>'

# Key: simulates the app server ignoring invalid paths
@app.route('/account/<path:anything>')
def account_with_path(anything):
    return account()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)