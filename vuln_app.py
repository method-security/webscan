#!/usr/bin/env python3
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Vulnerable HTML template with direct parameter injection
VULNERABLE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>XSS Vulnerable App</title>
</head>
<body>
    <h1>XSS Test Application</h1>
    
    <h2>Search (Reflected XSS)</h2>
    <form method="GET">
        <input type="text" name="q" value="{{ q }}" placeholder="Search...">
        <input type="submit" value="Search">
    </form>
    {% if q %}
    <p>You searched for: {{ q|safe }}</p>
    {% endif %}
    
    <h2>Profile (Multiple XSS Points)</h2>
    <form method="GET">
        <input type="text" name="name" value="{{ name }}" placeholder="Name...">
        <input type="text" name="email" value="{{ email }}" placeholder="Email...">
        <input type="submit" value="Update">
    </form>
    {% if name %}
    <p>Name: {{ name|safe }}</p>
    {% endif %}
    {% if email %}
    <p>Email: {{ email|safe }}</p>
    {% endif %}
    
</body>
</html>
'''

@app.route('/')
def index():
    q = request.args.get('q', '')
    name = request.args.get('name', '')
    email = request.args.get('email', '')
    search = request.args.get('search', '')
    
    return render_template_string(VULNERABLE_TEMPLATE, 
                                q=q, name=name, email=email, search=search)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5555, debug=True)