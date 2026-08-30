from flask import Flask, request, abort
import re

app = Flask(__name__)

# Define simple attack signatures
SQL_INJECTION = re.compile(r"(SELECT|UPDATE|DELETE|INSERT|DROP|UNION|;|--|')", re.IGNORECASE)
XSS_ATTACK = re.compile(r"(<script>|javascript:)", re.IGNORECASE)

def is_malicious(data):
    if SQL_INJECTION.search(data) or XSS_ATTACK.search(data):
        return True
    return False

@app.before_request
def waf():
    # Check all query args and form data for attack patterns
    for value in list(request.values.values()):
        if is_malicious(value):
            abort(403, "Blocked by WAF")

@app.route('/')
def home():
    return "Hello, World! Your request is clean ."

if __name__ == '__main__':
    app.run()
