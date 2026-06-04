import os
from flask import Flask, request, render_template_string

app = Flask(__name__)

T_INDEX = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Global Security Test Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background: radial-gradient(circle at top right, #1e1b4b, #0f172a);
            color: #f8fafc;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }
        header {
            background: rgba(15, 23, 42, 0.6);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            padding: 1.2rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo {
            font-size: 1.4rem;
            font-weight: 700;
            background: linear-gradient(to right, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .badge {
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 0.3rem 0.8rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .container {
            max-width: 800px;
            width: 90%;
            margin: 4rem auto;
            background: rgba(30, 41, 59, 0.45);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 24px;
            padding: 3rem;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            text-align: center;
        }
        h1 {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            font-weight: 700;
        }
        p.subtitle {
            color: #94a3b8;
            font-size: 1.1rem;
            line-height: 1.6;
            margin-bottom: 2.5rem;
        }
        form {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }
        .input-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            text-align: left;
        }
        label {
            font-size: 0.85rem;
            font-weight: 600;
            color: #38bdf8;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        input[type="text"], textarea {
            width: 100%;
            padding: 1rem 1.2rem;
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            background: rgba(15, 23, 42, 0.6);
            color: #ffffff;
            font-size: 1rem;
            font-family: inherit;
            outline: none;
            transition: all 0.2s ease;
        }
        input:focus, textarea:focus {
            border-color: #38bdf8;
            box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15);
        }
        button {
            background: linear-gradient(135deg, #38bdf8 0%, #4f46e5 100%);
            color: #ffffff;
            border: none;
            padding: 1rem;
            border-radius: 12px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            margin-top: 1rem;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(56, 189, 248, 0.25);
        }
        .result-box {
            margin-top: 2rem;
            padding: 1.5rem;
            border-radius: 12px;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.2);
            color: #34d399;
            font-weight: 500;
            text-align: left;
        }
        footer {
            padding: 2rem;
            text-align: center;
            font-size: 0.85rem;
            color: #64748b;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
        }
    </style>
</head>
<body>
    <header>
        <div class="logo">🌐 Global Security Portal</div>
        <div class="badge">🔒 Independent Secured Client</div>
    </header>

    <div class="container">
        <h1>Welcome to your Standalone Website</h1>
        <p class="subtitle">This is a completely independent backend application running on port 5001. When you route traffic through the main WAF suite, it is secured dynamically.</p>

        <form method="POST" action="/">
            <div class="input-group">
                <label for="feedback">Submit Feedback / Run Attack Test</label>
                <textarea id="feedback" name="feedback" rows="4" placeholder="Enter message here..." required></textarea>
            </div>
            <button type="submit">Send Secured Payload</button>
        </form>

        {% if result %}
        <div class="result-box">
            ✔️ Received clean input: <strong>{{ result }}</strong>
        </div>
        {% endif %}
    </div>

    <footer>
        &copy; 2026 Global Security Test Portal. Protected by AI-CTI Cloud WAF.
    </footer>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        result = request.form.get('feedback', '')
    return render_template_string(T_INDEX, result=result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
